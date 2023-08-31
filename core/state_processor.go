// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	tutils "github.com/ethereum/go-ethereum/trie/utils"
	"github.com/gballet/go-verkle"
	"github.com/holiman/uint256"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts    types.Receipts
		usedGas     = new(uint64)
		header      = block.Header()
		blockHash   = block.Hash()
		blockNumber = block.Number()
		allLogs     []*types.Log
		gp          = new(GasPool).AddGas(block.GasLimit())
	)
	// Mutate the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	var (
		context = NewEVMBlockContext(header, p.bc, nil)
		vmenv   = vm.NewEVM(context, vm.TxContext{}, statedb, p.config, cfg)
		signer  = types.MakeSigner(p.config, header.Number, header.Time)
	)
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)
		receipt, err := applyTransaction(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	// Fail if Shanghai not enabled and len(withdrawals) is non-zero.
	withdrawals := block.Withdrawals()
	if len(withdrawals) > 0 && !p.config.IsShanghai(block.Number(), block.Time()) {
		return nil, nil, 0, errors.New("withdrawals before shanghai")
	}

	// Overlay tree migration logic
	migrdb := statedb.Database()

	// verkle transition: if the conversion process is in progress, move
	// N values from the MPT into the verkle tree.
	if migrdb.InTransition() {
		var (
			now             = time.Now()
			tt              = statedb.GetTrie().(*trie.TransitionTrie)
			mpt             = tt.Base()
			vkt             = tt.Overlay()
			hasPreimagesBin = false
			preimageSeek    = migrdb.GetCurrentPreimageOffset()
			fpreimages      *bufio.Reader
		)

		// TODO: avoid opening the preimages file here and make it part of, potentially, statedb.Database().
		filePreimages, err := os.Open("preimages.bin")
		if err != nil {
			// fallback on reading the db
			log.Warn("opening preimage file", "error", err)
		} else {
			defer filePreimages.Close()
			if _, err := filePreimages.Seek(preimageSeek, io.SeekStart); err != nil {
				return nil, nil, 0, fmt.Errorf("seeking preimage file: %s", err)
			}
			fpreimages = bufio.NewReader(filePreimages)
			hasPreimagesBin = true
		}

		accIt, err := statedb.Snaps().AccountIterator(mpt.Hash(), migrdb.GetCurrentAccountHash())
		if err != nil {
			return nil, nil, 0, err
		}
		defer accIt.Release()
		accIt.Next()

		// If we're about to start with the migration process, we have to read the first account hash preimage.
		if migrdb.GetCurrentAccountAddress() == nil {
			var addr common.Address
			if hasPreimagesBin {
				if _, err := io.ReadFull(fpreimages, addr[:]); err != nil {
					return nil, nil, 0, fmt.Errorf("reading preimage file: %s", err)
				}
			} else {
				addr = common.BytesToAddress(rawdb.ReadPreimage(migrdb.DiskDB(), accIt.Hash()))
				if len(addr) != 20 {
					return nil, nil, 0, fmt.Errorf("addr len is zero is not 32: %d", len(addr))
				}
			}
			migrdb.SetCurrentAccountAddress(addr)
			if migrdb.GetCurrentAccountHash() != accIt.Hash() {
				return nil, nil, 0, fmt.Errorf("preimage file does not match account hash: %s != %s", crypto.Keccak256Hash(addr[:]), accIt.Hash())
			}
			preimageSeek += int64(len(addr))
		}

		const maxMovedCount = 10000
		// mkv will be assiting in the collection of up to maxMovedCount key values to be migrated to the VKT.
		// It has internal caches to do efficient MPT->VKT key calculations, which will be discarded after
		// this function.
		mkv := newKeyValueMigrator()
		// move maxCount accounts into the verkle tree, starting with the
		// slots from the previous account.
		count := 0

		// if less than maxCount slots were moved, move to the next account
		for count < maxMovedCount {
			acc, err := types.FullAccount(accIt.Account())
			if err != nil {
				log.Error("Invalid account encountered during traversal", "error", err)
				return nil, nil, 0, err
			}
			vkt.SetStorageRootConversion(*migrdb.GetCurrentAccountAddress(), acc.Root)

			// Start with processing the storage, because once the account is
			// converted, the `stateRoot` field loses its meaning. Which means
			// that it opens the door to a situation in which the storage isn't
			// converted, but it can not be found since the account was and so
			// there is no way to find the MPT storage from the information found
			// in the verkle account.
			// Note that this issue can still occur if the account gets written
			// to during normal block execution. A mitigation strategy has been
			// introduced with the `*StorageRootConversion` fields in VerkleDB.
			if acc.HasStorage() {
				stIt, err := statedb.Snaps().StorageIterator(mpt.Hash(), accIt.Hash(), migrdb.GetCurrentSlotHash())
				if err != nil {
					return nil, nil, 0, err
				}
				stIt.Next()

				// fdb.StorageProcessed will be initialized to `true` if the
				// entire storage for an account was not entirely processed
				// by the previous block. This is used as a signal to resume
				// processing the storage for that account where we left off.
				// If the entire storage was processed, then the iterator was
				// created in vain, but it's ok as this will not happen often.
				for ; !migrdb.GetStorageProcessed() && count < maxMovedCount; count++ {
					var (
						value     []byte   // slot value after RLP decoding
						safeValue [32]byte // 32-byte aligned value
					)
					if err := rlp.DecodeBytes(stIt.Slot(), &value); err != nil {
						return nil, nil, 0, fmt.Errorf("error decoding bytes %x: %w", stIt.Slot(), err)
					}
					copy(safeValue[32-len(value):], value)

					var slotnr []byte
					if hasPreimagesBin {
						var s [32]byte
						slotnr = s[:]
						if _, err := io.ReadFull(fpreimages, slotnr); err != nil {
							return nil, nil, 0, fmt.Errorf("reading preimage file: %s", err)
						}
					} else {
						slotnr = rawdb.ReadPreimage(migrdb.DiskDB(), stIt.Hash())
						if len(slotnr) != 32 {
							return nil, nil, 0, fmt.Errorf("slotnr len is zero is not 32: %d", len(slotnr))
						}
					}
					if crypto.Keccak256Hash(slotnr[:]) != stIt.Hash() {
						return nil, nil, 0, fmt.Errorf("preimage file does not match storage hash: %s!=%s", crypto.Keccak256Hash(slotnr), stIt.Hash())
					}
					preimageSeek += int64(len(slotnr))

					mkv.addStorageSlot(migrdb.GetCurrentAccountAddress().Bytes(), slotnr, safeValue[:])

					// advance the storage iterator
					migrdb.SetStorageProcessed(!stIt.Next())
					if !migrdb.GetStorageProcessed() {
						migrdb.SetCurrentSlotHash(stIt.Hash())
					}
				}
				stIt.Release()
			}

			// If the maximum number of leaves hasn't been reached, then
			// it means that the storage has finished processing (or none
			// was available for this account) and that the account itself
			// can be processed.
			if count < maxMovedCount {
				count++ // count increase for the account itself

				mkv.addAccount(migrdb.GetCurrentAccountAddress().Bytes(), acc)
				vkt.ClearStrorageRootConversion(*migrdb.GetCurrentAccountAddress())

				// Store the account code if present
				if !bytes.Equal(acc.CodeHash, types.EmptyCodeHash[:]) {
					code := rawdb.ReadCode(statedb.Database().DiskDB(), common.BytesToHash(acc.CodeHash))
					chunks := trie.ChunkifyCode(code)

					mkv.addAccountCode(migrdb.GetCurrentAccountAddress().Bytes(), uint64(len(code)), chunks)
				}

				// reset storage iterator marker for next account
				migrdb.SetStorageProcessed(false)
				migrdb.SetCurrentSlotHash(common.Hash{})

				// Move to the next account, if available - or end
				// the transition otherwise.
				if accIt.Next() {
					var addr common.Address
					if hasPreimagesBin {
						if _, err := io.ReadFull(fpreimages, addr[:]); err != nil {
							return nil, nil, 0, fmt.Errorf("reading preimage file: %s", err)
						}
					} else {
						addr = common.BytesToAddress(rawdb.ReadPreimage(migrdb.DiskDB(), accIt.Hash()))
						if len(addr) != 20 {
							return nil, nil, 0, fmt.Errorf("account address len is zero is not 20: %d", len(addr))
						}
					}
					// fmt.Printf("account switch: %s != %s\n", crypto.Keccak256Hash(addr[:]), accIt.Hash())
					if crypto.Keccak256Hash(addr[:]) != accIt.Hash() {
						return nil, nil, 0, fmt.Errorf("preimage file does not match account hash: %s != %s", crypto.Keccak256Hash(addr[:]), accIt.Hash())
					}
					preimageSeek += int64(len(addr))
					migrdb.SetCurrentAccountAddress(addr)
				} else {
					// case when the account iterator has
					// reached the end but count < maxCount
					migrdb.EndVerkleTransition()
					break
				}
			}
		}
		migrdb.SetCurrentPreimageOffset(preimageSeek)

		log.Info("Collected key values from base tree", "count", count, "duration", time.Since(now), "last account", statedb.Database().GetCurrentAccountHash())

		// Take all the collected key-values and prepare the new leaf values.
		// This fires a background routine that will start doing the work that
		// migrateCollectedKeyValues() will use to insert into the tree.
		//
		// TODO: Now both prepare() and migrateCollectedKeyValues() are next to each other, but
		//       after we fix an existing bug, we can call prepare() before the block execution and
		//       let it do the work in the background. After the block execution and finalization
		//       finish, we can call migrateCollectedKeyValues() which should already find everything ready.
		mkv.prepare()
		now = time.Now()
		if err := mkv.migrateCollectedKeyValues(tt.Overlay()); err != nil {
			return nil, nil, 0, fmt.Errorf("could not migrate key values: %w", err)
		}
		log.Info("Inserted key values in overlay tree", "count", count, "duration", time.Since(now))
	}

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), withdrawals)

	if block.NumberU64()%100 == 0 {
		stateRoot := statedb.GetTrie().Hash()
		log.Info("State root", "number", block.NumberU64(), "hash", stateRoot)
	}

	return receipts, allLogs, *usedGas, nil
}

func applyTransaction(msg *Message, config *params.ChainConfig, gp *GasPool, statedb *state.StateDB, blockNumber *big.Int, blockHash common.Hash, tx *types.Transaction, usedGas *uint64, evm *vm.EVM) (*types.Receipt, error) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	txContext.Accesses = statedb.NewAccessWitness()
	evm.Reset(txContext, statedb)

	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, err
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	statedb.Witness().Merge(txContext.Accesses)

	// Set the receipt logs and create the bloom filter.
	receipt.Logs = statedb.GetLogs(tx.Hash(), blockNumber.Uint64(), blockHash)
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())
	return receipt, err
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, error) {
	msg, err := TransactionToMessage(tx, types.MakeSigner(config, header.Number, header.Time), header.BaseFee)
	if err != nil {
		return nil, err
	}
	// Create a new context to be used in the EVM environment
	blockContext := NewEVMBlockContext(header, bc, author)
	vmenv := vm.NewEVM(blockContext, vm.TxContext{BlobHashes: tx.BlobHashes()}, statedb, config, cfg)
	return applyTransaction(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

var zeroTreeIndex uint256.Int

// keyValueMigrator is a helper module that collects key-values from the overlay-tree migration for Verkle Trees.
// It assumes that the walk of the base tree is done in address-order, so it exploit that fact to
// collect the key-values in a way that is efficient.
type keyValueMigrator struct {
	// leafData contains the values for the future leaf for a particular VKT branch.
	leafData []migratedKeyValue

	// When prepare() is called, it will start a background routine that will process the leafData
	// saving the result in newLeaves to be used by migrateCollectedKeyValues(). The background
	// routine signals that it is done by closing processingReady.
	processingReady chan struct{}
	newLeaves       []verkle.LeafNode
	prepareErr      error
}

func newKeyValueMigrator() *keyValueMigrator {
	// We do initialize the VKT config since prepare() might indirectly make multiple GetConfig() calls
	// in different goroutines when we never called GetConfig() before, causing a race considering the way
	// that `config` is designed in go-verkle.
	// TODO: jsign as a fix for this in the PR where we move to a file-less precomp, since it allows safe
	//       concurrent calls to GetConfig(). When that gets merged, we can remove this line.
	_ = verkle.GetConfig()
	return &keyValueMigrator{
		processingReady: make(chan struct{}),
		leafData:        make([]migratedKeyValue, 0, 10_000),
	}
}

type migratedKeyValue struct {
	branchKey    branchKey
	leafNodeData verkle.BatchNewLeafNodeData
}
type branchKey struct {
	addr      common.Address
	treeIndex uint256.Int
}

func newBranchKey(addr []byte, treeIndex *uint256.Int) branchKey {
	var sk branchKey
	copy(sk.addr[:], addr)
	sk.treeIndex = *treeIndex
	return sk
}

func (kvm *keyValueMigrator) addStorageSlot(addr []byte, slotNumber []byte, slotValue []byte) {
	treeIndex, subIndex := tutils.GetTreeKeyStorageSlotTreeIndexes(slotNumber)
	leafNodeData := kvm.getOrInitLeafNodeData(newBranchKey(addr, treeIndex))
	leafNodeData.Values[subIndex] = slotValue
}

func (kvm *keyValueMigrator) addAccount(addr []byte, acc *types.StateAccount) {
	leafNodeData := kvm.getOrInitLeafNodeData(newBranchKey(addr, &zeroTreeIndex))

	var version [verkle.LeafValueSize]byte
	leafNodeData.Values[tutils.VersionLeafKey] = version[:]

	var balance [verkle.LeafValueSize]byte
	for i, b := range acc.Balance.Bytes() {
		balance[len(acc.Balance.Bytes())-1-i] = b
	}
	leafNodeData.Values[tutils.BalanceLeafKey] = balance[:]

	var nonce [verkle.LeafValueSize]byte
	binary.LittleEndian.PutUint64(nonce[:8], acc.Nonce)
	leafNodeData.Values[tutils.NonceLeafKey] = nonce[:]

	leafNodeData.Values[tutils.CodeKeccakLeafKey] = acc.CodeHash[:]
}

func (kvm *keyValueMigrator) addAccountCode(addr []byte, codeSize uint64, chunks []byte) {
	leafNodeData := kvm.getOrInitLeafNodeData(newBranchKey(addr, &zeroTreeIndex))

	// Save the code size.
	var codeSizeBytes [verkle.LeafValueSize]byte
	binary.LittleEndian.PutUint64(codeSizeBytes[:8], codeSize)
	leafNodeData.Values[tutils.CodeSizeLeafKey] = codeSizeBytes[:]

	// The first 128 chunks are stored in the account header leaf.
	for i := 0; i < 128 && i < len(chunks)/32; i++ {
		leafNodeData.Values[byte(128+i)] = chunks[32*i : 32*(i+1)]
	}

	// Potential further chunks, have their own leaf nodes.
	for i := 128; i < len(chunks)/32; {
		treeIndex, _ := tutils.GetTreeKeyCodeChunkIndices(uint256.NewInt(uint64(i)))
		leafNodeData := kvm.getOrInitLeafNodeData(newBranchKey(addr, treeIndex))

		j := i
		for ; (j-i) < 256 && j < len(chunks)/32; j++ {
			leafNodeData.Values[byte((j-128)%256)] = chunks[32*j : 32*(j+1)]
		}
		i = j
	}
}

func (kvm *keyValueMigrator) getOrInitLeafNodeData(bk branchKey) *verkle.BatchNewLeafNodeData {
	// Remember that keyValueMigration receives actions ordered by (address, subtreeIndex).
	// This means that we can assume that the last element of leafData is the one that we
	// are looking for, or that we need to create a new one.
	if len(kvm.leafData) == 0 || kvm.leafData[len(kvm.leafData)-1].branchKey != bk {
		kvm.leafData = append(kvm.leafData, migratedKeyValue{
			branchKey: bk,
			leafNodeData: verkle.BatchNewLeafNodeData{
				Stem:   nil, // It will be calculated in the prepare() phase, since it's CPU heavy.
				Values: make(map[byte][]byte),
			},
		})
	}
	return &kvm.leafData[len(kvm.leafData)-1].leafNodeData
}

func (kvm *keyValueMigrator) prepare() {
	// We fire a background routine to process the leafData and save the result in newLeaves.
	// The background routine signals that it is done by closing processingReady.
	go func() {
		// Step 1: We split kvm.leafData in numBatches batches, and we process each batch in a separate goroutine.
		//         This fills each leafNodeData.Stem with the correct value.
		var wg sync.WaitGroup
		batchNum := runtime.NumCPU()
		batchSize := (len(kvm.leafData) + batchNum - 1) / batchNum
		for i := 0; i < len(kvm.leafData); i += batchSize {
			start := i
			end := i + batchSize
			if end > len(kvm.leafData) {
				end = len(kvm.leafData)
			}
			wg.Add(1)

			batch := kvm.leafData[start:end]
			go func() {
				defer wg.Done()
				var currAddr common.Address
				var currPoint *verkle.Point
				for i := range batch {
					if batch[i].branchKey.addr != currAddr {
						currAddr = batch[i].branchKey.addr
						currPoint = tutils.EvaluateAddressPoint(currAddr[:])
					}
					stem := tutils.GetTreeKeyWithEvaluatedAddess(currPoint, &batch[i].branchKey.treeIndex, 0)
					stem = stem[:verkle.StemSize]
					batch[i].leafNodeData.Stem = stem
				}
			}()
		}
		wg.Wait()

		// Step 2: Now that we have all stems (i.e: tree keys) calcualted, we can create the new leaves.
		nodeValues := make([]verkle.BatchNewLeafNodeData, len(kvm.leafData))
		for i := range kvm.leafData {
			nodeValues[i] = kvm.leafData[i].leafNodeData
		}

		// Create all leaves in batch mode so we can optimize cryptography operations.
		kvm.newLeaves, kvm.prepareErr = verkle.BatchNewLeafNode(nodeValues)
		close(kvm.processingReady)
	}()
}

func (kvm *keyValueMigrator) migrateCollectedKeyValues(tree *trie.VerkleTrie) error {
	now := time.Now()
	<-kvm.processingReady
	if kvm.prepareErr != nil {
		return fmt.Errorf("failed to prepare key values: %w", kvm.prepareErr)
	}
	log.Info("Prepared key values from base tree", "duration", time.Since(now))

	// Insert into the tree.
	if err := tree.InsertMigratedLeaves(kvm.newLeaves); err != nil {
		return fmt.Errorf("failed to insert migrated leaves: %w", err)
	}

	return nil
}
