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
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-verkle"
	"github.com/pk910/dynamic-ssz"
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
	if p.config.IsPrague(block.Number(), block.Time()) {
		parent := p.bc.GetBlockByHash(block.ParentHash())
		if !p.config.IsPrague(parent.Number(), parent.Time()) {
			InsertBlockHashHistoryAtEip2935Fork(statedb, block.NumberU64()-1, block.ParentHash(), p.bc)
		} else {
			ProcessParentBlockHash(statedb, block.NumberU64()-1, block.ParentHash())
		}

		// var record [1 + 8]byte
		// record[0] = 1
		// binary.LittleEndian.PutUint64(record[1:], block.NumberU64())
		// state.AppendBytesToFile("gas.log", record[:])
	}
	// Iterate over and process the individual transactions
	for i, tx := range block.Transactions() {
		// var record [1 + 32]byte
		// record[0] = 2
		// copy(record[1:], tx.Hash().Bytes())
		// state.AppendBytesToFile("gas.log", record[:])
		msg, err := TransactionToMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		statedb.SetTxContext(tx.Hash(), i)
		thash := tx.Hash()
		if thash[0] == 0xe5 && thash[1] == 0x5a && thash[2] == 0x21 && thash[3] == 0x50 {
			file, err := os.Create("bug.json")
			if err != nil {
				panic(err)
			}
			defer file.Close()
			vmenv.Config.Tracer = logger.NewJSONLogger(&logger.Config{
				EnableMemory:     true,
				EnableReturnData: true,
			}, file)
		} else {
			vmenv.Config.Tracer = nil
		}
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

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), block.Uncles(), withdrawals)

	header.Root = statedb.IntermediateRoot(true)
	// Associate current conversion state to computed state
	// root and store it in the database for later recovery.
	statedb.Database().SaveTransitionState(header.Root)

	var (
		proof     *verkle.VerkleProof
		statediff verkle.StateDiff
		keys      = statedb.Witness().Keys()
	)
	// Open the pre-tree to prove the pre-state against
	parent := p.bc.GetHeaderByNumber(header.Number.Uint64() - 1)
	if parent == nil {
		return nil, nil, 0, fmt.Errorf("nil parent header for block %d", header.Number)
	}

	// Load transition state at beginning of block, because
	// OpenTrie needs to know what the conversion status is.
	// statedb.Database().LoadTransitionState(parent.Root)

	preTrie, err := statedb.Database().OpenTrie(parent.Root)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("error opening pre-state tree root: %w", err)
	}
	// statedb.Database().LoadTransitionState(header.Root)

	var okpre, okpost bool
	var vtrpre, vtrpost *trie.VerkleTrie
	switch pre := preTrie.(type) {
	case *trie.VerkleTrie:
		vtrpre, okpre = preTrie.(*trie.VerkleTrie)
		switch tr := statedb.GetTrie().(type) {
		case *trie.VerkleTrie:
			vtrpost = tr
			okpost = true
		// This is to handle a situation right at the start of the conversion:
		// the post trie is a transition tree when the pre tree is an empty
		// verkle tree.
		case *trie.TransitionTrie:
			vtrpost = tr.Overlay()
			okpost = true
		default:
			okpost = false
		}
	case *trie.TransitionTrie:
		vtrpre = pre.Overlay()
		okpre = true
		post, _ := statedb.GetTrie().(*trie.TransitionTrie)
		vtrpost = post.Overlay()
		okpost = true
	default:
		// This should only happen for the first block of the
		// conversion, when the previous tree is a merkle tree.
		//  Logically, the "previous" verkle tree is an empty tree.
		okpre = true
		vtrpre = trie.NewVerkleTrie(verkle.New(), statedb.Database().TrieDB(), utils.NewPointCache(), false)
		post := statedb.GetTrie().(*trie.TransitionTrie)
		vtrpost = post.Overlay()
		okpost = true
	}
	if okpre && okpost {
		if len(keys) > 0 {
			proof, statediff, err = trie.ProveAndSerialize(vtrpre, vtrpost, keys, vtrpre.FlatdbNodeResolver)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("error generating verkle proof for block %d: %w", header.Number, err)
			}
		}

		ew := types.ExecutionWitness{StateDiff: statediff, VerkleProof: proof}
		encoder := dynssz.NewDynSsz(map[string]any{})
		encoded, err := encoder.MarshalSSZ(&ew)
		if err != nil {
			spew.Dump(ew)
			panic(err)
		}
		state.AppendBytesToFile("witness_size.csv", []byte(fmt.Sprintf("%d,%d\n", header.Number, len(encoded))))
		if header.Number.Uint64()%10000 == 0 {
			data := make([]byte, 8+len(encoded))
			copy(data[8:], encoded)
			binary.LittleEndian.PutUint64(data[:8], block.NumberU64())
			state.AppendBytesToFile("witnesses.ssz", data)
		}
	}
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
	istarget := blockContext.BlockNumber.Uint64() == 17165311
	if istarget {
		tracer := logger.NewStructLogger(&logger.Config{
			Debug:          istarget,
			DisableStorage: !istarget,
			//EnableMemory: false,
			EnableReturnData: istarget,
		})
		cfg.Tracer = tracer
	}
	vmenv := vm.NewEVM(blockContext, vm.TxContext{BlobHashes: tx.BlobHashes()}, statedb, config, cfg)
	return applyTransaction(msg, config, gp, statedb, header.Number, header.Hash(), tx, usedGas, vmenv)
}

func InsertBlockHashHistoryAtEip2935Fork(statedb *state.StateDB, prevNumber uint64, prevHash common.Hash, chain consensus.ChainHeaderReader) {
	// Make sure that the historical contract is added to the witness
	statedb.Witness().TouchFullAccount(params.HistoryStorageAddress[:], true)

	ancestor := chain.GetHeader(prevHash, prevNumber)
	for i := prevNumber; i > 0 && i > prevNumber-params.Eip2935BlockHashHistorySize; i-- {
		ProcessParentBlockHash(statedb, i, ancestor.Hash())
		ancestor = chain.GetHeader(ancestor.ParentHash, ancestor.Number.Uint64()-1)
	}
}

func ProcessParentBlockHash(statedb *state.StateDB, prevNumber uint64, prevHash common.Hash) {
	ringIndex := prevNumber % params.Eip2935BlockHashHistorySize
	var key common.Hash
	binary.BigEndian.PutUint64(key[24:], ringIndex)
	statedb.SetState(params.HistoryStorageAddress, key, prevHash)
	statedb.Witness().TouchSlotAndChargeGas(params.HistoryStorageAddress[:], key, true)
}
