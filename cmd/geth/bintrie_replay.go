// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/urfave/cli/v2"
)

var (
	bintrieReplayStartFlag = &cli.Uint64Flag{
		Name:  "start",
		Usage: "Block number to start replay from (default: auto-detect from DB)",
	}
	bintrieReplayEndFlag = &cli.Uint64Flag{
		Name:  "end",
		Usage: "Block number to stop replay at (default: head block)",
	}
	bintrieReplayBatchFlag = &cli.Uint64Flag{
		Name:  "batch",
		Usage: "Number of blocks to process between disk commits",
		Value: 128,
	}
	bintrieReplayRootFlag = &cli.StringFlag{
		Name:  "bintrie-root",
		Usage: "Binary trie root hash to start from (hex, auto-detected from pathdb if omitted)",
	}
	bintrieReplayNoCommitFlag = &cli.BoolFlag{
		Name:  "no-commit",
		Usage: "Process blocks without committing state changes (for debugging)",
	}
)

// replayChain is a minimal ChainContext implementation for block processing.
// It reads headers from the raw database without requiring a full blockchain instance.
type replayChain struct {
	chaindb ethdb.Database
	config  *params.ChainConfig
	engine  consensus.Engine
}

func (rc *replayChain) Config() *params.ChainConfig {
	return rc.config
}

func (rc *replayChain) CurrentHeader() *types.Header {
	return rawdb.ReadHeadHeader(rc.chaindb)
}

func (rc *replayChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	return rawdb.ReadHeader(rc.chaindb, hash, number)
}

func (rc *replayChain) GetHeaderByNumber(number uint64) *types.Header {
	hash := rawdb.ReadCanonicalHash(rc.chaindb, number)
	if hash == (common.Hash{}) {
		return nil
	}
	return rawdb.ReadHeader(rc.chaindb, hash, number)
}

func (rc *replayChain) GetHeaderByHash(hash common.Hash) *types.Header {
	number, ok := rawdb.ReadHeaderNumber(rc.chaindb, hash)
	if !ok {
		return nil
	}
	return rawdb.ReadHeader(rc.chaindb, hash, number)
}

func (rc *replayChain) Engine() consensus.Engine {
	return rc.engine
}

func replayBinaryTrie(ctx *cli.Context) error {
	// Open the node stack and chain database
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, false) // read-write for binary trie updates
	defer chaindb.Close()

	// Read chain config from the database
	genesisHash := rawdb.ReadCanonicalHash(chaindb, 0)
	if genesisHash == (common.Hash{}) {
		return errors.New("no genesis block found in database")
	}
	chainConfig := rawdb.ReadChainConfig(chaindb, genesisHash)
	if chainConfig == nil {
		return errors.New("chain config not found in database")
	}
	log.Info("Loaded chain config", "chainID", chainConfig.ChainID, "network", chainConfig.ChainID)

	// Find the head block
	headBlock := rawdb.ReadHeadBlock(chaindb)
	if headBlock == nil {
		return errors.New("no head block found")
	}
	headNumber := headBlock.NumberU64()
	log.Info("Head block", "number", headNumber, "hash", headBlock.Hash())

	// Determine start and end block numbers
	startBlock := uint64(0)
	if ctx.IsSet(bintrieReplayStartFlag.Name) {
		startBlock = ctx.Uint64(bintrieReplayStartFlag.Name)
	}
	endBlock := headNumber
	if ctx.IsSet(bintrieReplayEndFlag.Name) {
		endBlock = ctx.Uint64(bintrieReplayEndFlag.Name)
	}
	if startBlock == 0 {
		return errors.New("--start block is required (block at which binary trie was converted)")
	}
	if startBlock >= endBlock {
		return fmt.Errorf("start block (%d) must be less than end block (%d)", startBlock, endBlock)
	}
	batchSize := ctx.Uint64(bintrieReplayBatchFlag.Name)
	if batchSize == 0 {
		batchSize = 128
	}

	// Open the binary trie database (uses verkle/pathdb namespace)
	destTriedb := triedb.NewDatabase(chaindb, &triedb.Config{
		IsVerkle: true,
		PathDB: &pathdb.Config{
			JournalDirectory: stack.ResolvePath("triedb-bintrie"),
		},
	})
	defer destTriedb.Close()

	// Create the state database backed by the binary trie
	stateDB := state.NewDatabase(destTriedb, nil)

	// Determine the binary trie root to start from
	var binRoot common.Hash
	if ctx.IsSet(bintrieReplayRootFlag.Name) {
		var err error
		binRoot, err = parseRoot(ctx.String(bintrieReplayRootFlag.Name))
		if err != nil {
			return fmt.Errorf("invalid --bintrie-root: %v", err)
		}
		log.Info("Using provided binary trie root", "root", binRoot)
	} else {
		// Auto-detect: read the root node from the verkle-prefixed pathdb
		verkleDB := rawdb.NewTable(chaindb, string(rawdb.VerklePrefix))
		blob := rawdb.ReadAccountTrieNode(verkleDB, nil)
		if len(blob) == 0 {
			return errors.New("no binary trie root found in pathdb — provide --bintrie-root or run conversion first")
		}
		n, err := bintrie.DeserializeNode(blob, 0)
		if err != nil {
			return fmt.Errorf("failed to deserialize binary root node: %v", err)
		}
		binRoot = n.Hash()
		log.Info("Auto-detected binary trie root from pathdb", "root", binRoot)
	}

	// Verify we can open state at this root
	if _, err := state.New(binRoot, stateDB); err != nil {
		return fmt.Errorf("cannot open state at binary root %x: %v", binRoot, err)
	}
	log.Info("Successfully opened binary trie state", "root", binRoot)

	// Create consensus engine (beacon with ethash faker for Hoodi)
	engine := beacon.New(ethash.NewFaker())

	// Create the chain context for block processing
	chain := &replayChain{
		chaindb: chaindb,
		config:  chainConfig,
		engine:  engine,
	}

	processor := core.NewStateProcessor(chain)

	// Replay blocks
	log.Info("Starting binary trie block replay",
		"start", startBlock+1,
		"end", endBlock,
		"batchSize", batchSize,
	)

	currentRoot := binRoot

	// Debug: read specific slots from binary trie AND MPT before processing
	{
		targetAddr := common.HexToAddress("0x91cb447bafc6e0ea0f4fe056f5a9b1f14bb06e5d")
		debugSlots := []string{
			// TX 1 affected
			"cfde4f29a1b76838742d06bc06b2226419c9c4cac873b661b11d99afb903431f",
			"0e17799ab0c899fcf3ab5116b2c11d7e941a022637254bda2c1bec9dd14a9f13",
			"ec4f100d2f04571b4361e2d55056df75d31268f45891771d9777025df21b3225",
			"0e7edab21cbfaca3028d2a3df5b02de047fc251fcc121148961ecb58db764012",
			// TX 0 non-affected (REAL slots from trace3)
			"495924ca808012720914f22a1188bde30d257c08e85ac5a62845d7d7c049c35f",
		}
		// Read from binary trie
		sdb, err := state.New(binRoot, stateDB)
		if err == nil {
			sdb.SetAccessEvents(nil)
			for _, slotHex := range debugSlots {
				slot := common.HexToHash(slotHex)
				val := sdb.GetState(targetAddr, slot)
				log.Info("BIN-SLOT", "slot", fmt.Sprintf("%.16x...", slot), "value", fmt.Sprintf("%x", val), "nonzero", val != common.Hash{})
			}
		}
		// Also try reading from MPT state
		mptRoot := rawdb.ReadHeader(chaindb, rawdb.ReadCanonicalHash(chaindb, startBlock), startBlock).Root
		log.Info("MPT root for comparison", "block", startBlock, "root", mptRoot)
		srcTriedb := triedb.NewDatabase(chaindb, &triedb.Config{
			PathDB: &pathdb.Config{
				JournalDirectory: stack.ResolvePath("triedb"),
			},
		})
		mptStateDB := state.NewDatabase(srcTriedb, nil)
		mptState, err := state.New(mptRoot, mptStateDB)
		if err != nil {
			log.Warn("Cannot open MPT state (pruned?)", "err", err)
			// Try nearby blocks
			headBlock := rawdb.ReadHeadBlock(chaindb)
			if headBlock != nil {
				for trial := headBlock.NumberU64(); trial > headBlock.NumberU64()-300; trial-- {
					h := rawdb.ReadCanonicalHash(chaindb, trial)
					hdr := rawdb.ReadHeader(chaindb, h, trial)
					if hdr == nil {
						continue
					}
					mptState, err = state.New(hdr.Root, mptStateDB)
					if err == nil {
						log.Info("Found MPT state", "block", trial, "root", hdr.Root)
						break
					}
				}
			}
		} else {
			log.Info("Opened MPT state at conversion block", "block", startBlock)
		}
		if mptState != nil {
			for _, slotHex := range debugSlots {
				slot := common.HexToHash(slotHex)
				mptVal := mptState.GetState(targetAddr, slot)
				log.Info("MPT-SLOT", "slot", fmt.Sprintf("%.16x...", slot), "value", fmt.Sprintf("%x", mptVal), "nonzero", mptVal != common.Hash{})
			}
		}
		srcTriedb.Close()
	}

	replayStart := time.Now()
	blocksProcessed := uint64(0)
	txsProcessed := uint64(0)
	lastLog := time.Now()

	for blockNum := startBlock + 1; blockNum <= endBlock; blockNum++ {
		// Read the block from the chain database
		hash := rawdb.ReadCanonicalHash(chaindb, blockNum)
		if hash == (common.Hash{}) {
			return fmt.Errorf("block %d not found in canonical chain", blockNum)
		}
		block := rawdb.ReadBlock(chaindb, hash, blockNum)
		if block == nil {
			return fmt.Errorf("block %d body not found", blockNum)
		}

		// Open state at current binary root
		sdb, err := state.New(currentRoot, stateDB)
		if err != nil {
			return fmt.Errorf("failed to open state at block %d (root %x): %v", blockNum, currentRoot, err)
		}
		// Disable verkle access events — the binary trie uses IsVerkle=true
		// internally for pathdb routing, but we're not in the actual verkle
		// fork so EIP-4762 gas accounting must be disabled.
		sdb.SetAccessEvents(nil)

		// Process the block
		result, err := processor.Process(block, sdb, vm.Config{})
		if err != nil {
			return fmt.Errorf("failed to process block %d: %v", blockNum, err)
		}
		// Compare gas used with block header
		if result.GasUsed != block.GasUsed() {
			log.Warn("Gas used mismatch",
				"block", blockNum,
				"bintrie", result.GasUsed,
				"header", block.GasUsed(),
				"diff", int64(result.GasUsed)-int64(block.GasUsed()),
			)
			// Compare per-tx gas by reading receipts from the DB
			mptReceipts := rawdb.ReadReceipts(chaindb, hash, blockNum, block.Time(), chainConfig)
			if mptReceipts != nil && len(mptReceipts) == len(result.Receipts) {
				prevMPT := uint64(0)
				prevBin := uint64(0)
				for i, binR := range result.Receipts {
					mptR := mptReceipts[i]
					mptGas := mptR.CumulativeGasUsed - prevMPT
					binGas := binR.CumulativeGasUsed - prevBin
					if mptGas != binGas {
						log.Warn("Per-tx gas diff",
							"block", blockNum,
							"tx", i,
							"hash", block.Transactions()[i].Hash(),
							"mptGas", mptGas,
							"binGas", binGas,
							"diff", int64(binGas)-int64(mptGas),
							"mptStatus", mptR.Status,
							"binStatus", binR.Status,
						)
					}
					prevMPT = mptR.CumulativeGasUsed
					prevBin = binR.CumulativeGasUsed
				}
			}
		}

		noCommit := ctx.Bool(bintrieReplayNoCommitFlag.Name)
		if noCommit {
			log.Info("Block processed (no commit)", "block", blockNum, "txs", len(block.Transactions()), "gasUsed", result.GasUsed)
			blocksProcessed++
			txsProcessed += uint64(len(block.Transactions()))
		} else {
			// Commit state changes — this produces a new binary trie root
			newRoot, err := sdb.Commit(blockNum, chainConfig.IsEIP158(block.Number()), true)
			if err != nil {
				return fmt.Errorf("failed to commit state for block %d: %v", blockNum, err)
			}
			log.Info("Block committed", "block", blockNum, "txs", len(block.Transactions()), "gasUsed", result.GasUsed, "oldRoot", currentRoot, "newRoot", newRoot)

			currentRoot = newRoot
			blocksProcessed++
			txsProcessed += uint64(len(block.Transactions()))

			// Periodically flush to disk
			if blocksProcessed%batchSize == 0 {
				if err := destTriedb.Commit(currentRoot, false); err != nil {
					return fmt.Errorf("failed to flush triedb at block %d: %v", blockNum, err)
				}
			}
		}

		// Log progress
		if time.Since(lastLog) > 8*time.Second {
			elapsed := time.Since(replayStart)
			bps := float64(blocksProcessed) / elapsed.Seconds()
			remaining := float64(endBlock-blockNum) / bps
			log.Info("Replay progress",
				"block", blockNum,
				"of", endBlock,
				"blocks", blocksProcessed,
				"txs", txsProcessed,
				"gasUsed", result.GasUsed,
				"bps", fmt.Sprintf("%.1f", bps),
				"elapsed", common.PrettyDuration(elapsed),
				"eta", common.PrettyDuration(time.Duration(remaining)*time.Second),
				"binRoot", currentRoot,
			)
			lastLog = time.Now()
		}
	}

	// Final flush (skip in no-commit mode)
	if !ctx.Bool(bintrieReplayNoCommitFlag.Name) {
		if err := destTriedb.Commit(currentRoot, false); err != nil {
			return fmt.Errorf("final triedb flush failed: %v", err)
		}
	}

	elapsed := time.Since(replayStart)
	log.Info("Binary trie replay complete",
		"blocks", blocksProcessed,
		"txs", txsProcessed,
		"elapsed", common.PrettyDuration(elapsed),
		"finalRoot", currentRoot,
	)
	return nil
}
