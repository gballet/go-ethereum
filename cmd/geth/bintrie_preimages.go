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
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/urfave/cli/v2"
)

func generatePreimages(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, false)
	defer chaindb.Close()

	// Read chain config
	genesisHash := rawdb.ReadCanonicalHash(chaindb, 0)
	if genesisHash == (common.Hash{}) {
		return errors.New("no genesis block found in database")
	}
	chainConfig := rawdb.ReadChainConfig(chaindb, genesisHash)
	if chainConfig == nil {
		return errors.New("chain config not found in database")
	}

	// Determine block range
	startBlock := ctx.Uint64(bintrieReplayStartFlag.Name)
	endBlock := ctx.Uint64(bintrieReplayEndFlag.Name)
	if startBlock == 0 {
		return errors.New("--start is required")
	}
	if endBlock == 0 {
		headBlock := rawdb.ReadHeadBlock(chaindb)
		if headBlock == nil {
			return errors.New("no head block found")
		}
		endBlock = headBlock.NumberU64()
	}
	log.Info("Generating preimages by re-executing blocks", "start", startBlock, "end", endBlock, "blocks", endBlock-startBlock+1)

	// Open MPT triedb
	srcTriedb := utils.MakeTrieDatabase(ctx, stack, chaindb, false, false, false)
	defer srcTriedb.Close()

	stateDB := state.NewDatabase(srcTriedb, nil)

	// Create consensus engine and chain context
	engine := beacon.New(ethash.NewFaker())
	chain := &replayChain{
		chaindb: chaindb,
		config:  chainConfig,
		engine:  engine,
	}

	processor := core.NewStateProcessor(chain)

	// Process each block
	t0 := time.Now()
	totalPreimages := 0

	for blockNum := startBlock; blockNum <= endBlock; blockNum++ {
		hash := rawdb.ReadCanonicalHash(chaindb, blockNum)
		if hash == (common.Hash{}) {
			return fmt.Errorf("block %d not found in database", blockNum)
		}
		block := rawdb.ReadBlock(chaindb, hash, blockNum)
		if block == nil {
			return fmt.Errorf("block %d body not found", blockNum)
		}

		// Get parent state root
		parentHash := rawdb.ReadCanonicalHash(chaindb, blockNum-1)
		parent := rawdb.ReadHeader(chaindb, parentHash, blockNum-1)
		if parent == nil {
			return fmt.Errorf("parent block %d not found", blockNum-1)
		}

		// Open state at parent root
		sdb, err := state.New(parent.Root, stateDB)
		if err != nil {
			return fmt.Errorf("cannot open state at block %d (root %x): %v", blockNum-1, parent.Root, err)
		}

		// Process the block
		result, err := processor.Process(block, sdb, vm.Config{})
		if err != nil {
			return fmt.Errorf("block %d processing failed: %v", blockNum, err)
		}

		// Write preimages from this block
		preimages := sdb.Preimages()
		if len(preimages) > 0 {
			rawdb.WritePreimages(chaindb, preimages)
			totalPreimages += len(preimages)
		}

		if blockNum%10 == 0 || blockNum == endBlock {
			log.Info("Processed block", "number", blockNum, "txs", len(block.Transactions()),
				"gas", result.GasUsed, "preimages", len(preimages), "total_new", totalPreimages,
				"elapsed", common.PrettyDuration(time.Since(t0)))
		}
	}

	log.Info("Preimage generation complete",
		"blocks", endBlock-startBlock+1,
		"new_preimages", totalPreimages,
		"elapsed", common.PrettyDuration(time.Since(t0)),
	)
	return nil
}
