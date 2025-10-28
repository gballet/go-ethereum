// Copyright 2025 The go-ethereum Authors
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
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/urfave/cli/v2"
)

var (
	app = &cli.App{
		Name:    "snapbench",
		Usage:   "Benchmark snapshot to account trie root recomputation",
		Version: "1.0.0",
		Flags: append([]cli.Flag{
			utils.DataDirFlag,
			utils.AncientFlag,
			utils.DBEngineFlag,
			utils.StateSchemeFlag,
		}, debug.Flags...),
		Before: func(ctx *cli.Context) error {
			return debug.Setup(ctx)
		},
		After: func(ctx *cli.Context) error {
			debug.Exit()
			return nil
		},
		Commands: []*cli.Command{
			{
				Name:   "rebuild",
				Usage:  "Rebuild account trie root from snapshot and measure time",
				Action: benchmarkRebuild,
			},
		},
	}
)

func main() {
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func benchmarkRebuild(ctx *cli.Context) error {
	// Create node and open database
	stack, err := makeConfigNode(ctx)
	if err != nil {
		return fmt.Errorf("failed to create node: %w", err)
	}
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, true) // readonly
	defer chaindb.Close()

	log.Info("Database opened", "datadir", stack.DataDir())

	// Get the head block root
	headBlock := rawdb.ReadHeadBlock(chaindb)
	if headBlock == nil {
		return fmt.Errorf("no head block found in database")
	}
	headRoot := headBlock.Root()
	headNumber := headBlock.NumberU64()

	log.Info("Head block loaded", "number", headNumber, "root", headRoot)

	// Check if snapshot root exists
	snapRoot := rawdb.ReadSnapshotRoot(chaindb)
	if snapRoot == (common.Hash{}) {
		return fmt.Errorf("no snapshot found in database")
	}

	log.Info("Snapshot found", "root", snapRoot)

	// Initialize trie database
	triedb := utils.MakeTrieDatabase(ctx, stack, chaindb, false, true, false)
	defer triedb.Close()

	// Open snapshot tree
	snapConfig := snapshot.Config{
		CacheSize:  256,
		Recovery:   false,
		NoBuild:    true,  // Don't rebuild if missing
		AsyncBuild: false,
	}

	snaptree, err := snapshot.New(snapConfig, chaindb, triedb, headRoot)
	if err != nil {
		return fmt.Errorf("failed to open snapshot: %w", err)
	}

	log.Info("Snapshot tree opened successfully")

	// Get account iterator
	acctIt, err := snaptree.AccountIterator(headRoot, common.Hash{})
	if err != nil {
		return fmt.Errorf("failed to create account iterator: %w", err)
	}
	defer acctIt.Release()

	log.Info("Starting account trie rebuild with StackTrie...")

	// Start timing
	startTime := time.Now()

	// Create StackTrie (nil = no node callback)
	stackTrie := trie.NewStackTrie(nil)
	count := 0
	var lastLog time.Time

	// Iterate through all accounts
	for acctIt.Next() {
		accountHash := acctIt.Hash()
		slimData := acctIt.Account()

		// Convert slim account format to full account RLP
		// This is CRITICAL - snapshot stores slim format, trie needs full format
		fullData, err := types.FullAccountRLP(slimData)
		if err != nil {
			return fmt.Errorf("failed to convert account at hash %x: %w", accountHash, err)
		}

		// Update StackTrie with the account
		// Note: accounts are already in ascending order from the iterator
		if err := stackTrie.Update(accountHash[:], fullData); err != nil {
			return fmt.Errorf("failed to update trie at account %x: %w", accountHash, err)
		}

		count++

		// Log progress every 10k accounts or every 5 seconds
		if count%10000 == 0 || time.Since(lastLog) > 5*time.Second {
			elapsed := time.Since(startTime)
			rate := float64(count) / elapsed.Seconds()
			log.Info("Progress",
				"accounts", count,
				"elapsed", elapsed.Round(time.Millisecond),
				"rate", fmt.Sprintf("%.0f acct/s", rate))
			lastLog = time.Now()
		}
	}

	// Check for iterator errors
	if err := acctIt.Error(); err != nil {
		return fmt.Errorf("iterator error: %w", err)
	}

	// Compute final root
	computedRoot := stackTrie.Hash()
	duration := time.Since(startTime)

	// Calculate statistics
	accountsPerSecond := float64(count) / duration.Seconds()

	// Print results
	fmt.Println("\n" + string(make([]byte, 80)) + "\n")
	log.Info("=== Benchmark Results ===")
	log.Info("Total accounts processed", "count", count)
	log.Info("Total duration", "time", duration)
	log.Info("Processing rate", "accounts_per_sec", fmt.Sprintf("%.2f", accountsPerSecond))
	log.Info("Expected root", "hash", headRoot)
	log.Info("Computed root", "hash", computedRoot)

	if computedRoot == headRoot {
		log.Info("Root verification", "status", "SUCCESS - roots match!")
		return nil
	} else {
		log.Error("Root verification", "status", "FAILED - roots do not match")
		return fmt.Errorf("root mismatch: computed %x != expected %x", computedRoot, headRoot)
	}
}

// makeConfigNode creates a node with the configuration from the CLI context
func makeConfigNode(ctx *cli.Context) (*node.Node, error) {
	// Create default node config
	cfg := node.DefaultConfig
	cfg.Name = "snapbench"
	cfg.DataDir = ctx.String(utils.DataDirFlag.Name)

	// Set ancient datadir if specified
	if ctx.IsSet(utils.AncientFlag.Name) {
		cfg.DBEngine = ctx.String(utils.DBEngineFlag.Name)
	}

	// Create and return the node
	stack, err := node.New(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create node: %w", err)
	}

	return stack, nil
}
