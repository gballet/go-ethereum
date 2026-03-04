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
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/urfave/cli/v2"
)

var (
	deleteSourceFlag = &cli.BoolFlag{
		Name:  "delete-source",
		Usage: "Delete MPT trie nodes after conversion",
	}
	memoryLimitFlag = &cli.Uint64Flag{
		Name:  "memory-limit",
		Usage: "Max heap allocation in MB before forcing a commit cycle",
		Value: 16384,
	}
	freshConvertFlag = &cli.BoolFlag{
		Name:  "fresh",
		Usage: "Delete existing binary trie data and start conversion from scratch",
	}

	bintrieCommand = &cli.Command{
		Name:        "bintrie",
		Usage:       "A set of commands for binary trie operations",
		Description: "",
		Subcommands: []*cli.Command{
			{
				Name:      "convert",
				Usage:     "Convert MPT state to binary trie",
				ArgsUsage: "[state-root]",
				Action:    convertToBinaryTrie,
				Flags: slices.Concat([]cli.Flag{
					deleteSourceFlag,
					memoryLimitFlag,
					freshConvertFlag,
				}, utils.NetworkFlags, utils.DatabaseFlags),
				Description: `
geth bintrie convert [--delete-source] [--memory-limit MB] [state-root]

Reads all state from the Merkle Patricia Trie and writes it into a Binary Trie,
operating offline. Memory-safe via periodic commit-and-reload cycles.

The optional state-root argument specifies which state root to convert.
If omitted, the head block's state root is used.

Flags:
  --delete-source    Delete MPT trie nodes after successful conversion
  --memory-limit     Max heap allocation in MB before forcing a commit (default: 16384)
`,
			},
			{
				Name:   "replay",
				Usage:  "Replay blocks on the binary trie (offline state re-execution)",
				Action: replayBinaryTrie,
				Flags: slices.Concat([]cli.Flag{
					bintrieReplayStartFlag,
					bintrieReplayEndFlag,
					bintrieReplayBatchFlag,
					bintrieReplayRootFlag,
					bintrieReplayNoCommitFlag,
				}, utils.NetworkFlags, utils.DatabaseFlags),
				Description: `
geth bintrie replay --start <block> [--end <block>] [--batch <n>]

Replays blocks from the chain database against the binary trie state,
starting from the block at which the MPT-to-binary conversion was performed.

This command does NOT verify state roots against the block headers (since the
binary trie produces different roots than the MPT). It processes transactions,
applies state changes, and commits the resulting binary trie state.

Flags:
  --start   Block number at which the binary trie conversion was done (required)
  --end     Block number to stop at (default: head block)
  --batch   Blocks between disk flushes (default: 128)
`,
			},
			{
				Name:   "generate-preimages",
				Usage:  "Re-execute blocks to generate missing preimages",
				Action: generatePreimages,
				Flags: slices.Concat([]cli.Flag{
					bintrieReplayStartFlag,
					bintrieReplayEndFlag,
				}, utils.NetworkFlags, utils.DatabaseFlags),
				Description: `
geth bintrie generate-preimages --start <block> [--end <block>]

Re-executes blocks from the chain database to record storage key preimages.
Use this when blocks were originally synced without --cache.preimages.
`,
			},
		},
	}
)

type conversionStats struct {
	accounts   uint64
	slots      uint64
	codes      uint64
	commits    uint64
	start      time.Time
	lastReport time.Time
	lastMemChk time.Time
	lastKey    []byte // current iterator key for progress tracking

	// Cumulative timing for bottleneck analysis
	hashTime         time.Duration // time in bt.Commit() (hashing)
	dbTime           time.Duration // time in destDB.Update() + destDB.Commit() (DB writes)
	gcTime           time.Duration // time in runtime.GC() + FreeOSMemory()
	reloadTime       time.Duration // time to reload trie after commit
	iterTime         time.Duration // time iterating the MPT (account + storage iterators)
	insertTime       time.Duration // time in binTrie.UpdateStorage/UpdateAccount/UpdateContractCode
	resolveTime      time.Duration // time resolving hashed nodes during insertion (subset of insertTime)
	resolveCnt       uint64        // number of node resolutions
	preimageTime     time.Duration // time looking up preimages (GetKey)
	codeReadTime     time.Duration // time reading contract code from DB
	stoTrieTime      time.Duration // time opening storage tries (NewStateTrie + NodeIterator)
	rlpTime          time.Duration // time decoding RLP (accounts + storage values)
	missingPreimages uint64        // count of skipped entries due to missing preimages
}

func (s *conversionStats) report(force bool) {
	if !force && time.Since(s.lastReport) < 8*time.Second {
		return
	}
	elapsed := time.Since(s.start).Seconds()
	acctRate := float64(0)
	if elapsed > 0 {
		acctRate = float64(s.accounts) / elapsed
	}
	// Estimate progress from first byte of iterator key (0x00..0xFF → 0%..100%)
	progress := "n/a"
	if len(s.lastKey) > 0 {
		pct := float64(s.lastKey[0]) / 256.0 * 100.0
		progress = fmt.Sprintf("%.1f%%", pct)
	}
	// Compute the "other" time: total - all measured phases
	measured := s.hashTime + s.dbTime + s.gcTime + s.reloadTime + s.iterTime + s.insertTime + s.preimageTime + s.codeReadTime + s.stoTrieTime + s.rlpTime
	other := time.Since(s.start) - measured
	if other < 0 {
		other = 0
	}
	log.Info("Conversion progress",
		"progress", progress,
		"accounts", s.accounts,
		"slots", s.slots,
		"codes", s.codes,
		"commits", s.commits,
		"accounts/sec", fmt.Sprintf("%.0f", acctRate),
		"elapsed", common.PrettyDuration(time.Since(s.start)),
		"t_iter", common.PrettyDuration(s.iterTime),
		"t_insert", common.PrettyDuration(s.insertTime),
		"t_resolve", fmt.Sprintf("%s (%d calls)", common.PrettyDuration(s.resolveTime), s.resolveCnt),
		"t_preimage", common.PrettyDuration(s.preimageTime),
		"t_code", common.PrettyDuration(s.codeReadTime),
		"t_stoTrie", common.PrettyDuration(s.stoTrieTime),
		"t_rlp", common.PrettyDuration(s.rlpTime),
		"t_hash", common.PrettyDuration(s.hashTime),
		"t_db", common.PrettyDuration(s.dbTime),
		"t_gc", common.PrettyDuration(s.gcTime),
		"t_reload", common.PrettyDuration(s.reloadTime),
		"t_other", common.PrettyDuration(other),
		"missing", s.missingPreimages,
	)
	s.lastReport = time.Now()
}

func convertToBinaryTrie(ctx *cli.Context) error {
	if ctx.NArg() > 1 {
		return errors.New("too many arguments")
	}
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, false)
	defer chaindb.Close()

	headBlock := rawdb.ReadHeadBlock(chaindb)
	if headBlock == nil {
		return errors.New("no head block found")
	}
	var (
		root common.Hash
		err  error
	)
	if ctx.NArg() == 1 {
		root, err = parseRoot(ctx.Args().First())
		if err != nil {
			return fmt.Errorf("invalid state root: %v", err)
		}
	} else {
		root = headBlock.Root()
	}
	log.Info("Starting MPT to binary trie conversion", "root", root, "block", headBlock.NumberU64())

	srcTriedb := utils.MakeTrieDatabase(ctx, stack, chaindb, true, true, false)
	defer srcTriedb.Close()

	// Ensure the snap sync status flag doesn't disable the destination pathdb.
	if rawdb.ReadSnapSyncStatusFlag(chaindb) == rawdb.StateSyncRunning {
		log.Warn("Snap sync flag is set, clearing for bintrie conversion")
		rawdb.WriteSnapSyncStatusFlag(chaindb, rawdb.StateSyncFinished)
	}
	// If --fresh is set, clean up old binary trie data before opening the dest DB.
	if ctx.Bool(freshConvertFlag.Name) {
		log.Info("Fresh conversion requested, clearing old binary trie data")
		// Delete the conversion progress marker
		if err := chaindb.Delete(bintrieConvertMarkerKey); err != nil {
			log.Warn("Failed to delete conversion marker", "err", err)
		}
		// Delete all verkle-prefixed trie nodes from the key-value store
		verklePrefix := string(rawdb.VerklePrefix)
		it := chaindb.NewIterator([]byte(verklePrefix), nil)
		batch := chaindb.NewBatch()
		cleaned := 0
		for it.Next() {
			if err := batch.Delete(it.Key()); err != nil {
				it.Release()
				return fmt.Errorf("failed to delete verkle key: %v", err)
			}
			cleaned++
			if cleaned%10000 == 0 {
				if err := batch.Write(); err != nil {
					it.Release()
					return fmt.Errorf("failed to write cleanup batch: %v", err)
				}
				batch.Reset()
			}
		}
		it.Release()
		if err := batch.Write(); err != nil {
			return fmt.Errorf("failed to write final cleanup batch: %v", err)
		}
		// Also remove the bintrie journal directory and state_verkle ancient store
		bintrieJournalDir := stack.ResolvePath("triedb-bintrie")
		os.RemoveAll(bintrieJournalDir)
		verkleAncientDir := filepath.Join(stack.ResolvePath("chaindata"), "ancient", "state_verkle")
		os.RemoveAll(verkleAncientDir)
		log.Info("Cleaned old binary trie data", "keys", cleaned)
	}

	destTriedb := triedb.NewDatabase(chaindb, &triedb.Config{
		IsVerkle: true,
		PathDB: &pathdb.Config{
			JournalDirectory: stack.ResolvePath("triedb-bintrie"),
		},
	})
	defer destTriedb.Close()

	// Determine the current binary trie root from the destination pathdb.
	// If a previous partial conversion left data in the verkle namespace,
	// the disk layer root will be non-empty. We must use that as both
	// the starting trie root and the parent root for Update() calls.
	verkleDB := rawdb.NewTable(chaindb, string(rawdb.VerklePrefix))
	destRoot := types.EmptyBinaryHash
	if blob := rawdb.ReadAccountTrieNode(verkleDB, nil); len(blob) > 0 {
		n, err := bintrie.DeserializeNode(blob, 0)
		if err != nil {
			return fmt.Errorf("failed to deserialize existing binary root: %v", err)
		}
		destRoot = n.Hash()
		log.Info("Resuming from existing binary trie root", "root", destRoot)
	}
	binTrie, err := bintrie.NewBinaryTrie(destRoot, destTriedb)
	if err != nil {
		return fmt.Errorf("failed to create binary trie: %v", err)
	}
	memLimit := ctx.Uint64(memoryLimitFlag.Name) * 1024 * 1024

	currentRoot, err := runConversionLoop(chaindb, srcTriedb, destTriedb, binTrie, root, memLimit, destRoot)
	if err != nil {
		return err
	}
	log.Info("Conversion complete", "binaryRoot", currentRoot)
	// Clean up the conversion marker now that we're done.
	if err := chaindb.Delete(bintrieConvertMarkerKey); err != nil {
		log.Warn("Failed to delete conversion marker", "err", err)
	}

	if ctx.Bool(deleteSourceFlag.Name) {
		log.Info("Deleting source MPT data")
		if err := deleteMPTData(chaindb, srcTriedb, root); err != nil {
			return fmt.Errorf("MPT deletion failed: %v", err)
		}
		log.Info("Source MPT data deleted")
	}
	return nil
}

func runConversion(chaindb ethdb.Database, srcTriedb *triedb.Database, binTrie *bintrie.BinaryTrie, root common.Hash) error {
	srcTrie, err := trie.NewStateTrie(trie.StateTrieID(root), srcTriedb)
	if err != nil {
		return fmt.Errorf("failed to open source trie: %v", err)
	}
	acctIt, err := srcTrie.NodeIterator(nil)
	if err != nil {
		return fmt.Errorf("failed to create account iterator: %v", err)
	}
	accIter := trie.NewIterator(acctIt)

	for accIter.Next() {
		var acc types.StateAccount
		if err := rlp.DecodeBytes(accIter.Value, &acc); err != nil {
			return fmt.Errorf("invalid account RLP: %v", err)
		}
		addrBytes := srcTrie.GetKey(accIter.Key)
		if addrBytes == nil {
			return fmt.Errorf("missing preimage for account hash %x (run with --cache.preimages)", accIter.Key)
		}
		addr := common.BytesToAddress(addrBytes)

		var code []byte
		codeHash := common.BytesToHash(acc.CodeHash)
		if codeHash != types.EmptyCodeHash {
			code = rawdb.ReadCode(chaindb, codeHash)
			if code == nil {
				return fmt.Errorf("missing code for hash %x (account %x)", codeHash, addr)
			}
		}

		if err := binTrie.UpdateAccount(addr, &acc, len(code)); err != nil {
			return fmt.Errorf("failed to update account %x: %v", addr, err)
		}
		if len(code) > 0 {
			if err := binTrie.UpdateContractCode(addr, codeHash, code); err != nil {
				return fmt.Errorf("failed to update code for %x: %v", addr, err)
			}
		}

		if acc.Root != types.EmptyRootHash {
			addrHash := common.BytesToHash(accIter.Key)
			storageTrie, err := trie.NewStateTrie(trie.StorageTrieID(root, addrHash, acc.Root), srcTriedb)
			if err != nil {
				return fmt.Errorf("failed to open storage trie for %x: %v", addr, err)
			}
			storageNodeIt, err := storageTrie.NodeIterator(nil)
			if err != nil {
				return fmt.Errorf("failed to create storage iterator for %x: %v", addr, err)
			}
			storageIter := trie.NewIterator(storageNodeIt)

			for storageIter.Next() {
				slotKey := storageTrie.GetKey(storageIter.Key)
				if slotKey == nil {
					return fmt.Errorf("missing preimage for storage key %x (account %x)", storageIter.Key, addr)
				}
				_, content, _, err := rlp.Split(storageIter.Value)
				if err != nil {
					return fmt.Errorf("invalid storage RLP for key %x (account %x): %v", slotKey, addr, err)
				}
				if err := binTrie.UpdateStorage(addr, slotKey, content); err != nil {
					return fmt.Errorf("failed to update storage %x/%x: %v", addr, slotKey, err)
				}
			}
			if storageIter.Err != nil {
				return fmt.Errorf("storage iteration error for %x: %v", addr, storageIter.Err)
			}
		}
	}
	if accIter.Err != nil {
		return fmt.Errorf("account iteration error: %v", accIter.Err)
	}
	return nil
}

// Key used to persist the conversion progress marker in the database.
var bintrieConvertMarkerKey = []byte("bintrie-convert-marker")

func runConversionLoop(chaindb ethdb.Database, srcTriedb *triedb.Database, destTriedb *triedb.Database, binTrie *bintrie.BinaryTrie, root common.Hash, memLimit uint64, initialRoot common.Hash) (common.Hash, error) {
	currentRoot := initialRoot
	stats := &conversionStats{
		start:      time.Now(),
		lastReport: time.Now(),
		lastMemChk: time.Now(),
	}

	// Load the conversion marker to resume from where we left off.
	var startKey []byte
	if marker, _ := chaindb.Get(bintrieConvertMarkerKey); len(marker) > 0 {
		startKey = marker
		log.Info("Resuming conversion from marker", "marker", common.Bytes2Hex(startKey))
	}

	srcTrie, err := trie.NewStateTrie(trie.StateTrieID(root), srcTriedb)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to open source trie: %v", err)
	}
	acctIt, err := srcTrie.NodeIterator(startKey)
	if err != nil {
		return common.Hash{}, fmt.Errorf("failed to create account iterator: %v", err)
	}
	accIter := trie.NewIterator(acctIt)

	tIterStart := time.Now()
	for accIter.Next() {
		stats.iterTime += time.Since(tIterStart)

		tRLP := time.Now()
		var acc types.StateAccount
		if err := rlp.DecodeBytes(accIter.Value, &acc); err != nil {
			return common.Hash{}, fmt.Errorf("invalid account RLP: %v", err)
		}
		stats.rlpTime += time.Since(tRLP)

		tPreimage := time.Now()
		addrBytes := srcTrie.GetKey(accIter.Key)
		stats.preimageTime += time.Since(tPreimage)
		if addrBytes == nil {
			stats.missingPreimages++
			if stats.missingPreimages <= 20 {
				log.Warn("Missing preimage for account, skipping", "key", common.Bytes2Hex(accIter.Key))
			}
			tIterStart = time.Now()
			continue
		}
		addr := common.BytesToAddress(addrBytes)

		var code []byte
		codeHash := common.BytesToHash(acc.CodeHash)
		if codeHash != types.EmptyCodeHash {
			tCode := time.Now()
			code = rawdb.ReadCode(chaindb, codeHash)
			stats.codeReadTime += time.Since(tCode)
			if code == nil {
				return common.Hash{}, fmt.Errorf("missing code for hash %x (account %x)", codeHash, addr)
			}
			stats.codes++
		}

		tInsert := time.Now()
		if err := binTrie.UpdateAccount(addr, &acc, len(code)); err != nil {
			return common.Hash{}, fmt.Errorf("failed to update account %x: %v", addr, err)
		}
		if len(code) > 0 {
			if err := binTrie.UpdateContractCode(addr, codeHash, code); err != nil {
				return common.Hash{}, fmt.Errorf("failed to update code for %x: %v", addr, err)
			}
		}
		stats.insertTime += time.Since(tInsert)

		if acc.Root != types.EmptyRootHash {
			addrHash := common.BytesToHash(accIter.Key)
			tStoTrie := time.Now()
			storageTrie, err := trie.NewStateTrie(trie.StorageTrieID(root, addrHash, acc.Root), srcTriedb)
			if err != nil {
				return common.Hash{}, fmt.Errorf("failed to open storage trie for %x: %v", addr, err)
			}
			storageNodeIt, err := storageTrie.NodeIterator(nil)
			if err != nil {
				return common.Hash{}, fmt.Errorf("failed to create storage iterator for %x: %v", addr, err)
			}
			stats.stoTrieTime += time.Since(tStoTrie)
			storageIter := trie.NewIterator(storageNodeIt)

			slotCount := uint64(0)
			tIterStart = time.Now()
			for storageIter.Next() {
				stats.iterTime += time.Since(tIterStart)

				tPreimage = time.Now()
				slotKey := storageTrie.GetKey(storageIter.Key)
				stats.preimageTime += time.Since(tPreimage)
				if slotKey == nil {
					stats.missingPreimages++
					if stats.missingPreimages <= 20 {
						log.Warn("Missing preimage for storage key, skipping", "key", common.Bytes2Hex(storageIter.Key), "account", addr)
					}
					tIterStart = time.Now()
					continue
				}
				tRLP = time.Now()
				_, content, _, err := rlp.Split(storageIter.Value)
				stats.rlpTime += time.Since(tRLP)
				if err != nil {
					return common.Hash{}, fmt.Errorf("invalid storage RLP for key %x (account %x): %v", slotKey, addr, err)
				}
				tInsert = time.Now()
				if err := binTrie.UpdateStorage(addr, slotKey, content); err != nil {
					return common.Hash{}, fmt.Errorf("failed to update storage %x/%x: %v", addr, slotKey, err)
				}
				stats.insertTime += time.Since(tInsert)
				stats.slots++
				slotCount++

				if slotCount%1000 == 0 {
					binTrie, currentRoot, err = maybeCommit(binTrie, currentRoot, destTriedb, memLimit, stats, nil)
					if err != nil {
						return common.Hash{}, err
					}
				}
				tIterStart = time.Now()
			}
			if storageIter.Err != nil {
				return common.Hash{}, fmt.Errorf("storage iteration error for %x: %v", addr, storageIter.Err)
			}
		}
		stats.accounts++
		stats.lastKey = accIter.Key
		stats.report(false)
		tIterStart = time.Now()

		if stats.accounts%1000 == 0 {
			binTrie, currentRoot, err = maybeCommit(binTrie, currentRoot, destTriedb, memLimit, stats, chaindb)
			if err != nil {
				return common.Hash{}, err
			}
		}
	}
	if accIter.Err != nil {
		return common.Hash{}, fmt.Errorf("account iteration error: %v", accIter.Err)
	}

	// Collect resolve stats from the trie before final commit
	stats.resolveTime += binTrie.ResolveTime
	stats.resolveCnt += binTrie.ResolveCnt

	_, currentRoot, err = commitBinaryTrie(binTrie, currentRoot, destTriedb, stats)
	if err != nil {
		return common.Hash{}, fmt.Errorf("final commit failed: %v", err)
	}
	stats.commits++
	stats.report(true)
	return currentRoot, nil
}

func maybeCommit(bt *bintrie.BinaryTrie, currentRoot common.Hash, destDB *triedb.Database, memLimit uint64, stats *conversionStats, chaindb ethdb.Database) (*bintrie.BinaryTrie, common.Hash, error) {
	// Only check memory stats at most once per second to avoid overhead
	if time.Since(stats.lastMemChk) < time.Second {
		return bt, currentRoot, nil
	}
	stats.lastMemChk = time.Now()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if m.Alloc < memLimit {
		return bt, currentRoot, nil
	}
	log.Info("Memory limit reached, committing", "alloc", common.StorageSize(m.Alloc), "limit", common.StorageSize(memLimit))

	// Collect resolve stats from the trie before commit reloads it
	stats.resolveTime += bt.ResolveTime
	stats.resolveCnt += bt.ResolveCnt

	bt, currentRoot, err := commitBinaryTrie(bt, currentRoot, destDB, stats)
	if err != nil {
		return nil, common.Hash{}, err
	}
	// Persist the conversion marker so we can skip already-converted accounts on resume.
	if chaindb != nil && len(stats.lastKey) > 0 {
		if err := chaindb.Put(bintrieConvertMarkerKey, stats.lastKey); err != nil {
			return nil, common.Hash{}, fmt.Errorf("failed to save conversion marker: %v", err)
		}
	}
	stats.commits++
	stats.report(true)
	return bt, currentRoot, nil
}

func commitBinaryTrie(bt *bintrie.BinaryTrie, currentRoot common.Hash, destDB *triedb.Database, stats *conversionStats) (*bintrie.BinaryTrie, common.Hash, error) {
	// Phase 1: Hash computation
	t0 := time.Now()
	newRoot, nodeSet := bt.Commit(false)
	stats.hashTime += time.Since(t0)

	// If root hasn't changed (e.g. replaying already-converted data after resume),
	// skip the DB update and just GC.
	if newRoot == currentRoot {
		log.Info("Root unchanged, skipping DB commit (replaying converted data)", "root", newRoot)
		runtime.GC()
		debug.FreeOSMemory()
		bt, err := bintrie.NewBinaryTrie(newRoot, destDB)
		if err != nil {
			return nil, common.Hash{}, fmt.Errorf("failed to reload binary trie: %v", err)
		}
		return bt, currentRoot, nil
	}

	// Phase 2: DB writes
	if nodeSet != nil {
		t1 := time.Now()
		dbgNodes, dbgStorage := nodeSet.Size()
		log.Info("NodeSet details", "nodes", dbgNodes, "storage", common.StorageSize(dbgStorage))
		merged := trienode.NewWithNodeSet(nodeSet)
		if err := destDB.Update(newRoot, currentRoot, 0, merged, triedb.NewStateSet()); err != nil {
			return nil, common.Hash{}, fmt.Errorf("triedb update failed (newRoot=%x currentRoot=%x): %v", newRoot, currentRoot, err)
		}
		if err := destDB.Commit(newRoot, false); err != nil {
			return nil, common.Hash{}, fmt.Errorf("triedb commit failed: %v", err)
		}
		stats.dbTime += time.Since(t1)
		nodes, storage := nodeSet.Size()
		log.Info("Commit details", "nodes", nodes, "storage", common.StorageSize(storage), "hash", stats.hashTime, "db", stats.dbTime)
	}

	// Phase 3: GC
	t2 := time.Now()
	runtime.GC()
	debug.FreeOSMemory()
	stats.gcTime += time.Since(t2)

	// Phase 4: Reload trie
	t3 := time.Now()
	bt, err := bintrie.NewBinaryTrie(newRoot, destDB)
	if err != nil {
		return nil, common.Hash{}, fmt.Errorf("failed to reload binary trie: %v", err)
	}
	stats.reloadTime += time.Since(t3)
	return bt, newRoot, nil
}

func deleteMPTData(chaindb ethdb.Database, srcTriedb *triedb.Database, root common.Hash) error {
	isPathDB := srcTriedb.Scheme() == rawdb.PathScheme

	srcTrie, err := trie.NewStateTrie(trie.StateTrieID(root), srcTriedb)
	if err != nil {
		return fmt.Errorf("failed to open source trie for deletion: %v", err)
	}
	acctIt, err := srcTrie.NodeIterator(nil)
	if err != nil {
		return fmt.Errorf("failed to create account iterator for deletion: %v", err)
	}
	batch := chaindb.NewBatch()
	deleted := 0

	for acctIt.Next(true) {
		if isPathDB {
			rawdb.DeleteAccountTrieNode(batch, acctIt.Path())
		} else {
			node := acctIt.Hash()
			if node != (common.Hash{}) {
				rawdb.DeleteLegacyTrieNode(batch, node)
			}
		}
		deleted++

		if acctIt.Leaf() {
			var acc types.StateAccount
			if err := rlp.DecodeBytes(acctIt.LeafBlob(), &acc); err != nil {
				return fmt.Errorf("invalid account during deletion: %v", err)
			}
			if acc.Root != types.EmptyRootHash {
				addrHash := common.BytesToHash(acctIt.LeafKey())
				storageTrie, err := trie.NewStateTrie(trie.StorageTrieID(root, addrHash, acc.Root), srcTriedb)
				if err != nil {
					return fmt.Errorf("failed to open storage trie for deletion: %v", err)
				}
				storageIt, err := storageTrie.NodeIterator(nil)
				if err != nil {
					return fmt.Errorf("failed to create storage iterator for deletion: %v", err)
				}
				for storageIt.Next(true) {
					if isPathDB {
						rawdb.DeleteStorageTrieNode(batch, addrHash, storageIt.Path())
					} else {
						node := storageIt.Hash()
						if node != (common.Hash{}) {
							rawdb.DeleteLegacyTrieNode(batch, node)
						}
					}
					deleted++
					if batch.ValueSize() >= ethdb.IdealBatchSize {
						if err := batch.Write(); err != nil {
							return fmt.Errorf("batch write failed: %v", err)
						}
						batch.Reset()
					}
				}
				if storageIt.Error() != nil {
					return fmt.Errorf("storage deletion iterator error: %v", storageIt.Error())
				}
			}
		}
		if batch.ValueSize() >= ethdb.IdealBatchSize {
			if err := batch.Write(); err != nil {
				return fmt.Errorf("batch write failed: %v", err)
			}
			batch.Reset()
		}
	}
	if acctIt.Error() != nil {
		return fmt.Errorf("account deletion iterator error: %v", acctIt.Error())
	}
	if batch.ValueSize() > 0 {
		if err := batch.Write(); err != nil {
			return fmt.Errorf("final batch write failed: %v", err)
		}
	}
	log.Info("MPT deletion complete", "nodesDeleted", deleted)
	return nil
}
