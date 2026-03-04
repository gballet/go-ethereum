package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/triedb"
	"github.com/ethereum/go-ethereum/triedb/pathdb"
	"github.com/urfave/cli/v2"
)

func init() {
	// Add verify subcommand to bintrieCommand
	bintrieCommand.Subcommands = append(bintrieCommand.Subcommands, &cli.Command{
		Name:   "verify",
		Usage:  "Spot-check binary trie state against MPT state",
		Action: verifyBinaryTrie,
		Flags: slices.Concat([]cli.Flag{
			&cli.Uint64Flag{Name: "count", Usage: "Number of accounts to verify", Value: 100},
			&cli.Uint64Flag{Name: "block", Usage: "Block number to compare at"},
			&cli.StringFlag{Name: "address", Usage: "Compare storage for a specific contract address"},
		}, utils.NetworkFlags, utils.DatabaseFlags),
	})
}

func verifyBinaryTrie(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, false) // read-write needed for pathdb init
	defer chaindb.Close()

	// Use a specific block number if provided, otherwise head
	var mptRoot common.Hash
	var blockNum uint64
	if ctx.IsSet("block") {
		blockNum = ctx.Uint64("block")
		hash := rawdb.ReadCanonicalHash(chaindb, blockNum)
		if hash == (common.Hash{}) {
			return fmt.Errorf("block %d not found", blockNum)
		}
		header := rawdb.ReadHeader(chaindb, hash, blockNum)
		if header == nil {
			return fmt.Errorf("header for block %d not found", blockNum)
		}
		mptRoot = header.Root
	} else {
		headBlock := rawdb.ReadHeadBlock(chaindb)
		if headBlock == nil {
			return errors.New("no head block found")
		}
		mptRoot = headBlock.Root()
		blockNum = headBlock.NumberU64()
	}
	log.Info("Verifying binary trie against MPT", "block", blockNum, "mptRoot", mptRoot)

	// Open MPT
	srcTriedb := utils.MakeTrieDatabase(ctx, stack, chaindb, true, false, false)
	defer srcTriedb.Close()

	// Open binary trie
	destTriedb := triedb.NewDatabase(chaindb, &triedb.Config{
		IsVerkle: true,
		PathDB: &pathdb.Config{
			JournalDirectory: stack.ResolvePath("triedb-bintrie"),
		},
	})
	defer destTriedb.Close()

	// Auto-detect binary root
	verkleDB := rawdb.NewTable(chaindb, string(rawdb.VerklePrefix))
	blob := rawdb.ReadAccountTrieNode(verkleDB, nil)
	if len(blob) == 0 {
		return errors.New("no binary trie root found")
	}
	n, err := bintrie.DeserializeNode(blob, 0)
	if err != nil {
		return fmt.Errorf("failed to deserialize binary root: %v", err)
	}
	binRoot := n.Hash()
	log.Info("Binary trie root", "root", binRoot)

	// Open both state DBs
	binStateDB := state.NewDatabase(destTriedb, nil)
	binState, err := state.New(binRoot, binStateDB)
	if err != nil {
		return fmt.Errorf("failed to open binary state: %v", err)
	}
	// Disable access events to avoid issues
	binState.SetAccessEvents(nil)

	mptStateDB := state.NewDatabase(srcTriedb, nil)

	// Try the requested root, then fall back to scanning for an available root
	mptState, err := state.New(mptRoot, mptStateDB)
	if err != nil {
		log.Warn("Requested MPT root not available, trying disk layer root", "requested", mptRoot)
		// The pathdb disk layer root is read automatically; try block range near target
		headBlock := rawdb.ReadHeadBlock(chaindb)
		if headBlock != nil {
			// Search backwards from head for an available state
			for trial := headBlock.NumberU64(); trial > 0 && trial > headBlock.NumberU64()-200; trial-- {
				hash := rawdb.ReadCanonicalHash(chaindb, trial)
				if hash == (common.Hash{}) {
					continue
				}
				header := rawdb.ReadHeader(chaindb, hash, trial)
				if header == nil {
					continue
				}
				mptState, err = state.New(header.Root, mptStateDB)
				if err == nil {
					log.Info("Found available MPT state", "block", trial, "root", header.Root)
					mptRoot = header.Root
					break
				}
			}
		}
		if err != nil {
			return fmt.Errorf("failed to open MPT state at any recent root: %v", err)
		}
	}

	// If --address is set, do targeted storage comparison for that contract
	if ctx.IsSet("address") {
		targetAddr := common.HexToAddress(ctx.String("address"))
		log.Info("Comparing storage for specific contract", "addr", targetAddr)

		// Iterate MPT storage trie for target account
		storageRoot := mptState.GetStorageRoot(targetAddr)
		if storageRoot == (common.Hash{}) {
			return fmt.Errorf("account %s has empty storage root in MPT", targetAddr)
		}
		log.Info("MPT storage root", "root", storageRoot)
		addrHash := crypto.Keccak256Hash(targetAddr.Bytes())
		storageTrie, err := trie.NewStateTrie(trie.StorageTrieID(mptRoot, addrHash, storageRoot), srcTriedb)
		if err != nil {
			return fmt.Errorf("failed to open MPT storage trie: %v", err)
		}
		storageIt, err := storageTrie.NodeIterator(nil)
		if err != nil {
			return fmt.Errorf("failed to create storage iterator: %v", err)
		}
		iter := trie.NewIterator(storageIt)

		checked := uint64(0)
		mismatches := uint64(0)
		for iter.Next() {
			slotKey := storageTrie.GetKey(iter.Key)
			if slotKey == nil {
				continue
			}
			slot := common.BytesToHash(slotKey)

			mptVal := mptState.GetState(targetAddr, slot)
			binVal := binState.GetState(targetAddr, slot)

			if mptVal != binVal {
				log.Error("STORAGE MISMATCH",
					"addr", targetAddr,
					"slot", slot,
					"mptVal", mptVal,
					"binVal", binVal,
				)
				mismatches++
			}
			checked++
			if checked%10000 == 0 {
				log.Info("Storage compare progress", "slots", checked, "mismatches", mismatches)
			}
		}
		if iter.Err != nil {
			return fmt.Errorf("storage iteration error: %v", iter.Err)
		}
		log.Info("Storage comparison complete", "slots", checked, "mismatches", mismatches)
		return nil
	}

	// Iterate MPT accounts and compare
	srcTrie, err := trie.NewStateTrie(trie.StateTrieID(mptRoot), srcTriedb)
	if err != nil {
		return fmt.Errorf("failed to open source trie: %v", err)
	}
	acctIt, err := srcTrie.NodeIterator(nil)
	if err != nil {
		return fmt.Errorf("failed to create iterator: %v", err)
	}
	accIter := trie.NewIterator(acctIt)

	count := ctx.Uint64("count")
	checked := uint64(0)
	mismatches := uint64(0)

	for accIter.Next() && checked < count {
		addrBytes := srcTrie.GetKey(accIter.Key)
		if addrBytes == nil {
			continue
		}
		addr := common.BytesToAddress(addrBytes)

		mptBal := mptState.GetBalance(addr)
		binBal := binState.GetBalance(addr)
		mptNonce := mptState.GetNonce(addr)
		binNonce := binState.GetNonce(addr)
		mptCode := mptState.GetCodeHash(addr)
		binCode := binState.GetCodeHash(addr)

		match := true
		if mptBal.Cmp(binBal) != 0 {
			log.Error("Balance mismatch", "addr", addr, "mpt", mptBal, "bin", binBal)
			match = false
		}
		if mptNonce != binNonce {
			log.Error("Nonce mismatch", "addr", addr, "mpt", mptNonce, "bin", binNonce)
			match = false
		}
		if mptCode != binCode {
			log.Error("CodeHash mismatch", "addr", addr, "mpt", mptCode, "bin", binCode)
			match = false
		}
		if !match {
			mismatches++
		}
		checked++
		if checked%1000 == 0 {
			log.Info("Verification progress", "checked", checked, "mismatches", mismatches)
		}
	}

	log.Info("Verification complete", "checked", checked, "mismatches", mismatches)
	return nil
}
