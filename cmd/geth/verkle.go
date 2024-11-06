// Copyright 2022 The go-ethereum Authors
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
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	tutils "github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-verkle"
	cli "github.com/urfave/cli/v2"
)

var (
	zero [32]byte

	verkleCommand = &cli.Command{
		Name:        "verkle",
		Usage:       "A set of experimental verkle tree management commands",
		Description: "",
		Subcommands: []*cli.Command{
			{
				Name:      "to-verkle",
				Usage:     "use the snapshot to compute a translation of a MPT into a verkle tree",
				ArgsUsage: "<root>",
				Action:    convertToVerkle,
				Flags:     flags.Merge([]cli.Flag{}, utils.NetworkFlags, utils.DatabasePathFlags),
				Description: `
geth verkle to-verkle <state-root>
This command takes a snapshot and inserts its values in a fresh verkle tree.

The argument is interpreted as the root hash. If none is provided, the latest
block is used.
 `,
			},
			{
				Name:      "verify",
				Usage:     "verify the conversion of a MPT into a verkle tree",
				ArgsUsage: "<root>",
				Action:    verifyVerkle,
				Flags:     flags.Merge(utils.NetworkFlags, utils.DatabasePathFlags),
				Description: `
geth verkle verify <state-root>
This command takes a root commitment and attempts to rebuild the tree.
 `,
			},
			{
				Name:      "dump",
				Usage:     "Dump a verkle tree to a DOT file",
				ArgsUsage: "<root> <key1> [<key 2> ...]",
				Action:    expandVerkle,
				Flags:     flags.Merge(utils.NetworkFlags, utils.DatabasePathFlags),
				Description: `
geth verkle dump <state-root> <key 1> [<key 2> ...]
This command will produce a dot file representing the tree, rooted at <root>.
in which key1, key2, ... are expanded.
 `,
			},
		},
	}
)

func convertToVerkle(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, false)
	if chaindb == nil {
		return errors.New("nil chaindb")
	}
	headBlock := rawdb.ReadHeadBlock(chaindb)
	if headBlock == nil {
		log.Error("Failed to load head block")
		return errors.New("no head block")
	}
	if ctx.NArg() > 1 {
		log.Error("Too many arguments given")
		return errors.New("too many arguments")
	}
	var (
		root common.Hash
		err  error
	)
	if ctx.NArg() == 1 {
		root, err = parseRoot(ctx.Args().First())
		if err != nil {
			log.Error("Failed to resolve state root", "error", err)
			return err
		}
		log.Info("Start traversing the state", "root", root)
	} else {
		root = headBlock.Root()
		log.Info("Start traversing the state", "root", root, "number", headBlock.NumberU64())
	}

	var (
		accounts   int
		lastReport time.Time
		start      = time.Now()
		vRoot      = verkle.New().(*verkle.InternalNode)
	)

	saveverkle := func(path []byte, node verkle.VerkleNode) {
		node.Commit()
		s, err := node.Serialize()
		if err != nil {
			panic(err)
		}
		if err := chaindb.Put(path, s); err != nil {
			panic(err)
		}
	}

	triedb := trie.NewDatabase(chaindb)
	snaptree, err := snapshot.New(snapshot.Config{CacheSize: 256}, chaindb, triedb, root)
	if err != nil {
		return err
	}
	accIt, err := snaptree.AccountIterator(root, common.Hash{})
	if err != nil {
		return err
	}
	defer accIt.Release()

	vkt := trie.NewVerkleTrie(&trie.BinaryNode{}, triedb, tutils.NewPointCache(), false)
	count := 0

	// root.FlushAtDepth(depth, saveverkle)

	// Process all accounts sequentially
	for accIt.Next() {
		accounts += 1
		acc, err := types.FullAccount(accIt.Account())
		if err != nil {
			log.Error("Invalid account encountered during traversal", "error", err)
			return err
		}
		var code []byte
		// if !bytes.Equal(acc.CodeHash[:], types.EmptyCodeHash) {

		// }

		addr := rawdb.ReadPreimage(chaindb, accIt.Hash())
		if addr == nil {
			panic("can't find preimage for address")
		}
		err = vkt.UpdateAccount(common.BytesToAddress(addr), acc, len(code))
		if err != nil {
			panic(err)
		}
		if len(code) > 0 {
			err = vkt.UpdateContractCode(common.BytesToAddress(addr), common.Hash(acc.CodeHash), code)
			if err != nil {
				panic(err)
			}
		}

		// Save every slot into the tree
		if acc.Root != types.EmptyRootHash {
			storageIt, err := snaptree.StorageIterator(root, accIt.Hash(), common.Hash{})
			if err != nil {
				log.Error("Failed to open storage trie", "root", acc.Root, "error", err)
				return err
			}
			for storageIt.Next() {
				count++
				// The value is RLP-encoded, decode it
				var (
					value     []byte   // slot value after RLP decoding
					safeValue [32]byte // 32-byte aligned value
				)
				if err := rlp.DecodeBytes(storageIt.Slot(), &value); err != nil {
					return fmt.Errorf("error decoding bytes %x: %w", storageIt.Slot(), err)
				}
				copy(safeValue[32-len(value):], value)

				slotnr := rawdb.ReadPreimage(chaindb, storageIt.Hash())
				if slotnr == nil {
					return fmt.Errorf("could not find preimage for slot %x", storageIt.Hash())
				}

				err = vkt.UpdateStorage(common.BytesToAddress(addr), slotnr, safeValue[:])
				if err != nil {
					panic(err)
				}

				if count > 100_000 {
					fmt.Println("committing")
					vkt.Commit(false)
					count = 0
				}
			}
			storageIt.Release()
			if storageIt.Error() != nil {
				log.Error("Failed to traverse storage trie", "root", acc.Root, "error", storageIt.Error())
				return storageIt.Error()
			}
		}
		if time.Since(lastReport) > time.Second*8 {
			log.Info("Traversing state", "accounts", accounts, "elapsed", common.PrettyDuration(time.Since(start)))
			lastReport = time.Now()
		}
	}
	if accIt.Error() != nil {
		log.Error("Failed to compute commitment", "root", root, "error", accIt.Error())
		return accIt.Error()
	}
	log.Info("Wrote all leaves", "accounts", accounts, "elapsed", common.PrettyDuration(time.Since(start)))

	vRoot.Commit()
	vRoot.Flush(saveverkle)

	log.Info("Conversion complete", "root commitment", fmt.Sprintf("%x", vRoot.Commit().Bytes()), "accounts", accounts, "elapsed", common.PrettyDuration(time.Since(start)))
	return nil
}

// recurse into each child to ensure they can be loaded from the db. The tree isn't rebuilt
// (only its nodes are loaded) so there is no need to flush them, the garbage collector should
// take care of that for us.
func checkChildren(root verkle.VerkleNode, resolver verkle.NodeResolverFn) error {
	switch node := root.(type) {
	case *verkle.InternalNode:
		for i, child := range node.Children() {
			childC := child.Commitment().Bytes()

			childS, err := resolver(childC[:])
			if bytes.Equal(childC[:], zero[:]) {
				continue
			}
			if err != nil {
				return fmt.Errorf("could not find child %x in db: %w", childC, err)
			}
			// depth is set to 0, the tree isn't rebuilt so it's not a problem
			childN, err := verkle.ParseNode(childS, 0)
			if err != nil {
				return fmt.Errorf("decode error child %x in db: %w", child.Commitment().Bytes(), err)
			}
			if err := checkChildren(childN, resolver); err != nil {
				return fmt.Errorf("%x%w", i, err) // write the path to the erroring node
			}
		}
	case *verkle.LeafNode:
		// sanity check: ensure at least one value is non-zero

		for i := 0; i < verkle.NodeWidth; i++ {
			if len(node.Value(i)) != 0 {
				return nil
			}
		}
		return errors.New("both balance and nonce are 0")
	case verkle.Empty:
		// nothing to do
	default:
		return fmt.Errorf("unsupported type encountered %v", root)
	}

	return nil
}

func verifyVerkle(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, true)
	headBlock := rawdb.ReadHeadBlock(chaindb)
	if headBlock == nil {
		log.Error("Failed to load head block")
		return errors.New("no head block")
	}
	if ctx.NArg() > 1 {
		log.Error("Too many arguments given")
		return errors.New("too many arguments")
	}
	var (
		rootC common.Hash
		err   error
	)
	if ctx.NArg() == 1 {
		rootC, err = parseRoot(ctx.Args().First())
		if err != nil {
			log.Error("Failed to resolve state root", "error", err)
			return err
		}
		log.Info("Rebuilding the tree", "root", rootC)
	} else {
		rootC = headBlock.Root()
		log.Info("Rebuilding the tree", "root", rootC, "number", headBlock.NumberU64())
	}

	serializedRoot, err := chaindb.Get(rootC[:])
	if err != nil {
		return err
	}
	root, err := verkle.ParseNode(serializedRoot, 0)
	if err != nil {
		return err
	}

	if err := checkChildren(root, chaindb.Get); err != nil {
		log.Error("Could not rebuild the tree from the database", "err", err)
		return err
	}

	log.Info("Tree was rebuilt from the database")
	return nil
}

func expandVerkle(ctx *cli.Context) error {
	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chaindb := utils.MakeChainDatabase(ctx, stack, true)
	var (
		rootC   common.Hash
		keylist [][]byte
		err     error
	)
	if ctx.NArg() >= 2 {
		rootC, err = parseRoot(ctx.Args().First())
		if err != nil {
			log.Error("Failed to resolve state root", "error", err)
			return err
		}
		keylist = make([][]byte, 0, ctx.Args().Len()-1)
		args := ctx.Args().Slice()
		for i := range args[1:] {
			key, err := hex.DecodeString(args[i+1])
			log.Info("decoded key", "arg", args[i+1], "key", key)
			if err != nil {
				return fmt.Errorf("error decoding key #%d: %w", i+1, err)
			}
			keylist = append(keylist, key)
		}
		log.Info("Rebuilding the tree", "root", rootC)
	} else {
		return fmt.Errorf("usage: %s root key1 [key 2...]", ctx.App.Name)
	}

	serializedRoot, err := chaindb.Get(rootC[:])
	if err != nil {
		return err
	}
	root, err := verkle.ParseNode(serializedRoot, 0)
	if err != nil {
		return err
	}

	for i, key := range keylist {
		log.Info("Reading key", "index", i, "key", keylist[0])
		root.Get(key, chaindb.Get)
	}

	if err := os.WriteFile("dump.dot", []byte(verkle.ToDot(root)), 0o600); err != nil {
		log.Error("Failed to dump file", "err", err)
	} else {
		log.Info("Tree was dumped to file", "file", "dump.dot")
	}
	return nil
}
