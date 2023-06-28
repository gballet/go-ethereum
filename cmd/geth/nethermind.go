// Copyright 2015 The go-ethereum Authors
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
	// "context"
	// "encoding/json"
	// "errors"
	"fmt"
	// "math/big"
	"os"
	// "runtime"
	// "strconv"
	// "sync/atomic"
	"bufio"
	"encoding/hex"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	// "github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/ethclient"
	// "github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	// "github.com/ethereum/go-ethereum/metrics"
	// "github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/urfave/cli/v2"
	// "github.com/tecbot/gorocksdb"
)

var (
	nethermindCommand = &cli.Command{
		Action:    nethermindImport,
		Name:      "nethermind",
		Usage:     "Import a Nethermind database",
		ArgsUsage: "<neth db path> <block hash>",
		Flags: flags.Merge([]cli.Flag{
			utils.CacheFlag,
			utils.SyncModeFlag,
			utils.GCModeFlag,
			utils.SnapshotFlag,
			utils.CacheDatabaseFlag,
			utils.CacheGCFlag,
			utils.MetricsEnabledFlag,
			utils.MetricsEnabledExpensiveFlag,
			utils.MetricsHTTPFlag,
			utils.MetricsPortFlag,
			utils.MetricsEnableInfluxDBFlag,
			utils.MetricsEnableInfluxDBV2Flag,
			utils.MetricsInfluxDBEndpointFlag,
			utils.MetricsInfluxDBDatabaseFlag,
			utils.MetricsInfluxDBUsernameFlag,
			utils.MetricsInfluxDBPasswordFlag,
			utils.MetricsInfluxDBTagsFlag,
			utils.MetricsInfluxDBTokenFlag,
			utils.MetricsInfluxDBBucketFlag,
			utils.MetricsInfluxDBOrganizationFlag,
			utils.TxLookupLimitFlag,
		}, utils.DatabasePathFlags),
		Description: `
The import command imports blocks from an RLP-encoded form. The form can be one file
with several RLP-encoded blocks, or several files can be used.

If only one file is used, import error will result in failure. If several files are used,
processing will proceed even if an individual RLP-file import failure occurs.`,
	}
)

func importStateFromFile(db ethdb.Database) {
	// Import snapshot from file
	batch := db.NewBatch()
	inputFile, err := os.Open("state.txt")
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	// Create a scanner to read the input file line by line
	scanner := bufio.NewScanner(inputFile)

	var (
		// 	lastAccountHash common.Hash
		lastStorageRoot common.Hash
		count           uint64
		stTrie          *trie.StackTrie
		savenode        = func(owner common.Hash, path []byte, hash common.Hash, blob []byte) {
			rawdb.WriteTrieNode(batch, hash, blob)
		}
		accTrie  = trie.NewStackTrie(savenode)
		headRoot = common.HexToHash("833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69")
	)

	// Read each line and process the hex values
	for scanner.Scan() {
		line := scanner.Text()
		hexValues := strings.Split(line, ":")
		if len(hexValues) != 3 {
			fmt.Printf("Invalid line format: %s\n", line)
			continue
		}

		// Convert each hex value to its []byte representation
		var byteValues [][]byte
		for _, hexValue := range hexValues {
			byteValue, err := hex.DecodeString(hexValue)
			if err != nil {
				fmt.Printf("Invalid hex value: %s\n", hexValue)
				continue
			}
			byteValues = append(byteValues, byteValue)
		}

		// is this part of the account tree ?
		if hexValues[0] == "833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69" {
			// new account, verifies that the storage of the previous account
			// account is in agreement.
			if lastStorageRoot != (common.Hash{}) {
				_, err := stTrie.Commit()
				if err != nil {
					panic(err)
				}
				if stTrie.Hash() != lastStorageRoot {
					fmt.Printf("invalid storage root %x != %x\n", stTrie.Hash(), lastStorageRoot)
					panic("ici")
				}
				// if count > 1000000 {
				// 	break
				// }
				lastStorageRoot = common.Hash{}
				stTrie = nil
			}
			err = accTrie.TryUpdate(byteValues[1], byteValues[2])
			if err != nil {
				panic(err)
			}
			var account types.StateAccount
			rlp.DecodeBytes(byteValues[2], &account)

			if account.Root != emptyRoot {
				stTrie = trie.NewStackTrie(savenode)
				lastStorageRoot = account.Root
			}
			// 		accountHash := common.BytesToHash(byteValues[1])
			// 		rawdb.WriteAccountSnapshot(batch, accountHash, snapshot.SlimAccountRLP(account.Nonce, account.Balance, account.Root, account.CodeHash))
			// 		lastAccountHash = accountHash

		} else {
			err = stTrie.TryUpdate(byteValues[1], byteValues[2])
			if err != nil {
				panic(err)
			}
			// 		storageHash := common.BytesToHash(byteValues[0])
			// 		rawdb.WriteStorageSnapshot(batch, lastAccountHash, storageHash, byteValues[2])
		}
		count++
		if count%1000000 == 0 {
			log.Info("Processing", "line count", count)
			if err := batch.Write(); err != nil {
				panic(err)
			}
			batch = db.NewBatch()
		}
	}
	if lastStorageRoot != (common.Hash{}) {
		log.Info("processing storage for last account")
		_, err := stTrie.Commit()
		if err != nil {
			panic(err)
		}
		if stTrie.Hash() != lastStorageRoot {
			fmt.Printf("invalid storage root %x != %x\n", stTrie.Hash(), lastStorageRoot)
			panic("ici")
		}
		stTrie = nil
	}
	h, err := accTrie.Commit()
	if err != nil {
		panic(err)
	}
	fmt.Println(h)
	if accTrie.Hash() != headRoot {
		panic("incorrect root hash")
	}
	if err := batch.Write(); err != nil {
		panic(err)
	}
	/////////////////////////////////////////////////////////////

	// ////////////////// REBUILD SNAPSHOT //////////////////////
	_, err = snapshot.New(snapshot.Config{CacheSize: 2048}, db, trie.NewDatabase(db), headRoot)
	if err != nil {
		panic(err)
	}
	// if err := snaptree.Cap( /* headRoot */ accTrie.Hash(), 0); err != nil {
	// 	panic(err)
	// }
}

func nethermindImport(ctx *cli.Context) error {
	if ctx.Args().Len() < 2 {
		utils.Fatalf("This command requires two arguments.")
	}

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	// chain, db := utils.MakeChain(ctx, stack, false)
	db := utils.MakeChainDatabase(ctx, stack, false)
	triedb := trie.NewDatabase(db)
	core.SetupGenesisBlock(db, triedb, core.DefaultGnosisGenesisBlock())

	// importStateFromFile(db)
	db.Close()
	/////////////////////////////////////////////////////////////

	fmt.Println("redemarre la chaine")
	chain, db := utils.MakeChain(ctx, stack, false)
	chain.Stop()
	db.Close()

	// regenerate the trie from it
	// stateBloom, err := pruner.NewStateBloomWithSize(2048)
	// if err != nil {
	// 	return err
	// }
	// if err := snapshot.GenerateTrie(snaptree, headRoot, db, stateBloom); err != nil {
	// 	panic(err)
	// }

	// // var importErr error
	// opts := gorocksdb.NewDefaultOptions()
	// opts.SetCreateIfMissing(false)

	// idbHeaders, err := gorocksdb.Open(opts, ctx.Args().First()+"/xdai/headers")
	// if err != nil {
	// 	panic(err)
	// }
	// roh := gorocksdb.NewDefaultReadOptions()
	// defer roh.Close()

	// header, err := db.Get(roh, ctx.Args().Slice()[1])
	// if err != nil {
	// 	panic(err)
	// }

	// var h types.Header
	// err = rlp.DecodeBytes(header[:], &h)
	// if err != nil {
	// 	panic(err)
	// }

	// idbNode, err := gorocksdb.Open(opts, ctx.Args().First()+"/xdai/state/0")
	// if err != nil {
	// 	panic(err)
	// }
	// // TODO check idbNode shouldn't be freed somehow
	// ror := gorocksdb.NewDefaultReadOptions()
	// defer ror.Close()

	// rootNode, err := db.Get(ror, h.Root[:])
	// if err != nil {
	// 	panic(err)
	// }
	// var root [17]common.Hash
	// err = rlp.DecodeBytes(rootNode, &root)
	// if err != nil {
	// 	panic(err)
	// }

	// fonction recursive qui va chercher les enfants et les balance dans la DB
	// db.NewBatch().Put(...)

	// if ctx.Args().Len() == 1 {
	// 	if err := utils.ImportChain(chain, ctx.Args().First()); err != nil {
	// 		importErr = err
	// 		log.Error("Import error", "err", err)
	// 	}
	// } else {
	// 	for _, arg := range ctx.Args().Slice() {
	// 		if err := utils.ImportChain(chain, arg); err != nil {
	// 			importErr = err
	// 			log.Error("Import error", "file", arg, "err", err)
	// 		}
	// 	}
	// }
	// chain.Stop()
	fmt.Printf("Import done in %v.\n\n", time.Since(start))

	// Output pre-compaction stats mostly to see the import trashing
	// showLeveldbStats(db)

	// Print the memory statistics used by the importing
	// mem := new(runtime.MemStats)
	// runtime.ReadMemStats(mem)

	// fmt.Printf("Object memory: %.3f MB current, %.3f MB peak\n", float64(mem.Alloc)/1024/1024, float64(atomic.LoadUint64(&peakMemAlloc))/1024/1024)
	// fmt.Printf("System memory: %.3f MB current, %.3f MB peak\n", float64(mem.Sys)/1024/1024, float64(atomic.LoadUint64(&peakMemSys))/1024/1024)
	// fmt.Printf("Allocations:   %.3f million\n", float64(mem.Mallocs)/1000000)
	// fmt.Printf("GC pause:      %v\n\n", time.Duration(mem.PauseTotalNs))

	// if ctx.Bool(utils.NoCompactionFlag.Name) {
	// 	return nil
	// }

	// // Compact the entire database to more accurately measure disk io and print the stats
	// start = time.Now()
	// fmt.Println("Compacting entire database...")
	// if err := db.Compact(nil, nil); err != nil {
	// 	utils.Fatalf("Compaction failed: %v", err)
	// }
	// fmt.Printf("Compaction done in %v.\n\n", time.Since(start))

	// showLeveldbStats(db)
	// return importErr
	return nil
}
