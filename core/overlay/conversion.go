// Copyright 2023 The go-ethereum Authors
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

package overlay

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-verkle"
	"github.com/holiman/uint256"
)

var zeroTreeIndex uint256.Int

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

// OverlayVerkleTransition contains the overlay conversion logic
func OverlayVerkleTransition(statedb *state.StateDB, root common.Hash, maxMovedCount uint64) error {
	migrdb := statedb.Database()
	migrdb.LockCurrentTransitionState()
	defer migrdb.UnLockCurrentTransitionState()

	// verkle transition: if the conversion process is in progress, move
	// N values from the MPT into the verkle tree.
	if migrdb.InTransition() {
		log.Debug("Processing verkle conversion starting", "account hash", migrdb.GetCurrentAccountHash(), "slot hash", migrdb.GetCurrentSlotHash(), "state root", root)
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
				return fmt.Errorf("seeking preimage file: %s", err)
			}
			fpreimages = bufio.NewReader(filePreimages)
			hasPreimagesBin = true
		}

		accIt, err := statedb.Snaps().AccountIterator(mpt.Hash(), migrdb.GetCurrentAccountHash())
		if err != nil {
			return err
		}
		defer accIt.Release()
		accIt.Next()

		// If we're about to start with the migration process, we have to read the first account hash preimage.
		if migrdb.GetCurrentAccountAddress() == nil {
			var addr common.Address
			if hasPreimagesBin {
				if _, err := io.ReadFull(fpreimages, addr[:]); err != nil {
					return fmt.Errorf("reading preimage file: %s", err)
				}
			} else {
				addr = common.BytesToAddress(rawdb.ReadPreimage(migrdb.DiskDB(), accIt.Hash()))
				if len(addr) != 20 {
					return fmt.Errorf("addr len is zero is not 32: %d", len(addr))
				}
			}
			migrdb.SetCurrentAccountAddress(addr)
			if migrdb.GetCurrentAccountHash() != accIt.Hash() {
				return fmt.Errorf("preimage file does not match account hash: %s != %s", crypto.Keccak256Hash(addr[:]), accIt.Hash())
			}
			preimageSeek += int64(len(addr))
		}

		// move maxCount accounts into the verkle tree, starting with the
		// slots from the previous account.
		count := uint64(0)

		// if less than maxCount slots were moved, move to the next account
		for count < maxMovedCount {
			acc, err := types.FullAccount(accIt.Account())
			if err != nil {
				log.Error("Invalid account encountered during traversal", "error", err)
				return err
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
					return err
				}
				processed := stIt.Next()
				if processed {
					log.Debug("account has storage and a next item")
				} else {
					log.Debug("account has storage and NO next item")
				}

				// fdb.StorageProcessed will be initialized to `true` if the
				// entire storage for an account was not entirely processed
				// by the previous block. This is used as a signal to resume
				// processing the storage for that account where we left off.
				// If the entire storage was processed, then the iterator was
				// created in vain, but it's ok as this will not happen often.
				for ; !migrdb.GetStorageProcessed() && count < maxMovedCount; count++ {
					log.Trace("Processing storage", "count", count, "slot", stIt.Slot(), "storage processed", migrdb.GetStorageProcessed(), "current account", migrdb.GetCurrentAccountAddress(), "current account hash", migrdb.GetCurrentAccountHash())
					var (
						value     []byte   // slot value after RLP decoding
						safeValue [32]byte // 32-byte aligned value
					)
					if err := rlp.DecodeBytes(stIt.Slot(), &value); err != nil {
						return fmt.Errorf("error decoding bytes %x: %w", stIt.Slot(), err)
					}
					copy(safeValue[32-len(value):], value)

					var slotnr []byte
					if hasPreimagesBin {
						var s [32]byte
						slotnr = s[:]
						if _, err := io.ReadFull(fpreimages, slotnr); err != nil {
							return fmt.Errorf("reading preimage file: %s", err)
						}
					} else {
						slotnr = rawdb.ReadPreimage(migrdb.DiskDB(), stIt.Hash())
						if len(slotnr) != 32 {
							return fmt.Errorf("slotnr len is zero is not 32: %d", len(slotnr))
						}
					}
					log.Trace("found slot number", "number", slotnr)
					if crypto.Keccak256Hash(slotnr[:]) != stIt.Hash() {
						return fmt.Errorf("preimage file does not match storage hash: %s!=%s", crypto.Keccak256Hash(slotnr), stIt.Hash())
					}
					preimageSeek += int64(len(slotnr))

					if err := tt.Overlay().UpdateStorage(*migrdb.GetCurrentAccountAddress(), slotnr, safeValue[:]); err != nil {
						return fmt.Errorf("updating storage slot %x at address %x: %w", slotnr, *migrdb.GetCurrentAccountAddress(), err)
					}

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

				var code []byte
				if !bytes.Equal(acc.CodeHash, types.EmptyCodeHash[:]) {
					code = rawdb.ReadCode(statedb.Database().DiskDB(), common.BytesToHash(acc.CodeHash))
					tt.Overlay().UpdateContractCode(*migrdb.GetCurrentAccountAddress(), common.BytesToHash(acc.CodeHash), code)
				}

				tt.Overlay().UpdateAccount(*migrdb.GetCurrentAccountAddress(), acc, len(code))
				vkt.ClearStrorageRootConversion(*migrdb.GetCurrentAccountAddress())

				// reset storage iterator marker for next account
				migrdb.SetStorageProcessed(false)
				migrdb.SetCurrentSlotHash(common.Hash{})

				// Move to the next account, if available - or end
				// the transition otherwise.
				if accIt.Next() {
					log.Trace("Found another account to convert", "hash", accIt.Hash())
					var addr common.Address
					if hasPreimagesBin {
						if _, err := io.ReadFull(fpreimages, addr[:]); err != nil {
							return fmt.Errorf("reading preimage file: %s", err)
						}
					} else {
						addr = common.BytesToAddress(rawdb.ReadPreimage(migrdb.DiskDB(), accIt.Hash()))
						if len(addr) != 20 {
							return fmt.Errorf("account address len is zero is not 20: %d", len(addr))
						}
					}
					if crypto.Keccak256Hash(addr[:]) != accIt.Hash() {
						return fmt.Errorf("preimage file does not match account hash: %s != %s", crypto.Keccak256Hash(addr[:]), accIt.Hash())
					}
					log.Trace("Converting account address", "hash", accIt.Hash(), "addr", addr)
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

		log.Info("Inserted key values in overlay tree", "count", count, "duration", time.Since(now), "last account hash", statedb.Database().GetCurrentAccountHash(), "last account address", statedb.Database().GetCurrentAccountAddress(), "storage processed", statedb.Database().GetStorageProcessed(), "last storage", statedb.Database().GetCurrentSlotHash())
	}

	return nil
}
