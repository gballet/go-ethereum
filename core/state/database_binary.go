// Copyright 2026 The go-ethereum Authors
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

package state

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/bintrie"
	"github.com/ethereum/go-ethereum/trie/transitiontrie"
	"github.com/ethereum/go-ethereum/triedb"
)

// BinaryDB is an implementation of Database for binary tries. It uses
// the binary trie database as the primary store. During the MPT-to-binary
// transition, an optional MPT trie database provides read-only access to
// pre-transition state via a frozen base root.
type BinaryDB struct {
	bintriedb *triedb.Database
	mpttriedb *triedb.Database
	codedb    *CodeDB
	snap      *snapshot.Tree
	baseRoot  common.Hash
}

// NewBinaryDatabase creates a state database backed by a binary trie. This
// is used for post-transition chains and binary-at-genesis chains where no
// MPT fallback is needed.
func NewBinaryDatabase(bintriedb *triedb.Database, codedb *CodeDB) *BinaryDB {
	if codedb == nil {
		codedb = NewCodeDB(bintriedb.Disk())
	}
	return &BinaryDB{
		bintriedb: bintriedb,
		codedb:    codedb,
	}
}

// NewTransitionDatabase creates a state database for the active MPT-to-binary
// transition period. Reads fall through from the binary overlay to the frozen
// MPT base at baseRoot. Writes always go to the binary trie.
func NewTransitionDatabase(bintriedb, mpttriedb *triedb.Database, codedb *CodeDB, baseRoot common.Hash) *BinaryDB {
	if codedb == nil {
		codedb = NewCodeDB(bintriedb.Disk())
	}
	return &BinaryDB{
		bintriedb: bintriedb,
		mpttriedb: mpttriedb,
		codedb:    codedb,
		baseRoot:  baseRoot,
	}
}

// WithSnapshot configures the state snapshot tree. This must be called before
// the database is used.
func (db *BinaryDB) WithSnapshot(snap *snapshot.Tree) *BinaryDB {
	db.snap = snap
	return db
}

// StateReader returns a state reader associated with the specified state root.
func (db *BinaryDB) StateReader(stateRoot common.Hash) (StateReader, error) {
	var readers []StateReader

	reader, err := db.bintriedb.StateReader(stateRoot)
	if err == nil {
		readers = append(readers, newFlatReader(reader))
	}
	if db.mpttriedb != nil {
		baseReader, err := db.mpttriedb.StateReader(db.baseRoot)
		if err == nil {
			readers = append(readers, newFlatReader(baseReader))
		}
		tr, err := db.newTransitionTrieReader(stateRoot)
		if err != nil {
			return nil, err
		}
		readers = append(readers, tr)
	} else {
		tr, err := newTrieReader(stateRoot, db.bintriedb, nil)
		if err != nil {
			return nil, err
		}
		readers = append(readers, tr)
	}
	return newMultiStateReader(readers...)
}

// newTransitionTrieReader constructs a trie reader that wraps a TransitionTrie
// using data from both the binary trie database and the MPT trie database.
func (db *BinaryDB) newTransitionTrieReader(root common.Hash) (*trieReader, error) {
	bt, err := bintrie.NewBinaryTrie(root, db.bintriedb)
	if err != nil {
		bt, err = bintrie.NewBinaryTrie(common.Hash{}, db.bintriedb)
		if err != nil {
			return nil, err
		}
	}
	var base *trie.StateTrie
	if db.baseRoot != (common.Hash{}) {
		base, err = trie.NewStateTrie(trie.StateTrieID(db.baseRoot), db.mpttriedb)
		if err != nil {
			return nil, err
		}
	}
	tr := transitiontrie.NewTransitionTrie(base, bt, false)
	return &trieReader{
		root:     root,
		db:       db.bintriedb,
		mainTrie: tr,
		subRoots: make(map[common.Address]common.Hash),
		subTries: make(map[common.Address]Trie),
	}, nil
}

// Reader returns a state reader associated with the specified state root.
func (db *BinaryDB) Reader(stateRoot common.Hash) (Reader, error) {
	sr, err := db.StateReader(stateRoot)
	if err != nil {
		return nil, err
	}
	return newReader(db.codedb.Reader(), sr), nil
}

// ReadersWithCacheStats creates a pair of state readers that share the same
// underlying state reader and internal state cache, while maintaining separate
// statistics respectively.
func (db *BinaryDB) ReadersWithCacheStats(stateRoot common.Hash) (Reader, Reader, error) {
	r, err := db.StateReader(stateRoot)
	if err != nil {
		return nil, nil, err
	}
	sr := newStateReaderWithCache(r)
	ra := newReader(db.codedb.Reader(), newStateReaderWithStats(sr))
	rb := newReader(db.codedb.Reader(), newStateReaderWithStats(sr))
	return ra, rb, nil
}

// OpenTrie opens the main account trie at a specific root hash.
func (db *BinaryDB) OpenTrie(root common.Hash) (Trie, error) {
	if db.mpttriedb != nil {
		bt, err := bintrie.NewBinaryTrie(root, db.bintriedb)
		if err != nil {
			bt, err = bintrie.NewBinaryTrie(common.Hash{}, db.bintriedb)
			if err != nil {
				return nil, err
			}
		}
		base, err := trie.NewStateTrie(trie.StateTrieID(db.baseRoot), db.mpttriedb)
		if err != nil {
			return nil, err
		}
		return transitiontrie.NewTransitionTrie(base, bt, false), nil
	}
	return bintrie.NewBinaryTrie(root, db.bintriedb)
}

// OpenStorageTrie opens the storage trie of an account.
func (db *BinaryDB) OpenStorageTrie(stateRoot common.Hash, address common.Address, root common.Hash, self Trie) (Trie, error) {
	if self != nil && self.IsVerkle() {
		return self, nil
	}
	if db.mpttriedb != nil {
		return trie.NewStateTrie(trie.StorageTrieID(stateRoot, crypto.Keccak256Hash(address.Bytes()), root), db.mpttriedb)
	}
	return nil, errors.New("no MPT trie database available for storage trie")
}

// TrieDB returns the underlying binary trie database.
func (db *BinaryDB) TrieDB() *triedb.Database {
	return db.bintriedb
}

// Snapshot returns the underlying state snapshot.
func (db *BinaryDB) Snapshot() *snapshot.Tree {
	return db.snap
}

// Commit flushes all pending writes to the binary trie database.
func (db *BinaryDB) Commit(update *stateUpdate) error {
	if update.empty() {
		return nil
	}
	if len(update.codes) > 0 {
		batch := db.codedb.NewBatchWithSize(len(update.codes))
		for _, code := range update.codes {
			batch.Put(code.hash, code.blob)
		}
		if err := batch.Commit(); err != nil {
			return err
		}
	}
	if db.snap != nil && db.snap.Snapshot(update.originRoot) != nil {
		if err := db.snap.Update(update.root, update.originRoot, update.accounts, update.storages); err != nil {
			log.Warn("Failed to update snapshot tree", "from", update.originRoot, "to", update.root, "err", err)
		}
		if err := db.snap.Cap(update.root, TriesInMemory); err != nil {
			log.Warn("Failed to cap snapshot tree", "root", update.root, "layers", TriesInMemory, "err", err)
		}
	}
	originRoot := update.originRoot
	if db.mpttriedb != nil && originRoot == db.baseRoot {
		originRoot = types.EmptyBinaryHash
	}
	return db.bintriedb.Update(update.root, originRoot, update.blockNumber, update.nodes, update.stateSet())
}
