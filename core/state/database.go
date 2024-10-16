// Copyright 2017 The go-ethereum Authors
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
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-verkle"
)

const (
	// Number of codehash->size associations to keep.
	codeSizeCacheSize = 100000

	// Cache size granted for caching clean code.
	codeCacheSize = 64 * 1024 * 1024
)

var useBanner bool = true

func NoBanner() {
	useBanner = false
}

// Database wraps access to tries and contract code.
type Database interface {
	// OpenTrie opens the main account trie.
	OpenTrie(root common.Hash) (Trie, error)

	// OpenStorageTrie opens the storage trie of an account.
	OpenStorageTrie(stateRoot common.Hash, address common.Address, root common.Hash, main Trie) (Trie, error)

	// CopyTrie returns an independent copy of the given trie.
	CopyTrie(Trie) Trie

	// ContractCode retrieves a particular contract's code.
	ContractCode(addr common.Address, codeHash common.Hash) ([]byte, error)

	// ContractCodeSize retrieves a particular contracts code's size.
	ContractCodeSize(addr common.Address, codeHash common.Hash) (int, error)

	// DiskDB returns the underlying key-value disk database.
	DiskDB() ethdb.KeyValueStore

	// TrieDB retrieves the low level trie database used for data storage.
	TrieDB() *trie.Database

	StartVerkleTransition(originalRoot, translatedRoot common.Hash, chainConfig *params.ChainConfig, verkleTime *uint64, root common.Hash)

	ReorgThroughVerkleTransition()

	EndVerkleTransition()

	InTransition() bool

	Transitioned() bool

	InitTransitionStatus(bool, bool, common.Hash)

	SetCurrentSlotHash(common.Hash)

	GetCurrentAccountAddress() *common.Address

	SetCurrentAccountAddress(common.Address)

	GetCurrentAccountHash() common.Hash

	GetCurrentSlotHash() common.Hash

	SetStorageProcessed(bool)

	GetStorageProcessed() bool

	GetCurrentPreimageOffset() int64

	SetCurrentPreimageOffset(int64)

	AddRootTranslation(originalRoot, translatedRoot common.Hash)

	SetLastMerkleRoot(common.Hash)

	SaveTransitionState(common.Hash)

	LoadTransitionState(common.Hash)

	LockCurrentTransitionState()

	UnLockCurrentTransitionState()
}

// Trie is a Ethereum Merkle Patricia trie.
type Trie interface {
	// GetKey returns the sha3 preimage of a hashed key that was previously used
	// to store a value.
	//
	// TODO(fjl): remove this when StateTrie is removed
	GetKey([]byte) []byte

	// GetStorage returns the value for key stored in the trie. The value bytes
	// must not be modified by the caller. If a node was not found in the database,
	// a trie.MissingNodeError is returned.
	GetStorage(addr common.Address, key []byte) ([]byte, error)

	// GetAccount abstracts an account read from the trie. It retrieves the
	// account blob from the trie with provided account address and decodes it
	// with associated decoding algorithm. If the specified account is not in
	// the trie, nil will be returned. If the trie is corrupted(e.g. some nodes
	// are missing or the account blob is incorrect for decoding), an error will
	// be returned.
	GetAccount(address common.Address) (*types.StateAccount, error)

	// UpdateStorage associates key with value in the trie. If value has length zero,
	// any existing value is deleted from the trie. The value bytes must not be modified
	// by the caller while they are stored in the trie. If a node was not found in the
	// database, a trie.MissingNodeError is returned.
	UpdateStorage(addr common.Address, key, value []byte) error

	// UpdateAccount abstracts an account write to the trie. It encodes the
	// provided account object with associated algorithm and then updates it
	// in the trie with provided address.
	UpdateAccount(address common.Address, account *types.StateAccount, codeLen int) error

	// UpdateContractCode abstracts code write to the trie. It is expected
	// to be moved to the stateWriter interface when the latter is ready.
	UpdateContractCode(address common.Address, codeHash common.Hash, code []byte) error

	// DeleteStorage removes any existing value for key from the trie. If a node
	// was not found in the database, a trie.MissingNodeError is returned.
	DeleteStorage(addr common.Address, key []byte) error

	// DeleteAccount abstracts an account deletion from the trie.
	DeleteAccount(address common.Address) error

	// Hash returns the root hash of the trie. It does not write to the database and
	// can be used even if the trie doesn't have one.
	Hash() common.Hash

	// Commit collects all dirty nodes in the trie and replace them with the
	// corresponding node hash. All collected nodes(including dirty leaves if
	// collectLeaf is true) will be encapsulated into a nodeset for return.
	// The returned nodeset can be nil if the trie is clean(nothing to commit).
	// Once the trie is committed, it's not usable anymore. A new trie must
	// be created with new root and updated trie database for following usage
	Commit(collectLeaf bool) (common.Hash, *trienode.NodeSet, error)

	// NodeIterator returns an iterator that returns nodes of the trie. Iteration
	// starts at the key after the given start key. And error will be returned
	// if fails to create node iterator.
	NodeIterator(startKey []byte) (trie.NodeIterator, error)

	// Prove constructs a Merkle proof for key. The result contains all encoded nodes
	// on the path to the value at key. The value itself is also included in the last
	// node and can be retrieved by verifying the proof.
	//
	// If the trie does not contain a value for key, the returned proof contains all
	// nodes of the longest existing prefix of the key (at least the root), ending
	// with the node that proves the absence of the key.
	Prove(key []byte, proofDb ethdb.KeyValueWriter) error

	// IsVerkle returns true if the trie is verkle-tree based
	IsVerkle() bool
}

// NewDatabase creates a backing store for state. The returned database is safe for
// concurrent use, but does not retain any recent trie nodes in memory. To keep some
// historical state in memory, use the NewDatabaseWithConfig constructor.
func NewDatabase(db ethdb.Database) Database {
	return NewDatabaseWithConfig(db, nil)
}

// NewDatabaseWithConfig creates a backing store for state. The returned database
// is safe for concurrent use and retains a lot of collapsed RLP trie nodes in a
// large memory cache.
func NewDatabaseWithConfig(db ethdb.Database, config *trie.Config) Database {
	return &cachingDB{
		disk:                   db,
		codeSizeCache:          lru.NewCache[common.Hash, int](codeSizeCacheSize),
		codeCache:              lru.NewSizeConstrainedCache[common.Hash, []byte](codeCacheSize),
		triedb:                 trie.NewDatabaseWithConfig(db, config),
		addrToPoint:            utils.NewPointCache(),
		TransitionStatePerRoot: lru.NewBasicLRU[common.Hash, *TransitionState](100),
	}
}

// NewDatabaseWithNodeDB creates a state database with an already initialized node database.
func NewDatabaseWithNodeDB(db ethdb.Database, triedb *trie.Database) Database {
	return &cachingDB{
		disk:                   db,
		codeSizeCache:          lru.NewCache[common.Hash, int](codeSizeCacheSize),
		codeCache:              lru.NewSizeConstrainedCache[common.Hash, []byte](codeCacheSize),
		triedb:                 triedb,
		addrToPoint:            utils.NewPointCache(),
		TransitionStatePerRoot: lru.NewBasicLRU[common.Hash, *TransitionState](100),
	}
}

func (db *cachingDB) InTransition() bool {
	return db.CurrentTransitionState != nil && db.CurrentTransitionState.Started && !db.CurrentTransitionState.Ended
}

func (db *cachingDB) Transitioned() bool {
	return db.CurrentTransitionState != nil && db.CurrentTransitionState.Ended
}

// Fork implements the fork
func (db *cachingDB) StartVerkleTransition(originalRoot, translatedRoot common.Hash, chainConfig *params.ChainConfig, verkleTime *uint64, root common.Hash) {
	if useBanner {
		fmt.Println(`
	__________.__                       .__                .__                   __       .__                               .__          ____         
	\__    ___|  |__   ____        ____ |  |   ____ ______ |  |__ _____    _____/  |_     |  |__ _____    ______    __  _  _|__| ____   / ___\ ______
	  |    |  |  |  \_/ __ \     _/ __ \|  | _/ __ \\____ \|  |  \\__  \  /    \   __\    |  |  \\__  \  /  ___/    \ \/ \/ |  |/    \ / /_/  /  ___/
	  |    |  |   Y  \  ___/     \  ___/|  |_\  ___/|  |_> |   Y  \/ __ \|   |  |  |      |   Y  \/ __ \_\___ \      \     /|  |   |  \\___  /\___ \
	  |____|  |___|  /\___        \___  |____/\___  |   __/|___|  (____  |___|  |__|      |___|  (____  /_____/       \/\_/ |__|___|  /_____//_____/
                                                    |__|`)
	}
	db.CurrentTransitionState = &TransitionState{
		Started: true,
		// initialize so that the first storage-less accounts are processed
		StorageProcessed: true,
	}
	// db.AddTranslation(originalRoot, translatedRoot)
	db.baseRoot = originalRoot

	// Reinitialize values in case of a reorg
	if verkleTime != nil {
		chainConfig.VerkleTime = verkleTime
	}
}

func (db *cachingDB) ReorgThroughVerkleTransition() {
	log.Warn("trying to reorg through the transition, which makes no sense at this point")
}

func (db *cachingDB) InitTransitionStatus(started, ended bool, baseRoot common.Hash) {
	db.CurrentTransitionState = &TransitionState{
		Ended:   ended,
		Started: started,
		// TODO add other fields when we handle mid-transition interrupts
	}
	db.baseRoot = baseRoot
}

func (db *cachingDB) EndVerkleTransition() {
	if !db.CurrentTransitionState.Started {
		db.CurrentTransitionState.Started = true
	}

	if useBanner {
		fmt.Println(`
	__________.__                       .__                .__                   __       .__                       .__                    .___         .___
	\__    ___|  |__   ____        ____ |  |   ____ ______ |  |__ _____    _____/  |_     |  |__ _____    ______    |  | _____    ____   __| _/____   __| _/
	  |    |  |  |  \_/ __ \     _/ __ \|  | _/ __ \\____ \|  |  \\__  \  /    \   __\    |  |  \\__  \  /  ___/    |  | \__  \  /    \ / __ _/ __ \ / __ |
	  |    |  |   Y  \  ___/     \  ___/|  |_\  ___/|  |_> |   Y  \/ __ \|   |  |  |      |   Y  \/ __ \_\___ \     |  |__/ __ \|   |  / /_/ \  ___// /_/ |
	  |____|  |___|  /\___        \___  |____/\___  |   __/|___|  (____  |___|  |__|      |___|  (____  /_____/     |____(____  |___|  \____ |\___  \____ |
                                                    |__|`)
	}
	db.CurrentTransitionState.Ended = true
}

type TransitionState struct {
	CurrentAccountAddress *common.Address // addresss of the last translated account
	CurrentSlotHash       common.Hash     // hash of the last translated storage slot
	CurrentPreimageOffset int64           // next byte to read from the preimage file
	Started, Ended        bool

	// Mark whether the storage for an account has been processed. This is useful if the
	// maximum number of leaves of the conversion is reached before the whole storage is
	// processed.
	StorageProcessed bool
}

func (ts *TransitionState) Copy() *TransitionState {
	ret := &TransitionState{
		Started:               ts.Started,
		Ended:                 ts.Ended,
		CurrentSlotHash:       ts.CurrentSlotHash,
		CurrentPreimageOffset: ts.CurrentPreimageOffset,
		StorageProcessed:      ts.StorageProcessed,
	}

	if ts.CurrentAccountAddress != nil {
		ret.CurrentAccountAddress = &common.Address{}
		copy(ret.CurrentAccountAddress[:], ts.CurrentAccountAddress[:])
	}

	return ret
}

type cachingDB struct {
	disk          ethdb.KeyValueStore
	codeSizeCache *lru.Cache[common.Hash, int]
	codeCache     *lru.SizeConstrainedCache[common.Hash, []byte]
	triedb        *trie.Database

	// Transition-specific fields
	// TODO ensure that this info is in the DB
	CurrentTransitionState *TransitionState
	TransitionStatePerRoot lru.BasicLRU[common.Hash, *TransitionState]
	transitionStateLock    sync.Mutex

	addrToPoint *utils.PointCache

	baseRoot common.Hash // hash of the read-only base tree
}

func (db *cachingDB) openMPTTrie(root common.Hash) (Trie, error) {
	tr, err := trie.NewStateTrie(trie.StateTrieID(root), db.triedb)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

func (db *cachingDB) openVKTrie(_ common.Hash) (Trie, error) {
	payload, err := db.DiskDB().Get(trie.FlatDBVerkleNodeKeyPrefix)
	if err != nil {
		return trie.NewVerkleTrie(verkle.New(), db.triedb, db.addrToPoint, db.CurrentTransitionState.Ended), nil
	}

	r, err := verkle.ParseNode(payload, 0)
	if err != nil {
		panic(err)
	}
	return trie.NewVerkleTrie(r, db.triedb, db.addrToPoint, db.CurrentTransitionState.Ended), err
}

// OpenTrie opens the main account trie at a specific root hash.
func (db *cachingDB) OpenTrie(root common.Hash) (Trie, error) {
	// TODO separate both cases when I can be certain that it won't
	// find a Verkle trie where is expects a Transitoion trie.
	if db.InTransition() || db.Transitioned() {
		// NOTE this is a kaustinen-only change, it will break replay
		vkt, err := db.openVKTrie(root)
		if err != nil {
			log.Error("failed to open the vkt", "err", err)
			return nil, err
		}

		// If the verkle conversion has ended, return a single
		// verkle trie.
		if db.CurrentTransitionState.Ended {
			log.Debug("transition ended, returning a simple verkle tree")
			return vkt, nil
		}

		// Otherwise, return a transition trie, with a base MPT
		// trie and an overlay, verkle trie.
		mpt, err := db.openMPTTrie(db.baseRoot)
		if err != nil {
			log.Error("failed to open the mpt", "err", err, "root", db.baseRoot)
			return nil, err
		}

		return trie.NewTransitionTree(mpt.(*trie.SecureTrie), vkt.(*trie.VerkleTrie), false), nil
	}

	log.Info("not in transition, opening mpt alone", "root", root)
	return db.openMPTTrie(root)
}

func (db *cachingDB) openStorageMPTrie(stateRoot common.Hash, address common.Address, root common.Hash, _ Trie) (Trie, error) {
	tr, err := trie.NewStateTrie(trie.StorageTrieID(stateRoot, crypto.Keccak256Hash(address.Bytes()), root), db.triedb)
	if err != nil {
		return nil, err
	}
	return tr, nil
}

// OpenStorageTrie opens the storage trie of an account
func (db *cachingDB) OpenStorageTrie(stateRoot common.Hash, address common.Address, root common.Hash, self Trie) (Trie, error) {
	// TODO this should only return a verkle tree
	if db.Transitioned() {
		mpt, err := db.openStorageMPTrie(types.EmptyRootHash, address, common.Hash{}, self)
		if err != nil {
			return nil, err
		}
		// Return a "storage trie" that is an adapter between the storge MPT
		// and the unique verkle tree.
		switch self := self.(type) {
		case *trie.VerkleTrie:
			return trie.NewTransitionTree(mpt.(*trie.StateTrie), self, true), nil
		case *trie.TransitionTrie:
			return trie.NewTransitionTree(mpt.(*trie.StateTrie), self.Overlay(), true), nil
		default:
			panic("unexpected trie type")
		}
	}
	if db.InTransition() {
		log.Info("OpenStorageTrie during transition", "state root", stateRoot, "root", root)
		mpt, err := db.openStorageMPTrie(db.baseRoot, address, root, nil)
		if err != nil {
			return nil, err
		}
		// Return a "storage trie" that is an adapter between the storge MPT
		// and the unique verkle tree.
		switch self := self.(type) {
		case *trie.VerkleTrie:
			return trie.NewTransitionTree(mpt.(*trie.SecureTrie), self, true), nil
		case *trie.TransitionTrie:
			return trie.NewTransitionTree(mpt.(*trie.SecureTrie), self.Overlay(), true), nil
		default:
			return nil, errors.New("expected a verkle account tree, and found another type")
		}
	}
	mpt, err := db.openStorageMPTrie(stateRoot, address, root, nil)
	return mpt, err
}

// CopyTrie returns an independent copy of the given trie.
func (db *cachingDB) CopyTrie(t Trie) Trie {
	switch t := t.(type) {
	case *trie.StateTrie:
		return t.Copy()
	case *trie.TransitionTrie:
		return t.Copy()
	case *trie.VerkleTrie:
		return t.Copy()
	default:
		panic(fmt.Errorf("unknown trie type %T", t))
	}
}

// ContractCode retrieves a particular contract's code.
func (db *cachingDB) ContractCode(address common.Address, codeHash common.Hash) ([]byte, error) {
	code, _ := db.codeCache.Get(codeHash)
	if len(code) > 0 {
		return code, nil
	}
	code = rawdb.ReadCode(db.disk, codeHash)
	if len(code) > 0 {
		db.codeCache.Add(codeHash, code)
		db.codeSizeCache.Add(codeHash, len(code))
		return code, nil
	}
	return nil, errors.New("not found")
}

// ContractCodeWithPrefix retrieves a particular contract's code. If the
// code can't be found in the cache, then check the existence with **new**
// db scheme.
func (db *cachingDB) ContractCodeWithPrefix(address common.Address, codeHash common.Hash) ([]byte, error) {
	code, _ := db.codeCache.Get(codeHash)
	if len(code) > 0 {
		return code, nil
	}
	code = rawdb.ReadCodeWithPrefix(db.disk, codeHash)
	if len(code) > 0 {
		db.codeCache.Add(codeHash, code)
		db.codeSizeCache.Add(codeHash, len(code))
		return code, nil
	}
	return nil, errors.New("not found")
}

// ContractCodeSize retrieves a particular contracts code's size.
func (db *cachingDB) ContractCodeSize(addr common.Address, codeHash common.Hash) (int, error) {
	if cached, ok := db.codeSizeCache.Get(codeHash); ok {
		return cached, nil
	}
	code, err := db.ContractCode(addr, codeHash)
	return len(code), err
}

// DiskDB returns the underlying key-value disk database.
func (db *cachingDB) DiskDB() ethdb.KeyValueStore {
	return db.disk
}

// TrieDB retrieves any intermediate trie-node caching layer.
func (db *cachingDB) TrieDB() *trie.Database {
	return db.triedb
}

func (db *cachingDB) GetTreeKeyHeader(addr []byte) *verkle.Point {
	return db.addrToPoint.GetTreeKeyHeader(addr)
}

func (db *cachingDB) SetCurrentAccountAddress(addr common.Address) {
	db.CurrentTransitionState.CurrentAccountAddress = &addr
}

func (db *cachingDB) GetCurrentAccountHash() common.Hash {
	var addrHash common.Hash
	if db.CurrentTransitionState.CurrentAccountAddress != nil {
		addrHash = crypto.Keccak256Hash(db.CurrentTransitionState.CurrentAccountAddress[:])
	}
	return addrHash
}

func (db *cachingDB) GetCurrentAccountAddress() *common.Address {
	return db.CurrentTransitionState.CurrentAccountAddress
}

func (db *cachingDB) GetCurrentPreimageOffset() int64 {
	return db.CurrentTransitionState.CurrentPreimageOffset
}

func (db *cachingDB) SetCurrentPreimageOffset(offset int64) {
	db.CurrentTransitionState.CurrentPreimageOffset = offset
}

func (db *cachingDB) SetCurrentSlotHash(hash common.Hash) {
	db.CurrentTransitionState.CurrentSlotHash = hash
}

func (db *cachingDB) GetCurrentSlotHash() common.Hash {
	return db.CurrentTransitionState.CurrentSlotHash
}

func (db *cachingDB) SetStorageProcessed(processed bool) {
	db.CurrentTransitionState.StorageProcessed = processed
}

func (db *cachingDB) GetStorageProcessed() bool {
	return db.CurrentTransitionState.StorageProcessed
}

func (db *cachingDB) AddRootTranslation(originalRoot, translatedRoot common.Hash) {
}

func (db *cachingDB) SetLastMerkleRoot(merkleRoot common.Hash) {
	db.baseRoot = merkleRoot
}

func (db *cachingDB) SaveTransitionState(root common.Hash) {
	db.transitionStateLock.Lock()
	defer db.transitionStateLock.Unlock()
	if db.CurrentTransitionState != nil {
		var buf bytes.Buffer
		enc := gob.NewEncoder(&buf)
		err := enc.Encode(db.CurrentTransitionState)
		if err != nil {
			log.Error("failed to encode transition state", "err", err)
			return
		}

		if !db.TransitionStatePerRoot.Contains(root) {
			// Copy so that the address pointer isn't updated after
			// it has been saved.
			db.TransitionStatePerRoot.Add(root, db.CurrentTransitionState.Copy())

			rawdb.WriteVerkleTransitionState(db.DiskDB(), root, buf.Bytes())
		}

		log.Debug("saving transition state", "storage processed", db.CurrentTransitionState.StorageProcessed, "addr", db.CurrentTransitionState.CurrentAccountAddress, "slot hash", db.CurrentTransitionState.CurrentSlotHash, "root", root, "ended", db.CurrentTransitionState.Ended, "started", db.CurrentTransitionState.Started)
	}
}

func (db *cachingDB) LoadTransitionState(root common.Hash) {
	db.transitionStateLock.Lock()
	defer db.transitionStateLock.Unlock()
	// Try to get the transition state from the cache and
	// the DB if it's not there.
	ts, ok := db.TransitionStatePerRoot.Get(root)
	if !ok {
		// Not in the cache, try getting it from the DB
		data, err := rawdb.ReadVerkleTransitionState(db.DiskDB(), root)
		if err != nil {
			log.Error("failed to read transition state", "err", err)
			return
		}

		// if a state could be read from the db, attempt to decode it
		if len(data) > 0 {
			var (
				newts TransitionState
				buf   = bytes.NewBuffer(data[:])
				dec   = gob.NewDecoder(buf)
			)
			// Decode transition state
			err = dec.Decode(&newts)
			if err != nil {
				log.Error("failed to decode transition state", "err", err)
				return
			}
			ts = &newts
		}

		// Fallback that should only happen before the transition
		if ts == nil {
			// Initialize the first transition state, with the "ended"
			// field set to true if the database was created
			// as a verkle database.
			log.Debug("no transition state found, starting fresh", "is verkle", db.triedb.IsVerkle())
			// Start with a fresh state
			ts = &TransitionState{Ended: db.triedb.IsVerkle()}
		}
	}

	// Copy so that the CurrentAddress pointer in the map
	// doesn't get overwritten.
	db.CurrentTransitionState = ts.Copy()

	log.Debug("loaded transition state", "storage processed", db.CurrentTransitionState.StorageProcessed, "addr", db.CurrentTransitionState.CurrentAccountAddress, "slot hash", db.CurrentTransitionState.CurrentSlotHash, "root", root, "ended", db.CurrentTransitionState.Ended, "started", db.CurrentTransitionState.Started)
}

func (db *cachingDB) LockCurrentTransitionState() {
	db.transitionStateLock.Lock()
}

func (db *cachingDB) UnLockCurrentTransitionState() {
	db.transitionStateLock.Unlock()
}
