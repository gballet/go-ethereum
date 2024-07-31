// Copyright 2024 go-ethereum Authors
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

package trie

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-verkle"
	"golang.org/x/crypto/blake2b"
)

// BinaryNode represents any node in a binary trie.
type BinaryNode interface {
	Hash() []byte
	Get([]byte, verkle.NodeResolverFn) ([]byte, error)
	Insert([]byte, []byte, verkle.NodeResolverFn) error
}

type hashType int

// All known implementations of binaryNode
type (
	// branch is a node with two children ("left" and "right")
	// It can be prefixed by bits that are common to all subtrie
	// keys and it can also hold a value.
	branch struct {
		left  BinaryNode
		right BinaryNode
		depth int

		// key   []byte // TODO split into leaf and branch
		// value []byte

		// Used to send (hash, preimage) pairs when hashing
		// CommitCh chan BinaryHashPreimage

		// This is the binary equivalent of "extension nodes":
		// binary nodes can have a prefix that is common to all
		// subtrees.
		// stem []byte

		hasher hash.Hash
	}

	group struct {
		stem   []byte
		values [][]byte
		hasher hash.Hash
	}

	hashBinaryNode []byte

	empty struct{}
)

func (b *branch) getBit(stem []byte) bool {
	return stem[b.depth/8]&(1<<(7-b.depth%8)) == 0
}

func (b *branch) Hash() []byte {
	leftH := b.left.Hash()
	rightH := b.right.Hash()
	b.hasher.Reset()
	b.hasher.Write(leftH)
	b.hasher.Write(rightH)
	return b.hasher.Sum(nil)
}

func (b *branch) Get(key []byte, resolver verkle.NodeResolverFn) ([]byte, error) {
	if b.getBit(key) {
		return b.right.Get(key, resolver)
	}
	return b.left.Get(key, resolver)
}

func (b *branch) Insert(key, value []byte, resolver verkle.NodeResolverFn) error {
	var child BinaryNode
	if b.getBit(key) {
		child = b.left
	} else {
		child = b.right
	}

	switch child := child.(type) {
	case empty:
		childGroup := &group{
			stem:   key[:31],
			values: make([][]byte, 256),
			hasher: b.hasher,
		}
		childGroup.values[key[31]] = value
		child = childGroup
		return nil
	case hashBinaryNode:
		serialized, err := resolver()
		if err != nil {
			return err
		}
		// TODO parse node
		child = parsed
		return b.Insert(key, value, resolver)
	case *group:
		// compare stems
		if bytes.Equal(child.stem, key[:31]) {
			child.values[key[31]] = value
			return nil
		}

		// we need to split
		newsplit := &branch{
			depth:  b.depth + 1,
			hasher: b.hasher,
		}

		if newsplit.getBit(key) {
			newsplit.right = child
		} else {
			newsplit.left = right
		}
		child = newsplit
		return child.Insert(key, value, resolver)
	default:
		return child.Insert(key, value, resolver)
	}
}

func (g *group) Hash() []byte {
	var below [][]byte = g.values
	var list [][]byte
	for i := 7; i >= 0; i++ {
		list = make([][]byte, 1<<i)
		for j := 0; j < (1 << (i + 1)); j++ {
			if j%2 == 0 {
				g.hasher.Reset()
			} else {
				list[j/2] = g.hasher.Sum(below[j])
			}
		}
		below = list
	}
	g.hasher.Reset()
	g.hasher.Write(g.stem)
	return g.hasher.Sum(list[0])
}

func (g *group) Insert(key, value []byte, resolver verkle.NodeResolverFn) error {
	if !bytes.Equal(g.stem, key[:31]) {
		return errors.New("can not directly insert in group node")
	}

	g.values[key[31]] = value
	return nil
}

func (g *group) Get(key []byte, resolver verkle.NodeResolverFn) ([]byte, error) {
	if !bytes.Equal(g.stem, key[:31]) {
		return nil, nil
	}

	return g.values[key[31]], nil
}

// BinaryTrie represents a multi-level binary trie.
//
// Nodes with only one child are compacted into a "prefix"
// for the first node that has two children.
type BinaryTrie struct {
	root   BinaryNode
	store  *Database
	hasher hash.Hash
}

func NewBinaryTrie(root BinaryNode, db *Database, hasher hash.Hash) *BinaryTrie {
	return &BinaryTrie{root, db, hasher}
}

func NewBlake2sBinaryTree(root BinaryNode, db *Database) *BinaryTrie {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return NewBinaryTrie(root, db, hasher)
}

func NewSha256BinaryTree(root BinaryNode, db *Database) *BinaryTrie {
	return NewBinaryTrie(root, db, sha256.New())
}

var (
	FlatDBBinaryNodeKeyPrefix = []byte("flat-binary-") // prefix for flatdb keys
)

func (t *BinaryTrie) FlatdbNodeResolver(path []byte) ([]byte, error) {
	return t.store.diskdb.Get(append(FlatDBVerkleNodeKeyPrefix, path...))
}

func (t *BinaryTrie) UpdateAccount(addr common.Address, acc *types.StateAccount) error {
	var (
		err            error
		nonce, balance [32]byte
		values         = make([][]byte, verkle.NodeWidth)
		stem           = TODO
	)

	// Only evaluate the polynomial once
	values[utils.VersionLeafKey] = zero[:]
	values[utils.NonceLeafKey] = nonce[:]
	values[utils.BalanceLeafKey] = balance[:]
	values[utils.CodeHashLeafKey] = acc.CodeHash[:]

	binary.LittleEndian.PutUint64(nonce[:], acc.Nonce)
	bbytes := acc.Balance.Bytes()
	if len(bbytes) > 0 {
		for i, b := range bbytes {
			balance[len(bbytes)-i-1] = b
		}
	}

	switch root := t.root.(type) {
	case *branch:
		err = root.InsertValuesAtStem(stem, values, t.FlatdbNodeResolver)
	default:
		return errInvalidRootType
	}
	if err != nil {
		return fmt.Errorf("UpdateAccount (%x) error: %v", addr, err)
	}

	return nil
}

func (t *BinaryTrie) GetAccount(addr common.Address) (*types.StateAccount, error) {
	acc := &types.StateAccount{}
	versionkey := t.pointCache.GetTreeKeyVersionCached(addr[:])
	var (
		values [][]byte
		err    error
	)
	switch b := t.root.(type) {
	case *branch:
		values, err = b.GetValuesAtStem(versionkey[:31], t.FlatdbNodeResolver)
	default:
		return nil, errInvalidRootType
	}
	if err != nil {
		return nil, fmt.Errorf("GetAccount (%x) error: %v", addr, err)
	}

	// The following code is required for the MPT->VKT conversion.
	// An account can be partially migrated, where storage slots were moved to the VKT
	// but not yet the account. This means some account information as (header) storage slots
	// are in the VKT but basic account information must be read in the base tree (MPT).
	// TODO: we can simplify this logic depending if the conversion is in progress or finished.
	emptyAccount := true
	for i := 0; values != nil && i <= utils.CodeHashLeafKey && emptyAccount; i++ {
		emptyAccount = emptyAccount && values[i] == nil
	}
	if emptyAccount {
		return nil, nil
	}

	if len(values[utils.NonceLeafKey]) > 0 {
		acc.Nonce = binary.LittleEndian.Uint64(values[utils.NonceLeafKey])
	}
	// if the account has been deleted, then values[10] will be 0 and not nil. If it has
	// been recreated after that, then its code keccak will NOT be 0. So return `nil` if
	// the nonce, and values[10], and code keccak is 0.
	// if acc.Nonce == 0 && len(values) > 10 && len(values[10]) > 0 && bytes.Equal(values[utils.CodeHashLeafKey], zero[:]) {
	// 	if !t.ended {
	// 		return nil, errDeletedAccount
	// 	} else {
	// 		return nil, nil
	// 	}
	// }

	var balance [32]byte
	copy(balance[:], values[utils.BalanceLeafKey])
	for i := 0; i < len(balance)/2; i++ {
		balance[len(balance)-i-1], balance[i] = balance[i], balance[len(balance)-i-1]
	}
	// var balance [32]byte
	// if len(values[utils.BalanceLeafKey]) > 0 {
	// 	for i := 0; i < len(balance); i++ {
	// 		balance[len(balance)-i-1] = values[utils.BalanceLeafKey][i]
	// 	}
	// }
	acc.Balance = new(big.Int).SetBytes(balance[:])
	acc.CodeHash = values[utils.CodeHashLeafKey]
	// TODO fix the code size as well

	return acc, nil
}

func (trie *BinaryTrie) GetKey(key []byte) []byte {
	return key
}

func (trie *BinaryTrie) GetStorage(addr common.Address, key []byte) ([]byte, error) {
	pointEval := trie.pointCache.GetTreeKeyHeader(addr[:])
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(pointEval, key)
	return trie.root.Get(k, trie.FlatdbNodeResolver)
}
func (trie *BinaryTrie) UpdateStorage(address common.Address, key, value []byte) error {
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(trie.pointCache.GetTreeKeyHeader(address[:]), key)
	var v [32]byte
	if len(value) >= 32 {
		copy(v[:], value[:32])
	} else {
		copy(v[32-len(value):], value[:])
	}
	return trie.root.Insert(k, v[:], trie.FlatdbNodeResolver)
}

func (t *BinaryTrie) DeleteAccount(addr common.Address) error {
	return nil
}

// Delete removes any existing value for key from the trie. If a node was not
// found in the database, a trie.MissingNodeError is returned.
func (trie *BinaryTrie) DeleteStorage(addr common.Address, key []byte) error {
	pointEval := trie.pointCache.GetTreeKeyHeader(addr[:])
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(pointEval, key)
	var zero [32]byte
	return trie.root.Insert(k, zero[:], trie.FlatdbNodeResolver)
}

// Hash returns the root hash of the trie. It does not write to the database and
// can be used even if the trie doesn't have one.
func (trie *BinaryTrie) Hash() common.Hash {
	return trie.root.Commit().Bytes()
}

// Commit writes all nodes to the trie's memory database, tracking the internal
// and external (for account tries) references.
func (trie *BinaryTrie) Commit(_ bool) (common.Hash, *trienode.NodeSet, error) {
	root, ok := trie.root.(*branch)
	if !ok {
		return common.Hash{}, nil, errors.New("unexpected root node type")
	}
	nodes, err := root.BatchSerialize()
	if err != nil {
		return common.Hash{}, nil, fmt.Errorf("serializing tree nodes: %s", err)
	}

	batch := trie.db.diskdb.NewBatch()
	path := make([]byte, 0, len(FlatDBVerkleNodeKeyPrefix)+32)
	path = append(path, FlatDBVerkleNodeKeyPrefix...)
	for _, node := range nodes {
		path := append(path[:len(FlatDBVerkleNodeKeyPrefix)], node.Path...)

		if err := batch.Put(path, node.SerializedBytes); err != nil {
			return common.Hash{}, nil, fmt.Errorf("put node to disk: %s", err)
		}

		if batch.ValueSize() >= ethdb.IdealBatchSize {
			batch.Write()
			batch.Reset()
		}
	}
	batch.Write()

	return trie.Hash(), nil, nil
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration
// starts at the key after the given start key.
func (trie *BinaryTrie) NodeIterator(startKey []byte) (NodeIterator, error) {
	return newVerkleNodeIterator(trie, nil)
}

// Prove constructs a Merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root), ending
// with the node that proves the absence of the key.
func (trie *BinaryTrie) Prove(key []byte, proofDb ethdb.KeyValueWriter) error {
	panic("not implemented")
}

func (trie *BinaryTrie) Copy() *BinaryTrie {
	return &BinaryTrie{
		root:   trie.root.Copy(),
		store:  trie.store,
		hasher: trie.hasher,
	}
}

func (trie *BinaryTrie) IsVerkle() bool {
	return true
}

func (t *BinaryTrie) UpdateContractCode(addr common.Address, codeHash common.Hash, code []byte) error {
	var (
		chunks = ChunkifyCode(code)
		values [][]byte
		key    []byte
		err    error
	)
	for i, chunknr := 0, uint64(0); i < len(chunks); i, chunknr = i+32, chunknr+1 {
		groupOffset := (chunknr + 128) % 256
		if groupOffset == 0 /* start of new group */ || chunknr == 0 /* first chunk in header group */ {
			values = make([][]byte, verkle.NodeWidth)
			key = utils.GetTreeKeyCodeChunkWithEvaluatedAddress(t.pointCache.GetTreeKeyHeader(addr[:]), uint256.NewInt(chunknr))
		}
		values[groupOffset] = chunks[i : i+32]

		// Reuse the calculated key to also update the code size.
		if i == 0 {
			cs := make([]byte, 32)
			binary.LittleEndian.PutUint64(cs, uint64(len(code)))
			values[utils.CodeSizeLeafKey] = cs
		}

		if groupOffset == 255 || len(chunks)-i <= 32 {
			err = t.UpdateStem(key[:31], values)

			if err != nil {
				return fmt.Errorf("UpdateContractCode (addr=%x) error: %w", addr[:], err)
			}
		}
	}
	return nil
}
