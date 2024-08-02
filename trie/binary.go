// Copyright 2021 go-ethereum Authors
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
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

type (
	NodeResolverFn func([]byte) ([][]byte, error)

	BinaryNode interface {
		Get([]byte, NodeResolverFn) ([][]byte, error)
		Insert([]byte, [][]byte, NodeResolverFn) error
		Hash() []byte
	}

	// Represents an internal node, with an optional
	// extension.
	branch struct {
		depth       int
		extension   []byte
		left, right BinaryNode
	}

	// Represents a group of values at the bottom of the tree,
	// with their specific merkleization rules.
	group struct {
		depth  int
		stem   []byte
		values [][]byte
	}

	empty struct{}

	undefined struct{}

	hashed struct{}
)

const NValuesPerGroup = 256

func (empty) Get([]byte, NodeResolverFn) ([][]byte, error)      { panic("not implemented") }
func (empty) Insert([]byte, [][]byte, NodeResolverFn) error     { panic("not implemented") }
func (empty) Hash() []byte                                      { return zero[:] }
func (hashed) Get([]byte, NodeResolverFn) ([][]byte, error)     { panic("not implemented") }
func (hashed) Insert([]byte, [][]byte, NodeResolverFn) error    { panic("not implemented") }
func (hashed) Hash() []byte                                     { panic("not implemented") }
func (undefined) Get([]byte, NodeResolverFn) ([][]byte, error)  { panic("not implemented") }
func (undefined) Insert([]byte, [][]byte, NodeResolverFn) error { panic("not implemented") }
func (undefined) Hash() []byte                                  { panic("not implemented") }

func (b *branch) Get(key []byte, resolver NodeResolverFn) ([][]byte, error) {
	isRight := key[b.depth/8]&(1<<(b.depth%8)) != 0
	var child BinaryNode
	if isRight {
		child = b.right
	} else {
		child = b.left
	}

	switch child.(type) {
	case undefined:
		return nil, errors.New("missing node in stateless mode")
	case empty:
		return nil, nil
	case hashed:
		if resolver == nil {
			return nil, errors.New("could not resolve node")
		}
		serialized, err := resolver(key[:b.depth+1])
		if err != nil {
			return nil, fmt.Errorf("resolving node %x at depth %d: %w", key, b.depth, err)
		}
		resolved, err := ParseNode(serialized, b.depth+1)
		if err != nil {
			return nil, fmt.Errorf("verkle tree: error parsing resolved node %x: %w", key, err)
		}
		if isRight {
			b.right = resolved
		} else {
			b.left = resolved
		}
		// recurse to handle the case of a LeafNode child that
		// splits.
		return b.Get(key, resolver)
	case *branch, *group:
		return child.Get(key, resolver)
	default:
		return nil, errors.New("unknown node type")
	}
}

func split(a, b []byte) (int, bool) {
	for i := range a {
		for j := 7; j >= 0; j-- {
			a_byte := a[i]
			b_byte := b[i]
			a_bit := a_byte & (1 << j)
			b_bit := b_byte & (1 << j)
			if a_bit != b_bit {
				return i*8 + j, a_bit == 0
			}
		}
	}
	return 8 * len(a), false
}
func (b *branch) Insert(key []byte, values [][]byte, resolver NodeResolverFn) error {
	isRight := key[b.depth/8]&(1<<(b.depth%8)) != 0
	var child *BinaryNode
	if isRight {
		child = &b.right
	} else {
		child = &b.left
	}

	switch chld := (*child).(type) {
	case undefined:
		return errors.New("missing node in stateless mode")
	case empty:
		*child = &group{
			depth:  b.depth + 1,
			values: values,
			stem:   key[:31],
		}
		return nil
	case hashed:
		if resolver == nil {
			return errors.New("could not resolve node")
		}
		serialized, err := resolver(key[:b.depth+1])
		if err != nil {
			return fmt.Errorf("resolving node %x at depth %d: %w", key, b.depth, err)
		}
		resolved, err := ParseNode(serialized, b.depth+1)
		if err != nil {
			return fmt.Errorf("verkle tree: error parsing resolved node %x: %w", key, err)
		}
		if isRight {
			b.right = resolved
		} else {
			b.left = resolved
		}
		// recurse to handle the case of a LeafNode child that
		// splits.
		return b.Insert(key, values, resolver)
	case *group:
		splitIdx, isLeft := split(key, chld.stem)
		if splitIdx != 8*31 {
			newbr := &branch{
				depth:     b.depth + 1,
				extension: make([]byte, splitIdx),
			}
			if isLeft {
				newbr.left = &group{
					depth:  b.depth + 2,
					stem:   key[:31],
					values: values,
				}
				newbr.right = chld
			}
			*child = newbr
		}
		return b.Insert(key, values, resolver)
	case *branch:
		return nil
	default:
		panic("unknown node type")
	}
}

func (b *branch) Hash() []byte {

}

func (g *group) Get(key []byte, resolver NodeResolverFn) ([][]byte, error) {
	if bytes.Equal(key[:31], g.stem) {
		return g.values[:], nil
	}

	return nil, nil
}

func (g *group) Insert(key []byte, values [][]byte, _ NodeResolverFn) error {
	for i, val := range values {
		if val != nil {
			g.values[i] = val
		}
	}
	return nil
}

func (g *group) Hash() []byte {}

// BinaryTrie is a wrapper around BinaryNode that implements the trie.Trie
// interface so that Binary trees can be reused verbatim.
type BinaryTrie struct {
	root       *branch
	db         *Database
	pointCache *utils.PointCache
	ended      bool
}

func (vt *BinaryTrie) ToDot() string {
	return ToDot(vt.root)
}

func NewBinaryTrie(root BinaryNode, db *Database, pointCache *utils.PointCache, ended bool) *BinaryTrie {
	return &BinaryTrie{
		root:       root,
		db:         db,
		pointCache: pointCache,
		ended:      ended,
	}
}

func (trie *BinaryTrie) FlatdbNodeResolver(path []byte) ([]byte, error) {
	return trie.db.diskdb.Get(append(FlatDBBinaryNodeKeyPrefix, path...))
}

func (trie *BinaryTrie) InsertMigratedLeaves(leaves []LeafNode) error {
	return trie.root.InsertMigratedLeaves(leaves, trie.FlatdbNodeResolver)
}

var (
	FlatDBBinaryNodeKeyPrefix = []byte("binary-") // prefix for flatdb keys
)

// GetKey returns the sha3 preimage of a hashed key that was previously used
// to store a value.
func (trie *BinaryTrie) GetKey(key []byte) []byte {
	return key
}

// Get returns the value for key stored in the trie. The value bytes must
// not be modified by the caller. If a node was not found in the database, a
// trie.MissingNodeError is returned.
func (trie *BinaryTrie) GetStorage(addr common.Address, key []byte) ([]byte, error) {
	pointEval := trie.pointCache.GetTreeKeyHeader(addr[:])
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(pointEval, key)
	return trie.root.Get(k, trie.FlatdbNodeResolver)
}

// GetWithHashedKey returns the value, assuming that the key has already
// been hashed.
func (trie *BinaryTrie) GetWithHashedKey(key []byte) ([]byte, error) {
	return trie.root.Get(key, trie.FlatdbNodeResolver)
}

func (t *BinaryTrie) GetAccount(addr common.Address) (*types.StateAccount, error) {
	acc := &types.StateAccount{}
	versionkey := t.pointCache.GetTreeKeyVersionCached(addr[:])
	var (
		values [][]byte
		err    error
	)
	switch t.root.(type) {
	case *branch:
		values, err = t.root.(*branch).GetValuesAtStem(versionkey[:31], t.FlatdbNodeResolver)
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

	if acc.Nonce == 0 && len(values) > 10 && len(values[10]) > 0 && bytes.Equal(values[utils.CodeHashLeafKey], zero[:]) {
		if !t.ended {
			return nil, errDeletedAccount
		} else {
			return nil, nil
		}
	}
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

var zero [32]byte

func (t *BinaryTrie) UpdateAccount(addr common.Address, acc *types.StateAccount) error {
	var (
		err            error
		nonce, balance [32]byte
		values         = make([][]byte, NValuesPerGroup)
		stem           = t.pointCache.GetTreeKeyVersionCached(addr[:])
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
	// TODO figure out if the code size needs to be updated, too

	return nil
}

func (trie *BinaryTrie) UpdateStem(key []byte, values [][]byte) error {
	switch root := trie.root.(type) {
	case *branch:
		return root.InsertValuesAtStem(key, values, trie.FlatdbNodeResolver)
	default:
		panic("invalid root type")
	}
}

// Update associates key with value in the trie. If value has length zero, any
// existing value is deleted from the trie. The value bytes must not be modified
// by the caller while they are stored in the trie. If a node was not found in the
// database, a trie.MissingNodeError is returned.
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
	path := make([]byte, 0, len(FlatDBBinaryNodeKeyPrefix)+32)
	path = append(path, FlatDBBinaryNodeKeyPrefix...)
	for _, node := range nodes {
		path := append(path[:len(FlatDBBinaryNodeKeyPrefix)], node.Path...)

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
	return newBinaryNodeIterator(trie, nil)
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
		root:       trie.root.Copy(),
		db:         trie.db,
		pointCache: trie.pointCache,
	}
}

func (trie *BinaryTrie) IsBinary() bool {
	return true
}

func ProveAndSerialize(pretrie, posttrie *BinaryTrie, keys [][]byte, resolver NodeResolverFn) (*BinaryProof, StateDiff, error) {
	var postroot BinaryNode
	if posttrie != nil {
		postroot = posttrie.root
	}
	proof, _, _, _, err := MakeBinaryMultiProof(pretrie.root, postroot, keys, resolver)
	if err != nil {
		return nil, nil, err
	}

	p, kvps, err := SerializeProof(proof)
	if err != nil {
		return nil, nil, err
	}

	return p, kvps, nil
}

func DeserializeAndVerifyBinaryProof(vp *BinaryProof, preStateRoot []byte, postStateRoot []byte, statediff StateDiff) error {
	// TODO: check that `OtherStems` have expected length and values.

	proof, err := DeserializeProof(vp, statediff)
	if err != nil {
		return fmt.Errorf("proof deserialization error: %w", err)
	}

	rootC := new(Point)
	rootC.SetBytes(preStateRoot)
	pretree, err := PreStateTreeFromProof(proof, rootC)
	if err != nil {
		return fmt.Errorf("error rebuilding the pre-tree from proof: %w", err)
	}
	// TODO this should not be necessary, remove it
	// after the new proof generation code has stabilized.
	for _, stemdiff := range statediff {
		for _, suffixdiff := range stemdiff.SuffixDiffs {
			var key [32]byte
			copy(key[:31], stemdiff.Stem[:])
			key[31] = suffixdiff.Suffix

			val, err := pretree.Get(key[:], nil)
			if err != nil {
				return fmt.Errorf("could not find key %x in tree rebuilt from proof: %w", key, err)
			}
			if len(val) > 0 {
				if !bytes.Equal(val, suffixdiff.CurrentValue[:]) {
					return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, *suffixdiff.CurrentValue)
				}
			} else {
				if suffixdiff.CurrentValue != nil && len(suffixdiff.CurrentValue) != 0 {
					return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, *suffixdiff.CurrentValue)
				}
			}
		}
	}

	// TODO: this is necessary to verify that the post-values are the correct ones.
	// But all this can be avoided with a even faster way. The EVM block execution can
	// keep track of the written keys, and compare that list with this post-values list.
	// This can avoid regenerating the post-tree which is somewhat expensive.
	posttree, err := PostStateTreeFromStateDiff(pretree, statediff)
	if err != nil {
		return fmt.Errorf("error rebuilding the post-tree from proof: %w", err)
	}
	regeneratedPostTreeRoot := posttree.Commitment().Bytes()
	if !bytes.Equal(regeneratedPostTreeRoot[:], postStateRoot) {
		return fmt.Errorf("post tree root mismatch: %x != %x", regeneratedPostTreeRoot, postStateRoot)
	}

	return VerifyBinaryProofWithPreState(proof, pretree)
}

// ChunkedCode represents a sequence of 32-bytes chunks of code (31 bytes of which
// are actual code, and 1 byte is the pushdata offset).
type ChunkedCode []byte

// Copy the values here so as to avoid an import cycle
const (
	PUSH1  = byte(0x60)
	PUSH3  = byte(0x62)
	PUSH4  = byte(0x63)
	PUSH7  = byte(0x66)
	PUSH21 = byte(0x74)
	PUSH30 = byte(0x7d)
	PUSH32 = byte(0x7f)
)

// ChunkifyCode generates the chunked version of an array representing EVM bytecode
func ChunkifyCode(code []byte) ChunkedCode {
	var (
		chunkOffset = 0 // offset in the chunk
		chunkCount  = len(code) / 31
		codeOffset  = 0 // offset in the code
	)
	if len(code)%31 != 0 {
		chunkCount++
	}
	chunks := make([]byte, chunkCount*32)
	for i := 0; i < chunkCount; i++ {
		// number of bytes to copy, 31 unless
		// the end of the code has been reached.
		end := 31 * (i + 1)
		if len(code) < end {
			end = len(code)
		}

		// Copy the code itself
		copy(chunks[i*32+1:], code[31*i:end])

		// chunk offset = taken from the
		// last chunk.
		if chunkOffset > 31 {
			// skip offset calculation if push
			// data covers the whole chunk
			chunks[i*32] = 31
			chunkOffset = 1
			continue
		}
		chunks[32*i] = byte(chunkOffset)
		chunkOffset = 0

		// Check each instruction and update the offset
		// it should be 0 unless a PUSHn overflows.
		for ; codeOffset < end; codeOffset++ {
			if code[codeOffset] >= PUSH1 && code[codeOffset] <= PUSH32 {
				codeOffset += int(code[codeOffset] - PUSH1 + 1)
				if codeOffset+1 >= 31*(i+1) {
					codeOffset++
					chunkOffset = codeOffset - 31*(i+1)
					break
				}
			}
		}
	}

	return chunks
}

func (t *BinaryTrie) SetStorageRootConversion(addr common.Address, root common.Hash) {
	t.db.SetStorageRootConversion(addr, root)
}

func (t *BinaryTrie) ClearStrorageRootConversion(addr common.Address) {
	t.db.ClearStorageRootConversion(addr)
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
			values = make([][]byte, NValuesPerGroup)
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
