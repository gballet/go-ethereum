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
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie/trienode"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/ethereum/go-verkle"
	"github.com/holiman/uint256"
)

type BinaryNode struct {
	// extensions are coded by nodes that have only one child, but they
	// are not saved in the db.
	left, right *BinaryNode
	values      [][]byte
	stem        []byte
	depth       byte
	hash        *common.Hash // hash is non-nil if the node needs to be resolved
}

func bit(depth byte, key []byte) bool {
	return key[depth/8]&(1<<(7-(depth%8))) != 0
}

func (node *BinaryNode) isLeaf() bool {
	return node.depth == 248
}

func (node *BinaryNode) Get(key []byte, resolver verkle.NodeResolverFn) ([]byte, error) {
	values, err := node.GetValuesAtStem(key, resolver)
	if err != nil || values == nil {
		return nil, err
	}
	return values[key[31]], nil
}

func (node *BinaryNode) GetValuesAtStem(key []byte, resolver verkle.NodeResolverFn) ([][]byte, error) {
	if node.isLeaf() {
		return node.values, nil
	}

	var child *BinaryNode
	if bit(node.depth, key) {
		child = node.right
	} else {
		child = node.left
	}

	if child == nil {
		return nil, nil
	}
	if child.hash != nil {
		err := child.resolve(key, resolver)
		if err != nil {
			return nil, err
		}
	}
	return child.GetValuesAtStem(key, resolver)
}

func keyToPath(key []byte, depth byte) []byte {
	path := make([]byte, 1+(depth+7)/8)
	copy(path[:len(path)-1], key)
	path[len(path)-2] &= ^((1 << (8 - (depth % 8))) - 1) // clear the deeper bits
	path[len(path)-1] = depth
	return path
}

func (node *BinaryNode) resolve(key []byte, resolver verkle.NodeResolverFn) error {

	path := keyToPath(key, node.depth)
	serialized, err := resolver(path)
	if err != nil {
		panic(fmt.Sprintf("error getting serialized node %x, depth=%d: %w", path, node.depth, err))
	}
	parsed, err := ParseNode(serialized, node.depth, path)
	if err != nil {
		return err
	}
	node.hash = nil
	node.left = parsed.left
	node.right = parsed.right
	node.stem = parsed.stem
	node.values = parsed.values
	node.depth = parsed.depth
	return nil
}

func (node *BinaryNode) InsertValuesAtStem(key []byte, values [][]byte, resolver verkle.NodeResolverFn, traversalDepth byte) error {
	// clear out the hash, as it needs to be recomputed
	node.hash = nil

	if node.isLeaf() {
		// create as many intermediate nodes if the values disagree
		if !bytes.Equal(key[:31], node.stem[:]) {
			// create the leaf node that is displaced
			old := &BinaryNode{
				stem:   node.stem,
				depth:  248,
				values: node.values,
			}
			// convert current leaf node to a branch node
			node.stem = nil
			node.values = nil
			node.depth = traversalDepth

			if bit(node.depth, node.stem) {
				node.right = old
			} else {
				node.left = old
			}

			// if this is not where the fork happens, recurse
			if bit(node.depth, node.stem) == bit(node.depth, key) {
				return old.InsertValuesAtStem(key, values, resolver, node.depth+1)
			}

			if bit(node.depth, key) {
				node.right = &BinaryNode{
					stem:   key[:31],
					depth:  248,
					values: values,
				}
			} else {
				node.left = &BinaryNode{
					stem:   key[:31],
					depth:  248,
					values: values,
				}
			}
		}

		if node.stem == nil {
			node.stem = key[:31]
		}
		for i := range values {
			if values[i] != nil {
				node.values[i] = values[i]
			}
		}

		return nil
	}

	var child **BinaryNode
	if bit(node.depth, key) {
		child = &node.right
	} else {
		child = &node.left
	}

	// first case: missing right node: simply insert a new leaf
	if *child == nil {
		*child = &BinaryNode{
			depth:  node.depth + 1,
			stem:   key[:31],
			values: values,
		}
		return nil
	}

	// second case: a hashed node. Resolve and recurse.
	if (*child).hash != nil {
		err := node.right.resolve(key, resolver)
		if err != nil {
			return err
		}
	}

	return (*child).InsertValuesAtStem(key, values, resolver, node.depth+1)
}

func (node *BinaryNode) Hash() common.Hash {
	// if the node has already been hashed, return the cached value
	if node.hash != nil {
		return *node.hash
	}
	if node.isLeaf() {

	}
	hasher := sha256.New()
	if node.left != nil {
		hasher.Write(node.left.Hash().Bytes())
	} else {
		hasher.Write(zero[:])
	}
	if node.right != nil {
		hasher.Write(node.right.Hash().Bytes())
	} else {
		hasher.Write(zero[:])
	}
	return common.Hash(hasher.Sum(nil))
}

func (node *BinaryNode) Insert(key []byte, value []byte, resolver verkle.NodeResolverFn) error {
	values := make([][]byte, verkle.NodeWidth)
	values[key[31]] = value
	return node.InsertValuesAtStem(key, values, resolver, 0)
}

func (node *BinaryNode) Copy() *BinaryNode {
	if node.isLeaf() {
		newvalues := make([][]byte, verkle.NodeWidth)
		return &BinaryNode{
			values: newvalues,
			depth:  248,
			stem:   node.stem,
			hash:   node.hash,
		}
	}

	var leftChild, rightChild *BinaryNode
	if node.left != nil {
		leftChild = node.left.Copy()
	}
	if node.right != nil {
		rightChild = node.right.Copy()
	}
	return &BinaryNode{
		left:  leftChild,
		right: rightChild,
		depth: node.depth,
		hash:  node.hash,
	}
}

type internalEncode struct {
	Depth byte   `rlp:""`
	Ext   []byte `rlp:""`

	// we know if the node has two children. It can be
	// Left and right hash have to be stored, so that
	// skipped, I guess, if we make a db read when we
	// recompute the hash, but it seems faster to store
	// them here.
	Left  common.Hash `rlp:""`
	Right common.Hash `rlp:""`
}

type leafEncode struct {
	stem   []byte
	values [][]byte
	// No hash for leaf nodes as it's stored in the parent
	// hash   common.Hash
}

func ParseNode(serialized []byte, parentDepth byte, path []byte) (*BinaryNode, error) {
	child := &BinaryNode{}
	var leaf leafEncode
	var internal internalEncode
	err := rlp.DecodeBytes(serialized, &leaf)
	if err != nil {

		err := rlp.DecodeBytes(serialized, &internal)
		if err != nil {
			return nil, fmt.Errorf("error decoding serialized rlp: %w", err)
		}
		if internal.Left != (common.Hash{}) {
			child.left = &BinaryNode{depth: child.depth + 1, hash: &internal.Left}
		}
		if internal.Right != (common.Hash{}) {
			child.right = &BinaryNode{depth: child.depth + 1, hash: &internal.Right}
		}
	} else {
		child.stem = leaf.stem
		child.depth = 248
		child.values = leaf.values
	}

	// if there is a gap between the child's depth and the parent's depth
	// insert intermediate nodes with a single child. This is only if the
	// child isn't a leaf node, though.
	if !child.isLeaf() && len(internal.Ext) > 1 {
		count := 8*(len(internal.Ext)-1) + int(internal.Ext[len(internal.Ext)-1])
		for i := count - 1; i > 0; i-- {
			temp := &BinaryNode{
				depth: child.depth - 1,
			}
			if bit(byte(i), internal.Ext) {
				temp.left = child
			} else {
				temp.right = child
			}
			child = temp
		}
	}
	return child, nil
}

func (node *BinaryNode) Commit(path []byte, batch ethdb.Batch) error {
	if len(path) == 0 {
		fmt.Println("la")
	}
	if !node.isLeaf() {
		if node.depth == 1 {
			fmt.Println("ici")
		}
		// compress single-children nodes
		var child = node
		var ext [32]byte
		var d int

		for (child.left == nil && child.right != nil) || (child.left != nil && child.right == nil) {
			if child.left == nil {
				ext[d/8] |= (1 << (7 - (d % 8)))
				child = child.right
			} else {
				child = child.left
			}

			d += 1
		}
		extsize := (d+7)/8 + 1
		ext[extsize-1] = byte(d % 8)

		childPathSize := len(path)
		if node.depth%8 == 0 {
			// new byte will be 0, which is what we want
			childPathSize += 1
		}
		childPath := make([]byte, childPathSize)
		copy(childPath, path[:len(path)-1])
		// node.depth + 1 because the path depth can be
		// different from the child's depth.
		childPath[childPathSize-1] = (node.depth + 1) % 8

		// recurse into left child
		var leftHash common.Hash
		if child.left != nil {
			err := child.left.Commit(childPath, batch)
			if err != nil {
				panic(err)
			}
			leftHash = child.left.Hash()
			child.left.hash = &leftHash
			child.left.left = nil
			child.left.right = nil
			child.left.values = nil
			child.left.stem = nil
		}

		// recurse into right child + set the bit in the path
		var rightHash common.Hash
		if child.right != nil {
			childPath[childPathSize-2] |= (1 << (7 - (node.depth % 8)))
			err := child.right.Commit(childPath, batch)
			if err != nil {
				panic(err)
			}
			rightHash = child.right.Hash()
			child.right.hash = &rightHash
			child.right.left = nil
			child.right.right = nil
			child.right.values = nil
			child.right.stem = nil
		}

		// only store the first node that has two children.
		saved, err := rlp.EncodeToBytes(&internalEncode{node.depth, ext[:extsize], leftHash, rightHash})
		if err != nil {
			panic(err)
		}
		storagekey := make([]byte, 0, len("flat-")+len(path))
		storagekey = append([]byte("flat-"), path...)
		err = batch.Put(storagekey, saved)
		if err != nil {
			panic(err)
		}
		if batch.ValueSize() >= ethdb.IdealBatchSize {
			batch.Write()
			batch.Reset()
		}
		return nil
	}

	saved, err := rlp.EncodeToBytes(&leafEncode{node.stem, node.values})
	if err != nil {
		panic(err)
	}
	err = batch.Put(path, saved)
	if err != nil {
		panic(err)
	}
	if batch.ValueSize() >= ethdb.IdealBatchSize {
		batch.Write()
		batch.Reset()
	}
	return nil
}

// BinaryTrie is a wrapper around VerkleNode that implements the trie.Trie
// interface so that Verkle trees can be reused verbatim.
type BinaryTrie struct {
	root       *BinaryNode
	db         *Database
	pointCache *utils.PointCache
	ended      bool
}

func (vt *BinaryTrie) ToDot() string {
	// panic("not implemented")
	return ""
}

func NewVerkleTrie(root *BinaryNode, db *Database, pointCache *utils.PointCache, ended bool) *BinaryTrie {
	return &BinaryTrie{
		root:       root,
		db:         db,
		pointCache: pointCache,
		ended:      ended,
	}
}

func (trie *BinaryTrie) FlatdbNodeResolver(path []byte) ([]byte, error) {
	return trie.db.diskdb.Get(append(FlatDBVerkleNodeKeyPrefix, path...))
}

var (
	errInvalidRootType = errors.New("invalid node type for root")

	// WORKAROUND: this special error is returned if it has been
	// detected that the account was deleted in the verkle tree.
	// This is needed in case an account was translated while it
	// was in the MPT, and was selfdestructed in verkle mode.
	//
	// This is only a problem for replays, and this code is not
	// needed after SELFDESTRUCT has been removed.
	errDeletedAccount = errors.New("account deleted in VKT")

	FlatDBVerkleNodeKeyPrefix = []byte("flat-") // prefix for flatdb keys
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
	ref, err := hexutil.Decode("0x99d31ed3cba27c34938b7da489d139c2aff74711d2c20d2ff8a879498703d805")
	if err != nil {
		panic(err)
	}
	pointEval := trie.pointCache.GetTreeKeyHeader(addr[:])
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(pointEval, key)
	prout, err := trie.root.Get(k, trie.FlatdbNodeResolver)
	if bytes.Equal(key[:], ref[:]) {
		fmt.Printf("get addr=%x slot=%x value=%s\n", addr, key, prout)
		// panic("get")
	}
	return prout, err
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
	values, err = t.root.GetValuesAtStem(versionkey[:31], t.FlatdbNodeResolver)
	if err != nil {
		return nil, fmt.Errorf("GetAccount (%x) error: %v", addr, err)
	}

	emptyAccount := true
	for i := 0; values != nil && i <= utils.CodeHashLeafKey && emptyAccount; i++ {
		emptyAccount = emptyAccount && values[i] == nil
	}
	if emptyAccount {
		return nil, nil
	}

	if len(values[utils.BasicDataLeafKey]) > 0 {
		acc.Nonce = binary.BigEndian.Uint64(values[utils.BasicDataLeafKey][utils.BasicDataNonceOffset:])
	}
	// if the account has been deleted, then values[10] will be 0 and not nil. If it has
	// been recreated after that, then its code keccak will NOT be 0. So return `nil` if
	// the nonce, and values[10], and code keccak is 0.

	// XXX voir si effectivement de detruis tout
	if bytes.Equal(values[utils.BasicDataLeafKey], zero[:]) && len(values) > 10 && len(values[10]) > 0 && bytes.Equal(values[utils.CodeHashLeafKey], zero[:]) {
		if !t.ended {
			return nil, errDeletedAccount
		} else {
			return nil, nil
		}
	}
	var balance [16]byte
	copy(balance[:], values[utils.BasicDataLeafKey][utils.BasicDataBalanceOffset:])
	acc.Balance = new(big.Int).SetBytes(balance[:])
	acc.CodeHash = values[utils.CodeHashLeafKey]

	return acc, nil
}

var zero [32]byte

func (t *BinaryTrie) UpdateAccount(addr common.Address, acc *types.StateAccount, codelen int) error {
	var (
		err       error
		basicData [32]byte
		values    = make([][]byte, verkle.NodeWidth)
		stem      = t.pointCache.GetTreeKeyVersionCached(addr[:])
	)

	binary.BigEndian.PutUint32(basicData[utils.BasicDataCodeSizeOffset:], uint32(codelen))
	binary.BigEndian.PutUint64(basicData[utils.BasicDataNonceOffset:], acc.Nonce)
	// get the lower 16 bytes of water and change its endianness
	balanceBytes := acc.Balance.Bytes()
	copy(basicData[32-len(balanceBytes):], balanceBytes[:])
	// XXX overwrite code size if present and not updated
	// this will happen e.g. when updating the balance
	values[utils.BasicDataLeafKey] = basicData[:]
	values[utils.CodeHashLeafKey] = acc.CodeHash[:]

	err = t.root.InsertValuesAtStem(stem, values, t.FlatdbNodeResolver, 0)
	if err != nil {
		return fmt.Errorf("UpdateAccount (%x) error: %v", addr, err)
	}

	return nil
}

func (trie *BinaryTrie) UpdateStem(key []byte, values [][]byte) error {
	return trie.root.InsertValuesAtStem(key, values, trie.FlatdbNodeResolver, 0)
}

// Update associates key with value in the trie. If value has length zero, any
// existing value is deleted from the trie. The value bytes must not be modified
// by the caller while they are stored in the trie. If a node was not found in the
// database, a trie.MissingNodeError is returned.
func (trie *BinaryTrie) UpdateStorage(address common.Address, key, value []byte) error {
	ref, err := hexutil.Decode("0x99d31ed3cba27c34938b7da489d139c2aff74711d2c20d2ff8a879498703d805")
	if err != nil {
		panic(err)
	}
	if bytes.Equal(key[:], ref[:]) {
		fmt.Printf("update addr=%x slot=%x value=%x\n", address, key, value)
	}
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
	var (
		values = make([][]byte, verkle.NodeWidth)
		stem   = t.pointCache.GetTreeKeyVersionCached(addr[:])
	)

	for i := 0; i < verkle.NodeWidth; i++ {
		values[i] = zero[:]
	}
	return t.root.InsertValuesAtStem(stem, values, t.FlatdbNodeResolver, 0)
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
	return trie.root.Hash()
}

func nodeToDBKey(n verkle.VerkleNode) []byte {
	ret := n.Commitment().Bytes()
	return ret[:]
}

// Commit writes all nodes to the trie's memory database, tracking the internal
// and external (for account tries) references.
func (trie *BinaryTrie) Commit(_ bool) (common.Hash, *trienode.NodeSet, error) {
	batch := trie.db.diskdb.NewBatch()
	err := trie.root.Commit([]byte{0}, batch)
	if err != nil {
		return common.Hash{}, nil, fmt.Errorf("serializing tree nodes: %s", err)
	}

	path := make([]byte, 0, len(FlatDBVerkleNodeKeyPrefix)+32)
	path = append(path, FlatDBVerkleNodeKeyPrefix...)
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
		root:       trie.root.Copy(),
		db:         trie.db,
		pointCache: trie.pointCache,
	}
}

func (trie *BinaryTrie) IsVerkle() bool {
	return true
}

// func ProveAndSerialize(pretrie, posttrie *VerkleTrie, keys [][]byte, resolver verkle.NodeResolverFn) (*verkle.VerkleProof, verkle.StateDiff, error) {
// 	var postroot verkle.VerkleNode
// 	if posttrie != nil {
// 		postroot = posttrie.root
// 	}
// 	proof, _, _, _, err := verkle.MakeVerkleMultiProof(pretrie.root, postroot, keys, resolver)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	p, kvps, err := verkle.SerializeProof(proof)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	return p, kvps, nil
// }

// func DeserializeAndVerifyVerkleProof(vp *verkle.VerkleProof, preStateRoot []byte, postStateRoot []byte, statediff verkle.StateDiff) error {
// 	panic("pas appele j'espere")
// 	// TODO: check that `OtherStems` have expected length and values.

// 	proof, err := verkle.DeserializeProof(vp, statediff)
// 	if err != nil {
// 		return fmt.Errorf("verkle proof deserialization error: %w", err)
// 	}

// 	rootC := new(verkle.Point)
// 	rootC.SetBytes(preStateRoot)
// 	pretree, err := verkle.PreStateTreeFromProof(proof, rootC)
// 	if err != nil {
// 		return fmt.Errorf("error rebuilding the pre-tree from proof: %w", err)
// 	}
// 	// TODO this should not be necessary, remove it
// 	// after the new proof generation code has stabilized.
// 	// for _, stemdiff := range statediff {
// 	// method 1
// 	// for i, suffix := range stemdiff.Suffixes {
// 	// 	var key [32]byte
// 	// 	copy(key[:31], stemdiff.Stem[:])
// 	// 	key[31] = suffix

// 	// 	val, err := pretree.Get(key[:], nil)
// 	// 	if err != nil {
// 	// 		return fmt.Errorf("could not find key %x in tree rebuilt from proof: %w", key, err)
// 	// 	}
// 	// 	if len(val) > 0 {
// 	// 		if !bytes.Equal(val, stemdiff.Current[i]) {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.Current[i])
// 	// 		}
// 	// 	} else {
// 	// 		if stemdiff.Current[i] != nil && len(stemdiff.Current[i]) != 0 {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.Current[i])
// 	// 		}
// 	// 	}
// 	// }

// 	// method 2
// 	// for i, suffix := range stemdiff.ReadSuffixes {
// 	// 	var key [32]byte
// 	// 	copy(key[:31], stemdiff.Stem[:])
// 	// 	key[31] = suffix
// 	// 	val, err := pretree.Get(key[:], nil)
// 	// 	if err != nil {
// 	// 		return fmt.Errorf("could not find key %x in tree rebuilt from proof: %w", key, err)
// 	// 	}
// 	// 	if len(val) > 0 {
// 	// 		if !bytes.Equal(val, stemdiff.ReadCurrent[i]) {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.ReadCurrent[i])
// 	// 		}
// 	// 	} else {
// 	// 		if stemdiff.ReadCurrent[i] != nil && len(stemdiff.ReadCurrent[i]) != 0 {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.ReadCurrent[i])
// 	// 		}
// 	// 	}
// 	// }
// 	// for i, suffix := range stemdiff.UpdatedSuffixes {
// 	// 	var key [32]byte
// 	// 	copy(key[:31], stemdiff.Stem[:])
// 	// 	key[31] = suffix
// 	// 	val, err := pretree.Get(key[:], nil)
// 	// 	if err != nil {
// 	// 		return fmt.Errorf("could not find key %x in tree rebuilt from proof: %w", key, err)
// 	// 	}
// 	// 	if len(val) > 0 {
// 	// 		if !bytes.Equal(val, stemdiff.UpdatedCurrent[i]) {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.UpdatedCurrent[i])
// 	// 		}
// 	// 	} else {
// 	// 		if stemdiff.UpdatedCurrent[i] != nil && len(stemdiff.UpdatedCurrent[i]) != 0 {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.UpdatedCurrent[i])
// 	// 		}
// 	// 	}
// 	// }

// 	// method 3
// 	// for i, suffix := range stemdiff.ReadSuffixes {
// 	// 	var key [32]byte
// 	// 	copy(key[:31], stemdiff.Stem[:])
// 	// 	key[31] = suffix
// 	// 	val, err := pretree.Get(key[:], nil)
// 	// 	if err != nil {
// 	// 		return fmt.Errorf("could not find key %x in tree rebuilt from proof: %w", key, err)
// 	// 	}
// 	// 	if len(val) > 0 {
// 	// 		if !bytes.Equal(val, stemdiff.ReadCurrent[i]) {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.ReadCurrent[i])
// 	// 		}
// 	// 	} else {
// 	// 		if stemdiff.ReadCurrent[i] != nil && len(stemdiff.ReadCurrent[i]) != 0 {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.ReadCurrent[i])
// 	// 		}
// 	// 	}
// 	// }
// 	// for i, suffix := range stemdiff.UpdatedSuffixes {
// 	// 	var key [32]byte
// 	// 	copy(key[:31], stemdiff.Stem[:])
// 	// 	key[31] = suffix
// 	// 	val, err := pretree.Get(key[:], nil)
// 	// 	if err != nil {
// 	// 		return fmt.Errorf("could not find key %x in tree rebuilt from proof: %w", key, err)
// 	// 	}
// 	// 	if len(val) > 0 {
// 	// 		if !bytes.Equal(val, stemdiff.UpdatedCurrent[i]) {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.UpdatedCurrent[i])
// 	// 		}
// 	// 	} else {
// 	// 		if stemdiff.UpdatedCurrent[i] != nil && len(stemdiff.UpdatedCurrent[i]) != 0 {
// 	// 			return fmt.Errorf("could not find correct value at %x in tree rebuilt from proof: %x != %x", key, val, stemdiff.UpdatedCurrent[i])
// 	// 		}
// 	// 	}
// 	// }

// 	// }

// 	// TODO: this is necessary to verify that the post-values are the correct ones.
// 	// But all this can be avoided with a even faster way. The EVM block execution can
// 	// keep track of the written keys, and compare that list with this post-values list.
// 	// This can avoid regenerating the post-tree which is somewhat expensive.
// 	posttree, err := verkle.PostStateTreeFromStateDiff(pretree, statediff)
// 	if err != nil {
// 		return fmt.Errorf("error rebuilding the post-tree from proof: %w", err)
// 	}
// 	regeneratedPostTreeRoot := posttree.Commitment().Bytes()
// 	if !bytes.Equal(regeneratedPostTreeRoot[:], postStateRoot) {
// 		return fmt.Errorf("post tree root mismatch: %x != %x", regeneratedPostTreeRoot, postStateRoot)
// 	}

// 	return verkle.VerifyVerkleProofWithPreState(proof, pretree)
// }

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
			values = make([][]byte, verkle.NodeWidth)
			key = utils.GetTreeKeyCodeChunkWithEvaluatedAddress(t.pointCache.GetTreeKeyHeader(addr[:]), uint256.NewInt(chunknr))
		}
		values[groupOffset] = chunks[i : i+32]

		if groupOffset == 255 || len(chunks)-i <= 32 {
			err = t.UpdateStem(key[:31], values)

			if err != nil {
				return fmt.Errorf("UpdateContractCode (addr=%x) error: %w", addr[:], err)
			}
		}
	}
	return nil
}
