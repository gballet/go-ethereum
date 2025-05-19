// Copyright 2025 go-ethereum Authors
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
	"github.com/ethereum/go-verkle"
	"github.com/holiman/uint256"
	"github.com/zeebo/blake3"
)

type (
	NodeFlushFn    func([]byte, BinaryNode)
	NodeResolverFn func([]byte) ([]byte, error)
)

type BinaryNode interface {
	Get([]byte, NodeResolverFn) ([]byte, error)
	Insert([]byte, []byte, NodeResolverFn) (BinaryNode, error)
	Commit() common.Hash
	Copy() BinaryNode
	Hash() common.Hash
	GetValuesAtStem([]byte, NodeResolverFn) ([][]byte, error)
	InsertValuesAtStem([]byte, [][]byte, NodeResolverFn) (BinaryNode, error)
	CollectNodes([]byte, NodeFlushFn) error

	toDot(parent, path string) string
	GetHeight() int
}

type Empty struct{}

func (e Empty) Get(_ []byte, _ NodeResolverFn) ([]byte, error) {
	return nil, nil
}

func (e Empty) Insert(key []byte, value []byte, _ NodeResolverFn) (BinaryNode, error) {
	var values [256][]byte
	values[key[31]] = value
	return &StemNode{
		Stem:   append([]byte(nil), key[:31]...),
		Values: values[:],
	}, nil
}

func (e Empty) Commit() common.Hash {
	return common.Hash{}
}

func (e Empty) Copy() BinaryNode {
	return Empty{}
}

func (e Empty) Hash() common.Hash {
	return common.Hash{}
}

func (e Empty) GetValuesAtStem(_ []byte, _ NodeResolverFn) ([][]byte, error) {
	var values [256][]byte
	return values[:], nil
}

func (e Empty) InsertValuesAtStem(key []byte, values [][]byte, _ NodeResolverFn) (BinaryNode, error) {
	return &StemNode{
		Stem:   append([]byte(nil), key[:31]...),
		Values: values,
	}, nil
}

func (e Empty) CollectNodes(_ []byte, _ NodeFlushFn) error {
	panic("not implemented") // TODO: Implement
}

func (e Empty) toDot(parent string, path string) string {
	panic("not implemented") // TODO: Implement
}

func (e Empty) GetHeight() int {
	return 0
}

type HashedNode common.Hash

func (h HashedNode) Get(_ []byte, _ NodeResolverFn) ([]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (h HashedNode) Insert(key []byte, value []byte, resolver NodeResolverFn) (BinaryNode, error) {
	if resolver == nil {
		return h, errors.New("resolver is nil")
	}

	resolved, err := resolver(h[:])
	if err != nil {
		return nil, fmt.Errorf("insert error: %w", err)
	}
	node, err := DeserializeNode(resolved, 0)
	if err != nil {
		return nil, fmt.Errorf("insert node deserialization error: %w", err)
	}

	return node.Insert(key, value, resolver)
}

func (h HashedNode) Commit() common.Hash {
	panic("not implemented") // TODO: Implement
}

func (h HashedNode) Copy() BinaryNode {
	panic("not implemented") // TODO: Implement
}

func (h HashedNode) Hash() common.Hash {
	panic("not implemented") // TODO: Implement
}

func (h HashedNode) GetValuesAtStem(_ []byte, _ NodeResolverFn) ([][]byte, error) {
	panic("not implemented") // TODO: Implement
}

func (h HashedNode) InsertValuesAtStem(key []byte, values [][]byte, resolver NodeResolverFn) (BinaryNode, error) {
	if resolver == nil {
		return h, errors.New("resolver is nil")
	}

	resolved, err := resolver(h[:])
	if err != nil {
		return nil, fmt.Errorf("insert error: %w", err)
	}
	node, err := DeserializeNode(resolved, 0)
	if err != nil {
		return nil, fmt.Errorf("insert node deserialization error: %w", err)
	}

	return node.InsertValuesAtStem(key, values, resolver)
}

func (h HashedNode) toDot(parent string, path string) string {
	panic("not implemented") // TODO: Implement
}

func (h HashedNode) CollectNodes([]byte, NodeFlushFn) error {
	panic("not implemented") // TODO: Implement
}

func (h HashedNode) GetHeight() int {
	panic("should not get here, this is a bug") // TODO: Implement
}

type StemNode struct {
	Stem   []byte
	Values [][]byte
}

func (bt *StemNode) Get(key []byte, _ NodeResolverFn) ([]byte, error) {
	panic("this should not be called directly")
}

func (bt *StemNode) Insert(key []byte, value []byte, _ NodeResolverFn) (BinaryNode, error) {
	if !bytes.Equal(bt.Stem, key[:31]) {
		// look for the first bit that differs
		// TODO maintaining a depth field would save some work
		for depth := 0; depth < 31*8; depth++ {
			bitStem := bt.Stem[depth/8] >> (7 - (depth % 8)) & 1

			new := &InternalNode{}
			var child, other *BinaryNode
			if bitStem == 0 {
				new.left = bt
				child = &new.left
				other = &new.right
			} else {
				new.right = bt
				child = &new.right
				other = &new.left
			}

			bitKey := key[depth/8] >> (7 - (depth % 8)) & 1
			if bitKey == bitStem {
				var err error
				*child, err = (*child).Insert(key, value, nil)
				if err != nil {
					return new, fmt.Errorf("insert error: %w", err)
				}
			} else {
				var values [256][]byte
				values[key[31]] = value
				*other = &StemNode{
					Stem:   append([]byte(nil), key[:31]...),
					Values: values[:],
				}
			}

			return new, nil
		}
	}
	if len(value) != 32 {
		return bt, errors.New("invalid insertion: value length")
	}

	bt.Values[key[31]] = value
	return bt, nil
}

func (bt *StemNode) Commit() common.Hash {
	return bt.Hash()
}

func (bt *StemNode) Copy() BinaryNode {
	var values [256][]byte
	for i, v := range bt.Values {
		values[i] = append([]byte(nil), v...)
	}
	return &StemNode{
		Stem:   append([]byte(nil), bt.Stem...),
		Values: values[:],
	}
}

func (bt *StemNode) GetHeight() int {
	return 1
}

func (bt *StemNode) Hash() common.Hash {
	var data [verkle.NodeWidth]common.Hash
	for i, v := range bt.Values {
		if v != nil {
			h := blake3.Sum256(v)
			data[i] = common.BytesToHash(h[:])
		}
	}

	h := blake3.New()
	for level := 1; level <= 8; level++ {
		for i := 0; i < verkle.NodeWidth/(1<<level); i++ {
			h.Reset()

			if data[i*2] == (common.Hash{}) && data[i*2+1] == (common.Hash{}) {
				data[i] = common.Hash{}
				continue
			}

			h.Write(data[i*2][:])
			h.Write(data[i*2+1][:])
			data[i] = common.Hash(h.Sum(nil))
		}
	}

	h.Reset()
	h.Write(bt.Stem)
	h.Write([]byte{0})
	h.Write(data[0][:])
	return common.BytesToHash(h.Sum(nil))
}

func (bt *StemNode) CollectNodes(path []byte, flush NodeFlushFn) error {
	flush(path, bt)
	return nil
}

func (bt *StemNode) GetValuesAtStem(_ []byte, _ NodeResolverFn) ([][]byte, error) {
	return bt.Values[:], nil
}

func (bt *StemNode) InsertValuesAtStem(key []byte, values [][]byte, _ NodeResolverFn) (BinaryNode, error) {
	if !bytes.Equal(bt.Stem, key[:31]) {
		return &InternalNode{}, nil
	}

	// same stem, just merge the two value lists
	for i, v := range values {
		if v != nil {
			bt.Values[i] = v
		}
	}
	return bt, nil
}

func (bt *StemNode) toDot(parent, path string) string {
	me := fmt.Sprintf("stem%s", path)
	ret := fmt.Sprintf("%s [label=\"stem=%x c=%x\"]\n", me, bt.Stem, bt.Hash())
	ret = fmt.Sprintf("%s %s -> %s\n", ret, parent, me)
	for i, v := range bt.Values {
		if v != nil {
			ret = fmt.Sprintf("%s%s%x [label=\"%x\"]\n", ret, me, i, v)
			ret = fmt.Sprintf("%s%s -> %s%x\n", ret, me, me, i)
		}
	}
	return ret
}

func (n *StemNode) Key(i int) []byte {
	var ret [32]byte
	copy(ret[:], n.Stem)
	ret[verkle.StemSize] = byte(i)
	return ret[:]
}

type InternalNode struct {
	left, right BinaryNode
	depth       int
}

func NewBinaryNode() BinaryNode {
	return Empty{}
}

func (bt *InternalNode) GetValuesAtStem(stem []byte, resolver NodeResolverFn) ([][]byte, error) {
	if bt.depth > 31*8 {
		return nil, errors.New("node too deep")
	}

	bit := stem[bt.depth/8] >> (7 - (bt.depth % 8)) & 1
	var child *BinaryNode
	if bit == 0 {
		child = &bt.left
	} else {
		child = &bt.right
	}

	if hn, ok := (*child).(HashedNode); ok {
		data, err := resolver(hn[:])
		if err != nil {
			return nil, fmt.Errorf("GetValuesAtStem resolve error: %w", err)
		}
		node, err := DeserializeNode(data, bt.depth+1)
		if err != nil {
			return nil, fmt.Errorf("GetValuesAtStem node deserialization error: %w", err)
		}
		*child = node
	}
	return (*child).GetValuesAtStem(stem, resolver)
}

func (bt *InternalNode) Get(key []byte, resolver NodeResolverFn) ([]byte, error) {
	values, err := bt.GetValuesAtStem(key[:31], resolver)
	if err != nil {
		return nil, fmt.Errorf("Get error: %w", err)
	}
	return values[key[31]], nil
}

func (bt *InternalNode) Insert(key []byte, value []byte, resolver NodeResolverFn) (BinaryNode, error) {
	var values [256][]byte
	values[key[31]] = value
	return bt.InsertValuesAtStem(key[:31], values[:], resolver)
}

func (bt *InternalNode) Commit() common.Hash {
	hasher := blake3.New()
	hasher.Write(bt.left.Commit().Bytes())
	hasher.Write(bt.right.Commit().Bytes())
	sum := hasher.Sum(nil)
	return common.BytesToHash(sum)
}

func (bt *InternalNode) Copy() BinaryNode {
	return &InternalNode{
		left:  bt.left.Copy(),
		right: bt.right.Copy(),
		depth: bt.depth,
	}
}

func (bt *InternalNode) Hash() common.Hash {
	h := blake3.New()
	if bt.left != nil {
		h.Write(bt.left.Hash().Bytes())
	} else {
		h.Write(zero[:])
	}
	if bt.right != nil {
		h.Write(bt.right.Hash().Bytes())
	} else {
		h.Write(zero[:])
	}
	return common.BytesToHash(h.Sum(nil))
}

func (bt *InternalNode) InsertValuesAtStem(stem []byte, values [][]byte, resolver NodeResolverFn) (BinaryNode, error) {
	bit := stem[bt.depth/8] >> (7 - (bt.depth % 8)) & 1
	var (
		child *BinaryNode
		err   error
	)
	if bit == 0 {
		child = &bt.left
	} else {
		child = &bt.right
	}

	// if *child == nil {
	// 	*child = &StemNode{
	// 		Stem:   append([]byte(nil), stem[:31]...),
	// 		Values: values,
	// 	}
	// 	return bt, nil
	// }
	// XXX il faut vérifier si c'est un stemnode et aussi faire le resolve

	*child, err = (*child).InsertValuesAtStem(stem, values, resolver)
	return bt, err
}

func (bt *InternalNode) CollectNodes(path []byte, flushfn NodeFlushFn) error {
	if bt.left != nil {
		var p [256]byte
		copy(p[:], path)
		childpath := p[:len(path)]
		childpath = append(childpath, 0)
		if err := bt.left.CollectNodes(childpath, flushfn); err != nil {
			return err
		}
	}
	if bt.right != nil {
		var p [256]byte
		copy(p[:], path)
		childpath := p[:len(path)]
		childpath = append(childpath, 1)
		if err := bt.right.CollectNodes(childpath, flushfn); err != nil {
			return err
		}
	}
	flushfn(path, bt)
	return nil
}

func (bt *InternalNode) GetHeight() int {
	var (
		leftHeight  int
		rightHeight int
	)
	if bt.left != nil {
		leftHeight = bt.left.GetHeight()
	}
	if bt.right != nil {
		rightHeight = bt.right.GetHeight()
	}
	return 1 + max(leftHeight, rightHeight)
}

func SerializeNode(node BinaryNode) []byte {
	switch n := (node).(type) {
	case *InternalNode:
		var serialized [65]byte
		serialized[0] = 1
		copy(serialized[1:33], n.left.Hash().Bytes())
		copy(serialized[33:65], n.right.Hash().Bytes())
		return serialized[:]
	case *StemNode:
		var serialized [32 + 256*32]byte
		serialized[0] = 2
		copy(serialized[1:32], node.(*StemNode).Stem)
		bitmap := serialized[32:64]
		offset := 64
		for i, v := range node.(*StemNode).Values {
			if v != nil {
				bitmap[i/8] |= 1 << (7 - (i % 8))
				copy(serialized[offset:offset+32], v)
				offset += 32
			}
		}
		return serialized[:]
	default:
		panic("invalid node type")
	}
}

func DeserializeNode(serialized []byte, depth int) (BinaryNode, error) {
	if len(serialized) == 0 {
		return nil, errors.New("empty serialized node")
	}

	switch serialized[0] {
	case 1:
		if len(serialized) != 65 {
			return nil, errors.New("invalid serialized node length")
		}
		return &InternalNode{
			depth: depth,
			left:  HashedNode(common.BytesToHash(serialized[1:33])),
			right: HashedNode(common.BytesToHash(serialized[33:65])),
		}, nil
	case 2:
		var values [256][]byte
		bitmap := serialized[32:64]
		offset := 64
		for i := 0; i < 256; i++ {
			if bitmap[i/8]>>(7-(i%8))&1 == 1 {
				values[i] = serialized[offset : offset+32]
				offset += 32
			}
		}
		return &StemNode{
			Stem:   serialized[1:32],
			Values: values[:],
		}, nil
	default:
		return nil, errors.New("invalid node type")
	}
}

// VerkleTrie is a wrapper around VerkleNode that implements the trie.Trie
// interface so that Verkle trees can be reused verbatim.
type VerkleTrie struct {
	root       BinaryNode
	db         *Database
	pointCache *utils.PointCache
	ended      bool
}

func (vt *VerkleTrie) ToDot() string {
	vt.root.Commit()
	return vt.root.toDot("", "")
}

func (n *InternalNode) toDot(parent, path string) string {
	me := fmt.Sprintf("internal%s", path)
	ret := fmt.Sprintf("%s [label=\"I: %x\"]\n", me, n.Hash())
	if len(parent) > 0 {
		ret = fmt.Sprintf("%s %s -> %s\n", ret, parent, me)
	}

	if n.left != nil {
		ret = fmt.Sprintf("%s%s", ret, n.left.toDot(me, fmt.Sprintf("%s%02x", path, 0)))
	}
	if n.right != nil {
		ret = fmt.Sprintf("%s%s", ret, n.right.toDot(me, fmt.Sprintf("%s%02x", path, 1)))
	}

	return ret
}

func NewVerkleTrie(root BinaryNode, db *Database, pointCache *utils.PointCache, ended bool) *VerkleTrie {
	return &VerkleTrie{
		root:       root,
		db:         db,
		pointCache: pointCache,
		ended:      ended,
	}
}

func (trie *VerkleTrie) FlatdbNodeResolver(path []byte) ([]byte, error) {
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
func (trie *VerkleTrie) GetKey(key []byte) []byte {
	return key
}

// Get returns the value for key stored in the trie. The value bytes must
// not be modified by the caller. If a node was not found in the database, a
// trie.MissingNodeError is returned.
func (trie *VerkleTrie) GetStorage(addr common.Address, key []byte) ([]byte, error) {
	pointEval := trie.pointCache.GetTreeKeyHeader(addr[:])
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(pointEval, key)
	return trie.root.Get(k, trie.FlatdbNodeResolver)
}

// GetWithHashedKey returns the value, assuming that the key has already
// been hashed.
func (trie *VerkleTrie) GetWithHashedKey(key []byte) ([]byte, error) {
	return trie.root.Get(key, trie.FlatdbNodeResolver)
}

func (t *VerkleTrie) GetAccount(addr common.Address) (*types.StateAccount, error) {
	acc := &types.StateAccount{}
	versionkey := t.pointCache.GetTreeKeyBasicDataCached(addr[:])
	var (
		values [][]byte
		err    error
	)
	switch t.root.(type) {
	case *InternalNode:
		values, err = t.root.(*InternalNode).GetValuesAtStem(versionkey[:31], t.FlatdbNodeResolver)
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

	// if the account has been deleted, then values[10] will be 0 and not nil. If it has
	// been recreated after that, then its code keccak will NOT be 0. So return `nil` if
	// the nonce, and values[10], and code keccak is 0.
	if bytes.Equal(values[utils.BasicDataLeafKey], zero[:]) && len(values) > 10 && len(values[10]) > 0 && bytes.Equal(values[utils.CodeHashLeafKey], zero[:]) {
		if !t.ended {
			return nil, errDeletedAccount
		} else {
			return nil, nil
		}
	}

	acc.Nonce = binary.BigEndian.Uint64(values[utils.BasicDataLeafKey][utils.BasicDataNonceOffset:])
	var balance [16]byte
	copy(balance[:], values[utils.BasicDataLeafKey][utils.BasicDataBalanceOffset:])
	acc.Balance = new(big.Int).SetBytes(balance[:])
	acc.CodeHash = values[utils.CodeHashLeafKey]

	return acc, nil
}

var zero [32]byte

func (t *VerkleTrie) UpdateAccount(addr common.Address, acc *types.StateAccount, codeLen int) error {
	var (
		basicData [32]byte
		values    = make([][]byte, verkle.NodeWidth)
		stem      = t.pointCache.GetTreeKeyBasicDataCached(addr[:])
	)

	binary.BigEndian.PutUint32(basicData[utils.BasicDataCodeSizeOffset-1:], uint32(codeLen))
	binary.BigEndian.PutUint64(basicData[utils.BasicDataNonceOffset:], acc.Nonce)
	// Because the balance is a max of 16 bytes, truncate
	// the extra values. This happens in devmode, where
	// 0xff**32 is allocated to the developer account.
	balanceBytes := acc.Balance.Bytes()
	// TODO: reduce the size of the allocation in devmode, then panic instead
	// of truncating.
	if len(balanceBytes) > 16 {
		balanceBytes = balanceBytes[16:]
	}
	copy(basicData[32-len(balanceBytes):], balanceBytes[:])
	values[utils.BasicDataLeafKey] = basicData[:]
	values[utils.CodeHashLeafKey] = acc.CodeHash[:]

	switch root := t.root.(type) {
	case *InternalNode:
		r, err := root.InsertValuesAtStem(stem, values, t.FlatdbNodeResolver)
		if err != nil {
			return fmt.Errorf("UpdateAccount (%x) error: %v", addr, err)
		}
		t.root = r
	default:
		return errInvalidRootType
	}

	return nil
}

func (trie *VerkleTrie) UpdateStem(key []byte, values [][]byte) error {
	switch root := trie.root.(type) {
	case *InternalNode:
		r, err := root.InsertValuesAtStem(key, values, trie.FlatdbNodeResolver)
		if err != nil {
			return fmt.Errorf("UpdateStem (%x) error: %v", key, err)
		}
		trie.root = r
		return nil
	default:
		panic("invalid root type")
	}
}

// Update associates key with value in the trie. If value has length zero, any
// existing value is deleted from the trie. The value bytes must not be modified
// by the caller while they are stored in the trie. If a node was not found in the
// database, a trie.MissingNodeError is returned.
func (trie *VerkleTrie) UpdateStorage(address common.Address, key, value []byte) error {
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(trie.pointCache.GetTreeKeyHeader(address[:]), key)
	var v [32]byte
	if len(value) >= 32 {
		copy(v[:], value[:32])
	} else {
		copy(v[32-len(value):], value[:])
	}
	root, err := trie.root.Insert(k, v[:], trie.FlatdbNodeResolver)
	if err != nil {
		return fmt.Errorf("UpdateStorage (%x) error: %v", address, err)
	}
	trie.root = root
	return nil
}

func (t *VerkleTrie) DeleteAccount(addr common.Address) error {
	return nil
}

// Delete removes any existing value for key from the trie. If a node was not
// found in the database, a trie.MissingNodeError is returned.
func (trie *VerkleTrie) DeleteStorage(addr common.Address, key []byte) error {
	pointEval := trie.pointCache.GetTreeKeyHeader(addr[:])
	k := utils.GetTreeKeyStorageSlotWithEvaluatedAddress(pointEval, key)
	var zero [32]byte
	root, err := trie.root.Insert(k, zero[:], trie.FlatdbNodeResolver)
	if err != nil {
		return fmt.Errorf("DeleteStorage (%x) error: %v", addr, err)
	}
	trie.root = root
	return nil
}

// Hash returns the root hash of the trie. It does not write to the database and
// can be used even if the trie doesn't have one.
func (trie *VerkleTrie) Hash() common.Hash {
	return trie.root.Commit()
}

// Commit writes all nodes to the trie's memory database, tracking the internal
// and external (for account tries) references.
func (trie *VerkleTrie) Commit(_ bool) (common.Hash, *trienode.NodeSet, error) {
	root := trie.root.(*InternalNode)
	nodeset := trienode.NewNodeSet(common.Hash{})

	err := root.CollectNodes(nil, func(path []byte, node BinaryNode) {
		serialized := SerializeNode(node)
		trie.db.diskdb.Put(append(FlatDBVerkleNodeKeyPrefix, path...), serialized)
	})
	if err != nil {
		panic(fmt.Errorf("CollectNodes failed: %v", err))
	}

	// Serialize root commitment form
	return trie.root.Hash(), nodeset, nil
}

// NodeIterator returns an iterator that returns nodes of the trie. Iteration
// starts at the key after the given start key.
func (trie *VerkleTrie) NodeIterator(startKey []byte) (NodeIterator, error) {
	return newVerkleNodeIterator(trie, nil)
}

// Prove constructs a Merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root), ending
// with the node that proves the absence of the key.
func (trie *VerkleTrie) Prove(key []byte, proofDb ethdb.KeyValueWriter) error {
	panic("not implemented")
}

func (trie *VerkleTrie) Copy() *VerkleTrie {
	return &VerkleTrie{
		root:       trie.root.Copy(),
		db:         trie.db,
		pointCache: trie.pointCache,
	}
}

func (trie *VerkleTrie) IsVerkle() bool {
	return true
}

func MakeBinaryMultiProof(pretrie, posttrie BinaryNode, keys [][]byte, resolver NodeResolverFn) (*verkle.VerkleProof, [][]byte, [][]byte, [][]byte, error) {
	panic("not implemented")
}

func SerializeProof(proof *verkle.VerkleProof) (*verkle.VerkleProof, verkle.StateDiff, error) {
	panic("not implemented")
}

func ProveAndSerialize(pretrie, posttrie *VerkleTrie, keys [][]byte, resolver NodeResolverFn) (*verkle.VerkleProof, verkle.StateDiff, error) {
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

func (t *VerkleTrie) SetStorageRootConversion(addr common.Address, root common.Hash) {
	t.db.SetStorageRootConversion(addr, root)
}

func (t *VerkleTrie) ClearStrorageRootConversion(addr common.Address) {
	t.db.ClearStorageRootConversion(addr)
}

// Note: the basic data leaf needs to have been previously created for this to work
func (t *VerkleTrie) UpdateContractCode(addr common.Address, codeHash common.Hash, code []byte) error {
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
