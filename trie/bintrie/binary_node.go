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

package bintrie

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

type (
	NodeFlushFn    func([]byte, BinaryNode)
	NodeResolverFn func([]byte, common.Hash) ([]byte, error)
)

// zero is the zero value for a 32-byte array.
var zero [32]byte

const (
	NodeWidth = 256 // Number of child per leaf node
	StemSize  = 31  // Number of bytes to travel before reaching a group of leaves
)

const (
	nodeTypeStem = iota + 1 // Stem node, contains a stem and a bitmap of values
	nodeTypeInternal
)

// BinaryNode is an interface for a binary trie node.
type BinaryNode interface {
	Get([]byte, NodeResolverFn) ([]byte, error)
	Insert([]byte, []byte, NodeResolverFn, int) (BinaryNode, error)
	Copy() BinaryNode
	Hash() common.Hash
	GetValuesAtStem([]byte, NodeResolverFn) ([][]byte, error)
	InsertValuesAtStem([]byte, [][]byte, NodeResolverFn, int) (BinaryNode, error)
	CollectNodes([]byte, NodeFlushFn) error

	toDot(parent, path string) string
	GetHeight() int
}

// SerializeNode serializes a binary trie node into a byte slice.
func SerializeNode(node BinaryNode) []byte {
	switch n := (node).(type) {
	case *InternalNode:
		var serialized [65]byte
		serialized[0] = nodeTypeInternal
		copy(serialized[1:33], n.left.Hash().Bytes())
		copy(serialized[33:65], n.right.Hash().Bytes())
		panic(fmt.Sprintf("serialization: %v", serialized))
		return serialized[:]
	case *StemNode:
		var serialized [1 + 31 + 32 + 256*32]byte
		serialized[0] = nodeTypeStem
		copy(serialized[1:32], n.Stem)
		bitmap := serialized[32:64]
		offset := 64
		for i, v := range n.Values {
			if v != nil {
				bitmap[i/8] |= 1 << (7 - (i % 8))
				copy(serialized[offset:offset+32], v)
				offset += 32
			}
		}
		// Only return the actual data, not the entire array
		return serialized[:offset]
	default:
		panic("invalid node type")
	}
}

var invalidSerializedLength = errors.New("invalid serialized node length")

// DeserializeNode deserializes a binary trie node from a byte slice.
func DeserializeNode(serialized []byte, depth int) (BinaryNode, error) {
	if len(serialized) == 0 {
		return Empty{}, nil
	}

	switch serialized[0] {
	case nodeTypeInternal:
		if len(serialized) != 65 {
			return nil, fmt.Errorf("invalid length < 65: %d, %w", len(serialized), invalidSerializedLength)
		}
		return &InternalNode{
			depth: depth,
			left:  HashedNode(common.BytesToHash(serialized[1:33])),
			right: HashedNode(common.BytesToHash(serialized[33:65])),
		}, nil
	case nodeTypeStem:
		if len(serialized) < 64 {
			return nil, fmt.Errorf("invalid length < 64: %d, %w", len(serialized), invalidSerializedLength)
		}
		var values [256][]byte
		bitmap := serialized[32:64]
		offset := 64

		for i := range 256 {
			if bitmap[i/8]>>(7-(i%8))&1 == 1 {
				if len(serialized) < offset+32 {
					return nil, fmt.Errorf("! invalid serialized length: %v %d %d depth=%d %v %v %w", serialized, len(serialized), offset+32, depth, bitmap, serialized[1:32], invalidSerializedLength)
				}
				values[i] = serialized[offset : offset+32]
				offset += 32
			}
		}
		return &StemNode{
			Stem:   serialized[1:32],
			Values: values[:],
			depth:  depth,
		}, nil
	default:
		return nil, errors.New("invalid node type")
	}
}

// ToDot converts the binary trie to a DOT language representation. Useful for debugging.
func ToDot(root BinaryNode) string {
	return root.toDot("", "")
}
