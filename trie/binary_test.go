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
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

var (
	zeroKey  = [32]byte{}
	oneKey   = common.HexToHash("0101010101010101010101010101010101010101010101010101010101010101")
	twoKey   = common.HexToHash("0202020202020202020202020202020202020202020202020202020202020202")
	threeKey = common.HexToHash("0303030303030303030303030303030303030303030303030303030303030303")
	fourKey  = common.HexToHash("0404040404040404040404040404040404040404040404040404040404040404")
	ffKey    = common.HexToHash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
)

func TestSingleEntry(t *testing.T) {
	tree := NewBinaryNode()
	tree.Insert(zeroKey[:], oneKey[:], nil)
	if tree.GetHeight() == 1 {
		t.Fatal("invalid depth")
	}
	expected := common.HexToHash("694545468677064fd833cddc8455762fe6b21c6cabe2fc172529e0f573181cd5")
	if tree.Hash() != expected {
		t.Fatalf("invalid tree root, got %x, want %x", tree.Hash(), expected)
	}
}
func TestTwoEntriesDiffFirstBit(t *testing.T) {
	tree := NewBinaryNode()
	tree.Insert(zeroKey[:], oneKey[:], nil)
	tree.Insert(common.HexToHash("8000000000000000000000000000000000000000000000000000000000000000").Bytes(), twoKey[:], nil)
	if tree.GetHeight() != 2 {
		t.Fatal("invalid height")
	}
	if tree.Hash() != common.HexToHash("85fc622076752a6fcda2c886c18058d639066a83473d9684704b5a29455ed2ed") {
		t.Fatal("invalid tree root")
	}
}

func TestOneStemColocatedValues(t *testing.T) {
	tree := NewBinaryNode()
	tree.Insert(common.HexToHash("0000000000000000000000000000000000000000000000000000000000000003").Bytes(), oneKey[:], nil)
	tree.Insert(common.HexToHash("0000000000000000000000000000000000000000000000000000000000000004").Bytes(), twoKey[:], nil)
	tree.Insert(common.HexToHash("0000000000000000000000000000000000000000000000000000000000000009").Bytes(), threeKey[:], nil)
	tree.Insert(common.HexToHash("00000000000000000000000000000000000000000000000000000000000000FF").Bytes(), fourKey[:], nil)
	if tree.GetHeight() != 1 {
		t.Fatal("invalid height")
	}
}
func TestTwoStemColocatedValues(t *testing.T) {
	tree := NewBinaryNode()
	// stem: 0...0
	tree.Insert(common.HexToHash("0000000000000000000000000000000000000000000000000000000000000003").Bytes(), oneKey[:], nil)
	tree.Insert(common.HexToHash("0000000000000000000000000000000000000000000000000000000000000004").Bytes(), twoKey[:], nil)
	// stem: 10...0
	tree.Insert(common.HexToHash("8000000000000000000000000000000000000000000000000000000000000003").Bytes(), oneKey[:], nil)
	tree.Insert(common.HexToHash("8000000000000000000000000000000000000000000000000000000000000004").Bytes(), twoKey[:], nil)
	if tree.GetHeight() != 2 {
		t.Fatal("invalid height")
	}
}

func TestTwoKeysMatchFirst42Bits(t *testing.T) {
	tree := NewBinaryNode()
	// key1 and key 2 have the same prefix of 42 bits (b0*42+b1+b1) and differ after.
	key1 := common.HexToHash("0000000000C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0").Bytes()
	key2 := common.HexToHash("0000000000E00000000000000000000000000000000000000000000000000000").Bytes()
	tree.Insert(key1, oneKey[:], nil)
	tree.Insert(key2, twoKey[:], nil)
	if tree.GetHeight() != 1+42+1 {
		t.Fatal("invalid height")
	}
}
func TestInsertDuplicateKey(t *testing.T) {
	tree := NewBinaryNode()
	tree.Insert(oneKey[:], oneKey[:], nil)
	tree.Insert(oneKey[:], twoKey[:], nil)
	if tree.GetHeight() != 1 {
		t.Fatal("invalid height")
	}
	// Verify that the value is updated
	// if tree.values[1] == twoKey[:] {
	// 	t.Fatal("invalid height")
	// }
}
func TestLargeNumberOfEntries(t *testing.T) {
	tree := NewBinaryNode()
	for i := 0; i < 256; i++ {
		var key [32]byte
		key[0] = byte(i)
		tree.Insert(key[:], ffKey[:], nil)
	}
	if tree.GetHeight() != 1+8 {
		t.Fatal("invalid height")
	}
}

func TestMerkleizeMultipleEntries(t *testing.T) {
	tree := NewBinaryNode()
	keys := [][]byte{
		zeroKey[:],
		common.HexToHash("8000000000000000000000000000000000000000000000000000000000000000").Bytes(),
		common.HexToHash("0100000000000000000000000000000000000000000000000000000000000000").Bytes(),
		common.HexToHash("8100000000000000000000000000000000000000000000000000000000000000").Bytes(),
	}
	for i, key := range keys {
		var v [32]byte
		binary.LittleEndian.PutUint64(v[:8], uint64(i))
		tree.Insert(key, v[:], nil)
	}
	got := tree.Hash()
	expected := common.HexToHash("e93c209026b8b00d76062638102ece415028bd104e1d892d5399375a323f2218")
	if got != expected {
		t.Fatal("invalid root")
	}
}
