// Copyright 2026 go-ethereum Authors
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
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie/archive"
)

func TestExpiredNodeEncodeDecode(t *testing.T) {
	testCases := []struct {
		offset uint64
		size   uint64
	}{
		{0, 0},
		{1, 100},
		{255, 1024},
		{256, 4096},
		{1 << 16, 1 << 20},
		{1 << 32, 1 << 32},
		{1<<64 - 1, 1<<64 - 1},
	}

	for _, tc := range testCases {
		original := &expiredNode{offset: tc.offset, size: tc.size}

		w := rlp.NewEncoderBuffer(nil)
		original.encode(w)
		encoded := w.ToBytes()
		w.Flush()

		decoded, err := decodeNodeUnsafe(nil, encoded)
		if err != nil {
			t.Fatalf("failed to decode expired node with offset %d, size %d: %v", tc.offset, tc.size, err)
		}

		expNode, ok := decoded.(*expiredNode)
		if !ok {
			t.Fatalf("decoded node is not an expired node, got %T", decoded)
		}

		if expNode.offset != original.offset {
			t.Errorf("offset mismatch: got %d, want %d", expNode.offset, original.offset)
		}
		if expNode.size != original.size {
			t.Errorf("size mismatch: got %d, want %d", expNode.size, original.size)
		}
	}
}

func TestExpiredNodeEncodedFormat(t *testing.T) {
	node := &expiredNode{offset: 0x0102030405060708, size: 0x1112131415161718}

	w := rlp.NewEncoderBuffer(nil)
	node.encode(w)
	encoded := w.ToBytes()
	w.Flush()

	expected := []byte{
		0x00,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	}
	if !bytes.Equal(encoded, expected) {
		t.Errorf("encoded format mismatch: got %x, want %x", encoded, expected)
	}
}

func TestExpiredNodeFstring(t *testing.T) {
	node := &expiredNode{offset: 12345, size: 6789}
	s := node.fstring("")
	if s != "<expired: offset=12345, size=6789> " {
		t.Errorf("fstring mismatch: got %q", s)
	}
}

func TestExpiredNodeCache(t *testing.T) {
	node := &expiredNode{offset: 100}
	hash, dirty := node.cache()
	if hash != nil {
		t.Error("expected nil hash from expired node cache")
	}
	if !dirty {
		t.Error("expected dirty=true from expired node cache")
	}
}

func TestExpiredNodeInvalidLength(t *testing.T) {
	invalidCases := [][]byte{
		{0x00},
		{0x00, 0x01},
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11},
	}

	for _, buf := range invalidCases {
		_, err := decodeNodeUnsafe(nil, buf)
		if err == nil {
			t.Errorf("expected error for buffer length %d, got nil", len(buf))
		}
	}
}

func TestExpiredNodeNoResolver(t *testing.T) {
	tr := NewEmpty(nil)
	tr.root = &expiredNode{offset: 100}

	_, err := tr.Get([]byte("key"))
	if !errors.Is(err, archive.ErrNoResolver) {
		t.Errorf("expected archive.ErrNoResolver, got %v", err)
	}
}

func TestExpiredNodeWithResolver(t *testing.T) {
	tr := NewEmpty(nil)

	leafNode := &shortNode{
		Key: hexToCompact(keybytesToHex([]byte{0x12})),
		Val: valueNode([]byte("testvalue")),
	}
	encodedLeaf := nodeToBytes(leafNode)

	resolver := func(offset, size uint64) ([]*archive.Record, error) {
		if offset == 100 {
			return []*archive.Record{{Value: encodedLeaf}}, nil
		}
		return nil, errors.New("unknown offset")
	}

	tr.SetArchiveResolver(resolver)
	tr.root = &expiredNode{offset: 100, size: uint64(len(encodedLeaf)), archiveResolver: resolver}

	val, err := tr.Get([]byte{0x12})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(val) != "testvalue" {
		t.Errorf("value mismatch: got %q, want %q", val, "testvalue")
	}
}

func TestExpiredNodeCopy(t *testing.T) {
	resolver := func(offset, size uint64) ([]*archive.Record, error) {
		return nil, nil
	}

	original := &expiredNode{
		offset:          12345,
		size:            6789,
		archiveResolver: resolver,
	}

	copied := copyNode(original)
	copiedExp, ok := copied.(*expiredNode)
	if !ok {
		t.Fatalf("copied node is not an expired node, got %T", copied)
	}

	if copiedExp.offset != original.offset {
		t.Errorf("offset mismatch: got %d, want %d", copiedExp.offset, original.offset)
	}

	if copiedExp.size != original.size {
		t.Errorf("size mismatch: got %d, want %d", copiedExp.size, original.size)
	}

	if copiedExp.archiveResolver == nil {
		t.Error("archive resolver was not copied")
	}
}
