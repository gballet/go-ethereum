package bintrie

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestStorageSlotByte30NotDropped(t *testing.T) {
	addr := common.HexToAddress("0x91cb447bafc6e0ea0f4fe056f5a9b1f14bb06e5d")

	// Two storage keys that differ ONLY in byte 30.
	// Before the fix, copy(k[1:], key[:31]) + k[31]=key[31] dropped key[30],
	// making these two keys collide in the binary trie.
	slotA, _ := hex.DecodeString("0e17799ab0c899fcf3ab5116b2c11d7e941a022637254bda2c1bec9dd14a9c13")
	slotB, _ := hex.DecodeString("0e17799ab0c899fcf3ab5116b2c11d7e941a022637254bda2c1bec9dd14a9f13")

	keyA := GetBinaryTreeKeyStorageSlot(addr, slotA)
	keyB := GetBinaryTreeKeyStorageSlot(addr, slotB)

	if bytes.Equal(keyA, keyB) {
		t.Fatalf("byte-30 collision: slots differing only in byte 30 produced the same binary tree key\n  slotA=%x\n  slotB=%x\n  key=%x", slotA, slotB, keyA)
	}

	// Verify they share the same suffix (byte 31 = 0x13)
	if keyA[31] != keyB[31] {
		t.Fatalf("suffix should be the same (both have key[31]=0x13), got %02x vs %02x", keyA[31], keyB[31])
	}

	// Verify stems differ
	if bytes.Equal(keyA[:31], keyB[:31]) {
		t.Fatalf("stems should differ since byte 30 feeds into the SHA256 input")
	}
}

func TestStorageSlotConsistentWithStorageIndex(t *testing.T) {
	addr := common.HexToAddress("0x91cb447bafc6e0ea0f4fe056f5a9b1f14bb06e5d")

	// Test with a known main storage key
	slot, _ := hex.DecodeString("cfde4f29a1b76838742d06bc06b2226419c9c4cac873b661b11d99afb903431f")

	// Compute via GetBinaryTreeKeyStorageSlot
	binKey := GetBinaryTreeKeyStorageSlot(addr, slot)

	// Compute via StorageIndex + GetBinaryTreeKey
	treeIndex, suffix := StorageIndex(slot)
	var k [32]byte
	indexBytes := treeIndex.Bytes32()
	copy(k[:31], indexBytes[1:])
	k[31] = suffix
	expected := GetBinaryTreeKey(addr, k[:])

	if !bytes.Equal(binKey, expected) {
		t.Fatalf("GetBinaryTreeKeyStorageSlot result doesn't match StorageIndex+GetBinaryTreeKey\n  got:      %x\n  expected: %x", binKey, expected)
	}
}

func TestHeaderStorageSlot(t *testing.T) {
	addr := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")

	// Header storage: key[:31] all zeros, key[31] < 64
	slot := make([]byte, 32)
	slot[31] = 5 // slot 5 -> sub_index = 64 + 5 = 69

	key := GetBinaryTreeKeyStorageSlot(addr, slot)

	// Suffix should be 64 + 5 = 69
	if key[31] != 69 {
		t.Fatalf("header storage suffix should be 69, got %d", key[31])
	}
}
