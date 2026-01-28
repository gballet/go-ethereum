// Copyright 2024 The go-ethereum Authors
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

package core

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/native_syscalls"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// Constants for tests (mirrored from native_syscalls package)
const (
	testSlotQueueHead                = 2
	testSlotQueueTail                = 3
	testSlotCount                    = 1
	testSlotQueueStart               = 4
	testWithdrawalQueueEntrySlots    = 3
	testConsolidationQueueEntrySlots = 4
)

// uint64ToHashTest converts a uint64 to a common.Hash for testing.
func uint64ToHashTest(v uint64) common.Hash {
	var h common.Hash
	for i := 0; i < 8; i++ {
		h[31-i] = byte(v >> (8 * i))
	}
	return h
}

// createNativeSyscallsTestStateDB creates a fresh StateDB for testing with
// system contracts properly initialized.
func createNativeSyscallsTestStateDB(t *testing.T) *state.StateDB {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("Failed to create state: %v", err)
	}

	// Deploy system contract code so accounts aren't deleted by Finalise(true)
	statedb.SetCode(params.BeaconRootsAddress, params.BeaconRootsCode, 0)
	statedb.SetCode(params.HistoryStorageAddress, params.HistoryStorageCode, 0)
	statedb.SetCode(params.WithdrawalQueueAddress, params.WithdrawalQueueCode, 0)
	statedb.SetCode(params.ConsolidationQueueAddress, params.ConsolidationQueueCode, 0)

	// Set nonces (required for contract accounts)
	statedb.SetNonce(params.BeaconRootsAddress, 1, 0)
	statedb.SetNonce(params.HistoryStorageAddress, 1, 0)
	statedb.SetNonce(params.WithdrawalQueueAddress, 1, 0)
	statedb.SetNonce(params.ConsolidationQueueAddress, 1, 0)

	return statedb
}

// TestBeaconBlockRoot_Native tests the native beacon block root implementation.
func TestBeaconBlockRoot_Native(t *testing.T) {
	testCases := []struct {
		name       string
		timestamp  uint64
		beaconRoot common.Hash
	}{
		{
			name:       "basic",
			timestamp:  1700000000,
			beaconRoot: common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
		},
		{
			name:       "zero_root",
			timestamp:  1700000001,
			beaconRoot: common.Hash{},
		},
		{
			name:       "max_slot",
			timestamp:  8190, // Near ring buffer boundary
			beaconRoot: common.HexToHash("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
		},
		{
			name:       "wrap_around",
			timestamp:  8192, // Wraps to slot 1
			beaconRoot: common.HexToHash("0xcafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"),
		},
		{
			name:       "large_timestamp",
			timestamp:  1800000000,
			beaconRoot: common.HexToHash("0xabababababababababababababababababababababababababababababababab"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statedb := createNativeSyscallsTestStateDB(t)

			// Execute native implementation
			native_syscalls.ExecuteBeaconBlockRoot(statedb, tc.beaconRoot, tc.timestamp)

			// Verify state
			timestampSlot := tc.timestamp % native_syscalls.RingBufferSize
			rootSlot := timestampSlot + native_syscalls.RingBufferSize

			// Check timestamp was stored
			storedTimestamp := statedb.GetState(params.BeaconRootsAddress, uint64ToHashTest(timestampSlot))
			expectedTimestamp := uint64ToHashTest(tc.timestamp)
			if storedTimestamp != expectedTimestamp {
				t.Errorf("Timestamp mismatch: got %x, want %x", storedTimestamp, expectedTimestamp)
			}

			// Check root was stored
			storedRoot := statedb.GetState(params.BeaconRootsAddress, uint64ToHashTest(rootSlot))
			if storedRoot != tc.beaconRoot {
				t.Errorf("Root mismatch: got %x, want %x", storedRoot, tc.beaconRoot)
			}
		})
	}
}

// TestHistoryStorage_Native tests the native history storage implementation.
func TestHistoryStorage_Native(t *testing.T) {
	testCases := []struct {
		name        string
		blockNumber uint64
		parentHash  common.Hash
	}{
		{
			name:        "basic",
			blockNumber: 1000,
			parentHash:  common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"),
		},
		{
			name:        "zero_hash",
			blockNumber: 1001,
			parentHash:  common.Hash{},
		},
		{
			name:        "near_boundary",
			blockNumber: 8192, // (8192-1) % 8191 = 0
			parentHash:  common.HexToHash("0x1111111111111111111111111111111111111111111111111111111111111111"),
		},
		{
			name:        "first_block",
			blockNumber: 1,
			parentHash:  common.HexToHash("0x2222222222222222222222222222222222222222222222222222222222222222"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statedb := createNativeSyscallsTestStateDB(t)

			// Execute native implementation
			native_syscalls.ExecuteHistoryStorage(statedb, tc.parentHash, tc.blockNumber)

			// Verify state
			slot := (tc.blockNumber - 1) % native_syscalls.RingBufferSize
			storedHash := statedb.GetState(params.HistoryStorageAddress, uint64ToHashTest(slot))
			if storedHash != tc.parentHash {
				t.Errorf("Parent hash mismatch: got %x, want %x", storedHash, tc.parentHash)
			}
		})
	}
}

// setupWithdrawalQueueTest sets up a withdrawal queue with test entries.
func setupWithdrawalQueueTest(statedb *state.StateDB, numEntries uint64) {
	addr := params.WithdrawalQueueAddress

	// Set queue tail (head starts at 0)
	statedb.SetState(addr, uint64ToHashTest(testSlotQueueTail), uint64ToHashTest(numEntries))

	// Set count
	statedb.SetState(addr, uint64ToHashTest(testSlotCount), uint64ToHashTest(numEntries))

	// Add queue entries
	for i := uint64(0); i < numEntries; i++ {
		baseSlot := testSlotQueueStart + i*testWithdrawalQueueEntrySlots

		// Source address (slot 0) - use a deterministic address based on index
		// Address is right-aligned in 32 bytes, so we set bytes 12-31
		var addrHash common.Hash
		addrHash[12] = byte(i + 1)
		addrHash[31] = byte(i + 1)
		statedb.SetState(addr, uint64ToHashTest(baseSlot), addrHash)

		// Pubkey[0:32] (slot 1)
		var pubkey1 common.Hash
		for j := 0; j < 32; j++ {
			pubkey1[j] = byte(i + uint64(j))
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+1), pubkey1)

		// Pubkey[32:48] + amount (slot 2)
		// Bytes 0-15: pubkey[32:48]
		// Bytes 16-23: amount (8 bytes, big-endian in storage)
		var slot2 common.Hash
		for j := 0; j < 16; j++ {
			slot2[j] = byte(i + uint64(j) + 32)
		}
		// Amount in bytes 16-23
		slot2[22] = byte(i >> 8)
		slot2[23] = byte(i)
		statedb.SetState(addr, uint64ToHashTest(baseSlot+2), slot2)
	}
}

// TestWithdrawalQueue_Native tests the native withdrawal queue implementation.
func TestWithdrawalQueue_Native(t *testing.T) {
	testCases := []struct {
		name            string
		numEntries      uint64
		expectedDequeue uint64
	}{
		{"empty_queue", 0, 0},
		{"single_entry", 1, 1},
		{"partial_dequeue", 5, 5},
		{"max_dequeue", 16, 16},
		{"overflow_dequeue", 20, 16}, // More than max per block, should only dequeue 16
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statedb := createNativeSyscallsTestStateDB(t)
			setupWithdrawalQueueTest(statedb, tc.numEntries)

			// Execute native implementation
			result := native_syscalls.ExecuteWithdrawalQueue(statedb)

			// Check result length
			expectedLen := tc.expectedDequeue * native_syscalls.WithdrawalRequestSize
			if uint64(len(result)) != expectedLen {
				t.Errorf("Result length mismatch: got %d, want %d", len(result), expectedLen)
			}

			// Verify queue state was updated
			addr := params.WithdrawalQueueAddress
			newHead := statedb.GetState(addr, uint64ToHashTest(testSlotQueueHead))

			if tc.expectedDequeue > 0 && tc.numEntries > tc.expectedDequeue {
				// Queue not empty, head should be updated
				expectedHead := uint64ToHashTest(tc.expectedDequeue)
				if newHead != expectedHead {
					t.Errorf("Queue head mismatch: got %x, want %x", newHead, expectedHead)
				}
			} else if tc.expectedDequeue > 0 && tc.numEntries == tc.expectedDequeue {
				// Queue emptied, head should be reset to 0
				if newHead != (common.Hash{}) {
					t.Errorf("Queue head should be reset to 0, got %x", newHead)
				}
			}

			// Verify serialized output format for non-empty results
			if tc.expectedDequeue > 0 && len(result) >= 76 {
				// Check first entry format: address (20) + pubkey (48) + amount (8)
				// Address bytes 0-19 come from slot0[12:32]
				// For i=0: addrHash[12]=1, addrHash[31]=1
				// So result[0]=1 (from addrHash[12]) and result[19]=1 (from addrHash[31])
				addrBytes := result[0:20]
				if addrBytes[0] != 1 || addrBytes[19] != 1 {
					t.Errorf("First address mismatch: got %x, want first byte=1 last byte=1", addrBytes)
				}
			}
		})
	}
}

// setupConsolidationQueueTest sets up a consolidation queue with test entries.
func setupConsolidationQueueTest(statedb *state.StateDB, numEntries uint64) {
	addr := params.ConsolidationQueueAddress

	// Set queue tail (head starts at 0)
	statedb.SetState(addr, uint64ToHashTest(testSlotQueueTail), uint64ToHashTest(numEntries))

	// Set count
	statedb.SetState(addr, uint64ToHashTest(testSlotCount), uint64ToHashTest(numEntries))

	// Add queue entries
	for i := uint64(0); i < numEntries; i++ {
		baseSlot := testSlotQueueStart + i*testConsolidationQueueEntrySlots

		// Source address (slot 0) - right-aligned in 32 bytes
		var addrHash common.Hash
		addrHash[12] = byte(i + 1)
		addrHash[31] = byte(i + 1)
		statedb.SetState(addr, uint64ToHashTest(baseSlot), addrHash)

		// Source pubkey[0:32] (slot 1)
		var pubkey1 common.Hash
		for j := 0; j < 32; j++ {
			pubkey1[j] = byte(i + uint64(j))
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+1), pubkey1)

		// Source pubkey[32:48] + target pubkey[0:16] (slot 2)
		var slot2 common.Hash
		for j := 0; j < 32; j++ {
			slot2[j] = byte(i + uint64(j) + 32)
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+2), slot2)

		// Target pubkey[16:48] (slot 3)
		var slot3 common.Hash
		for j := 0; j < 32; j++ {
			slot3[j] = byte(i + uint64(j) + 64)
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+3), slot3)
	}
}

// TestConsolidationQueue_Native tests the native consolidation queue implementation.
func TestConsolidationQueue_Native(t *testing.T) {
	testCases := []struct {
		name            string
		numEntries      uint64
		expectedDequeue uint64
	}{
		{"empty_queue", 0, 0},
		{"single_entry", 1, 1},
		{"max_dequeue", 2, 2},
		{"overflow_dequeue", 5, 2}, // More than max per block, should only dequeue 2
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statedb := createNativeSyscallsTestStateDB(t)
			setupConsolidationQueueTest(statedb, tc.numEntries)

			// Execute native implementation
			result := native_syscalls.ExecuteConsolidationQueue(statedb)

			// Check result length
			expectedLen := tc.expectedDequeue * native_syscalls.ConsolidationRequestSize
			if uint64(len(result)) != expectedLen {
				t.Errorf("Result length mismatch: got %d, want %d", len(result), expectedLen)
			}

			// Verify queue state was updated
			addr := params.ConsolidationQueueAddress
			newHead := statedb.GetState(addr, uint64ToHashTest(testSlotQueueHead))

			if tc.expectedDequeue > 0 && tc.numEntries > tc.expectedDequeue {
				// Queue not empty, head should be updated
				expectedHead := uint64ToHashTest(tc.expectedDequeue)
				if newHead != expectedHead {
					t.Errorf("Queue head mismatch: got %x, want %x", newHead, expectedHead)
				}
			} else if tc.expectedDequeue > 0 && tc.numEntries == tc.expectedDequeue {
				// Queue emptied, head should be reset to 0
				if newHead != (common.Hash{}) {
					t.Errorf("Queue head should be reset to 0, got %x", newHead)
				}
			}

			// Verify serialized output format for non-empty results
			if tc.expectedDequeue > 0 && len(result) >= 116 {
				// Check first entry format: address (20) + source pubkey (48) + target pubkey (48)
				// For i=0: addrHash[12]=1, addrHash[31]=1
				addrBytes := result[0:20]
				if addrBytes[0] != 1 || addrBytes[19] != 1 {
					t.Errorf("First address mismatch: got %x, want first byte=1 last byte=1", addrBytes)
				}
			}
		})
	}
}

// TestWithdrawalQueue_DataIntegrity verifies the serialized output matches input data.
func TestWithdrawalQueue_DataIntegrity(t *testing.T) {
	statedb := createNativeSyscallsTestStateDB(t)
	setupWithdrawalQueueTest(statedb, 3)

	result := native_syscalls.ExecuteWithdrawalQueue(statedb)

	// Should have 3 entries * 76 bytes = 228 bytes
	if len(result) != 228 {
		t.Fatalf("Expected 228 bytes, got %d", len(result))
	}

	// Verify each entry
	for i := uint64(0); i < 3; i++ {
		offset := i * 76

		// Check address (last byte should be i+1, first byte should also be i+1 due to addrHash[12])
		if result[offset] != byte(i+1) {
			t.Errorf("Entry %d: address first byte mismatch: got %d, want %d", i, result[offset], i+1)
		}
		if result[offset+19] != byte(i+1) {
			t.Errorf("Entry %d: address last byte mismatch: got %d, want %d", i, result[offset+19], i+1)
		}

		// Check pubkey first byte (should be byte(i))
		if result[offset+20] != byte(i) {
			t.Errorf("Entry %d: pubkey first byte mismatch: got %d, want %d", i, result[offset+20], i)
		}

		// Check amount (little-endian output, bytes 68-75)
		// For i=0: amount=0, for i=1: amount=1, for i=2: amount=2
		// In little-endian: [i, 0, 0, 0, 0, 0, 0, 0]
		if result[offset+68] != byte(i) {
			t.Errorf("Entry %d: amount first byte mismatch: got %d, want %d", i, result[offset+68], i)
		}
	}
}

// TestConsolidationQueue_DataIntegrity verifies the serialized output matches input data.
func TestConsolidationQueue_DataIntegrity(t *testing.T) {
	statedb := createNativeSyscallsTestStateDB(t)
	setupConsolidationQueueTest(statedb, 2)

	result := native_syscalls.ExecuteConsolidationQueue(statedb)

	// Should have 2 entries * 116 bytes = 232 bytes
	if len(result) != 232 {
		t.Fatalf("Expected 232 bytes, got %d", len(result))
	}

	// Verify each entry
	for i := uint64(0); i < 2; i++ {
		offset := i * 116

		// Check address (first and last bytes should be i+1)
		if result[offset] != byte(i+1) {
			t.Errorf("Entry %d: address first byte mismatch: got %d, want %d", i, result[offset], i+1)
		}
		if result[offset+19] != byte(i+1) {
			t.Errorf("Entry %d: address last byte mismatch: got %d, want %d", i, result[offset+19], i+1)
		}

		// Check source pubkey first byte (should be byte(i))
		if result[offset+20] != byte(i) {
			t.Errorf("Entry %d: source pubkey first byte mismatch: got %d, want %d", i, result[offset+20], i)
		}
	}
}

// TestWithdrawalQueue_ExcessCounter verifies the excess counter is updated correctly.
func TestWithdrawalQueue_ExcessCounter(t *testing.T) {
	testCases := []struct {
		name           string
		numEntries     uint64
		expectedExcess uint64
	}{
		{"below_target", 1, 0},                    // 1 < TARGET(2), excess = 0
		{"at_target", 2, 0},                       // 2 == TARGET(2), excess = 0
		{"above_target", 5, 3},                    // 5 - 2 = 3
		{"well_above_target", 20, 18},             // 20 - 2 = 18
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statedb := createNativeSyscallsTestStateDB(t)
			setupWithdrawalQueueTest(statedb, tc.numEntries)

			// Execute native implementation
			native_syscalls.ExecuteWithdrawalQueue(statedb)

			// Check excess counter
			excess := statedb.GetState(params.WithdrawalQueueAddress, uint64ToHashTest(0))
			expectedExcess := uint64ToHashTest(tc.expectedExcess)
			if excess != expectedExcess {
				t.Errorf("Excess mismatch: got %x, want %x", excess, expectedExcess)
			}

			// Count should be reset to 0
			count := statedb.GetState(params.WithdrawalQueueAddress, uint64ToHashTest(testSlotCount))
			if count != (common.Hash{}) {
				t.Errorf("Count should be reset to 0, got %x", count)
			}
		})
	}
}

// TestConsolidationQueue_ExcessCounter verifies the excess counter is updated correctly.
func TestConsolidationQueue_ExcessCounter(t *testing.T) {
	testCases := []struct {
		name           string
		numEntries     uint64
		expectedExcess uint64
	}{
		{"below_target", 0, 0},                    // 0 < TARGET(1), excess = 0
		{"at_target", 1, 0},                       // 1 == TARGET(1), excess = 0
		{"above_target", 3, 2},                    // 3 - 1 = 2
		{"well_above_target", 10, 9},              // 10 - 1 = 9
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			statedb := createNativeSyscallsTestStateDB(t)
			setupConsolidationQueueTest(statedb, tc.numEntries)

			// Execute native implementation
			native_syscalls.ExecuteConsolidationQueue(statedb)

			// Check excess counter
			excess := statedb.GetState(params.ConsolidationQueueAddress, uint64ToHashTest(0))
			expectedExcess := uint64ToHashTest(tc.expectedExcess)
			if excess != expectedExcess {
				t.Errorf("Excess mismatch: got %x, want %x", excess, expectedExcess)
			}

			// Count should be reset to 0
			count := statedb.GetState(params.ConsolidationQueueAddress, uint64ToHashTest(testSlotCount))
			if count != (common.Hash{}) {
				t.Errorf("Count should be reset to 0, got %x", count)
			}
		})
	}
}
