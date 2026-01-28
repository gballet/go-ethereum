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

// Fuzz tests for verifying equivalence between native Go implementations and
// EVM bytecode implementations of system contracts.
//
// These tests compare the behavior of:
//   - EIP-4788 Beacon Block Root Storage (params.BeaconRootsAddress)
//   - EIP-2935 History Storage (params.HistoryStorageAddress)
//   - EIP-7002 Withdrawal Queue (params.WithdrawalQueueAddress)
//   - EIP-7251 Consolidation Queue (params.ConsolidationQueueAddress)
//
// Each test creates two fresh StateDBs, executes the same operation via EVM and
// native implementations, then compares storage state and return values. Any
// divergence indicates a bug that needs investigation.
//
// Run with: go test -run=FuzzXxx -fuzz=FuzzXxx -fuzztime=30s ./core/

package core

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/native_syscalls"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
)

// createFuzzStateDB creates a fresh StateDB with system contracts deployed.
func createFuzzStateDB(t testing.TB) *state.StateDB {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatalf("Failed to create state: %v", err)
	}

	// Deploy all system contract code
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

// createFuzzEVM creates an EVM with proper chain config for system calls.
func createFuzzEVM(statedb *state.StateDB, nativeSyscalls bool, blockNumber uint64, timestamp uint64) *vm.EVM {
	// Chain config with all forks enabled for PUSH0 support
	chainConfig := &params.ChainConfig{
		ChainID:             big.NewInt(1),
		HomesteadBlock:      big.NewInt(0),
		EIP150Block:         big.NewInt(0),
		EIP155Block:         big.NewInt(0),
		EIP158Block:         big.NewInt(0),
		ByzantiumBlock:      big.NewInt(0),
		ConstantinopleBlock: big.NewInt(0),
		PetersburgBlock:     big.NewInt(0),
		IstanbulBlock:       big.NewInt(0),
		MuirGlacierBlock:    big.NewInt(0),
		BerlinBlock:         big.NewInt(0),
		LondonBlock:         big.NewInt(0),
		ArrowGlacierBlock:   big.NewInt(0),
		GrayGlacierBlock:    big.NewInt(0),
		MergeNetsplitBlock:  big.NewInt(0),
		ShanghaiTime:        u64ptr(0),
		CancunTime:          u64ptr(0),
		PragueTime:          u64ptr(0),
	}

	blockCtx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(n uint64) common.Hash { return common.Hash{} },
		Coinbase:    common.Address{},
		GasLimit:    30_000_000,
		BlockNumber: new(big.Int).SetUint64(blockNumber),
		Time:        timestamp,
		Difficulty:  big.NewInt(0),
		BaseFee:     big.NewInt(0),
		BlobBaseFee: big.NewInt(0),
		Random:      &common.Hash{},
	}

	vmConfig := vm.Config{
		NativeSystemCalls: nativeSyscalls,
	}

	return vm.NewEVM(blockCtx, statedb, chainConfig, vmConfig)
}

// u64ptr returns a pointer to a uint64.
func u64ptr(v uint64) *uint64 {
	return &v
}

// compareStorageSlots compares specific storage slots between two states.
func compareStorageSlots(t testing.TB, addr common.Address, s1, s2 *state.StateDB, slots []uint64) {
	for _, slot := range slots {
		key := uint64ToHashTest(slot)
		v1 := s1.GetState(addr, key)
		v2 := s2.GetState(addr, key)
		if v1 != v2 {
			t.Fatalf("slot %d mismatch at %s: EVM=%x, Native=%x", slot, addr.Hex(), v1, v2)
		}
	}
}

// FuzzBeaconBlockRoot_Equivalence tests EVM vs native beacon root storage.
// The beacon roots contract stores timestamp and root in a ring buffer:
//   - storage[timestamp % 8191] = timestamp
//   - storage[timestamp % 8191 + 8191] = beacon_root
func FuzzBeaconBlockRoot_Equivalence(f *testing.F) {
	// Add seed corpus with interesting values
	f.Add(uint64(1700000000), []byte{0x12, 0x34, 0x56, 0x78})
	f.Add(uint64(0), []byte{})
	f.Add(uint64(8190), []byte{0xde, 0xad, 0xbe, 0xef})  // Near ring buffer boundary
	f.Add(uint64(8191), []byte{0xff, 0xff, 0xff, 0xff})  // At boundary (wraps to 0)
	f.Add(uint64(8192), []byte{0xca, 0xfe, 0xba, 0xbe})  // Just past boundary (wraps to 1)
	f.Add(uint64(16382), []byte{0x11, 0x22, 0x33, 0x44}) // Second wrap
	f.Add(uint64(1<<32), []byte{0xaa, 0xbb, 0xcc, 0xdd}) // Large timestamp
	f.Add(uint64(1<<63-1), []byte{0x00, 0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, timestamp uint64, beaconRootBytes []byte) {
		// Convert []byte to [32]byte, padding or truncating as needed
		var beaconRoot common.Hash
		copy(beaconRoot[:], beaconRootBytes)

		// Create two identical states
		stateEVM := createFuzzStateDB(t)
		stateNative := createFuzzStateDB(t)

		// Execute EVM version
		evmEVM := createFuzzEVM(stateEVM, false, 1, timestamp)
		ProcessBeaconBlockRoot(beaconRoot, evmEVM)

		// Execute native version
		evmNative := createFuzzEVM(stateNative, true, 1, timestamp)
		ProcessBeaconBlockRoot(beaconRoot, evmNative)

		// Calculate expected slots
		timestampSlot := timestamp % native_syscalls.RingBufferSize
		rootSlot := timestampSlot + native_syscalls.RingBufferSize

		// Compare storage slots
		compareStorageSlots(t, params.BeaconRootsAddress, stateEVM, stateNative,
			[]uint64{timestampSlot, rootSlot})

		// Also verify the actual values are correct
		storedTimestamp := stateEVM.GetState(params.BeaconRootsAddress, uint64ToHashTest(timestampSlot))
		expectedTimestamp := uint64ToHashTest(timestamp)
		if storedTimestamp != expectedTimestamp {
			t.Fatalf("timestamp storage mismatch: got %x, want %x", storedTimestamp, expectedTimestamp)
		}

		storedRoot := stateEVM.GetState(params.BeaconRootsAddress, uint64ToHashTest(rootSlot))
		if storedRoot != beaconRoot {
			t.Fatalf("root storage mismatch: got %x, want %x", storedRoot, beaconRoot)
		}
	})
}

// FuzzHistoryStorage_Equivalence tests EVM vs native history storage.
// The history storage contract stores parent hash in a ring buffer:
//   - storage[(block_number - 1) % 8191] = parent_hash
func FuzzHistoryStorage_Equivalence(f *testing.F) {
	// Add seed corpus with interesting values
	f.Add(uint64(1), []byte{0xab, 0xcd, 0xef, 0x12})    // First block
	f.Add(uint64(1000), []byte{0x11, 0x22, 0x33, 0x44}) // Typical block
	f.Add(uint64(8191), []byte{0xde, 0xad, 0xbe, 0xef}) // At boundary (slot 8190)
	f.Add(uint64(8192), []byte{0xca, 0xfe, 0xba, 0xbe}) // Wraps to slot 0
	f.Add(uint64(8193), []byte{0xff, 0x00, 0xff, 0x00}) // Wraps to slot 1
	f.Add(uint64(16383), []byte{0xaa, 0xbb, 0xcc, 0xdd})
	f.Add(uint64(1<<32), []byte{0x99, 0x88, 0x77, 0x66})
	f.Add(uint64(1<<63-1), []byte{0x00, 0x00, 0x00, 0x01})

	f.Fuzz(func(t *testing.T, blockNumber uint64, parentHashBytes []byte) {
		// Block number 0 is invalid (genesis has no parent)
		if blockNumber == 0 {
			return
		}

		// Convert []byte to common.Hash
		var parentHash common.Hash
		copy(parentHash[:], parentHashBytes)

		// Create two identical states
		stateEVM := createFuzzStateDB(t)
		stateNative := createFuzzStateDB(t)

		// Execute EVM version
		evmEVM := createFuzzEVM(stateEVM, false, blockNumber, 1700000000)
		ProcessParentBlockHash(parentHash, evmEVM)

		// Execute native version
		evmNative := createFuzzEVM(stateNative, true, blockNumber, 1700000000)
		ProcessParentBlockHash(parentHash, evmNative)

		// Calculate expected slot
		slot := (blockNumber - 1) % native_syscalls.RingBufferSize

		// Compare storage slots
		compareStorageSlots(t, params.HistoryStorageAddress, stateEVM, stateNative, []uint64{slot})

		// Verify the actual value is correct
		storedHash := stateEVM.GetState(params.HistoryStorageAddress, uint64ToHashTest(slot))
		if storedHash != parentHash {
			t.Fatalf("parent hash storage mismatch: got %x, want %x", storedHash, parentHash)
		}
	})
}

// setupFuzzWithdrawalQueue sets up a withdrawal queue with the specified number of entries.
// Each entry uses deterministic data based on its index for reproducibility.
// This matches the storage layout expected by the EIP-7002 withdrawal queue contract.
func setupFuzzWithdrawalQueue(statedb *state.StateDB, numEntries uint64) {
	addr := params.WithdrawalQueueAddress

	// Set queue tail (head starts at 0)
	statedb.SetState(addr, uint64ToHashTest(testSlotQueueTail), uint64ToHashTest(numEntries))

	// Set count
	statedb.SetState(addr, uint64ToHashTest(testSlotCount), uint64ToHashTest(numEntries))

	// Add queue entries
	for i := uint64(0); i < numEntries; i++ {
		baseSlot := testSlotQueueStart + i*testWithdrawalQueueEntrySlots

		// Source address (slot 0) - use a deterministic address based on index
		// Address is right-aligned in 32 bytes
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
		// Bytes 16-23: amount (8 bytes, big-endian)
		var slot2 common.Hash
		for j := 0; j < 16; j++ {
			slot2[j] = byte(i + uint64(j) + 32)
		}
		// Amount in bytes 16-23 (small deterministic value)
		slot2[22] = byte(i >> 8)
		slot2[23] = byte(i)
		statedb.SetState(addr, uint64ToHashTest(baseSlot+2), slot2)
	}
}

// FuzzWithdrawalQueue_Equivalence tests EVM vs native withdrawal queue.
// The withdrawal queue dequeues up to 16 entries per block and returns them serialized.
func FuzzWithdrawalQueue_Equivalence(f *testing.F) {
	// Add seed corpus with interesting queue sizes
	f.Add(uint64(0))   // Empty queue
	f.Add(uint64(1))   // Single entry
	f.Add(uint64(5))   // Partial dequeue
	f.Add(uint64(15))  // Just under max
	f.Add(uint64(16))  // Exactly max per block
	f.Add(uint64(17))  // Just over max
	f.Add(uint64(32))  // Double max
	f.Add(uint64(50))  // Well over max

	f.Fuzz(func(t *testing.T, numEntries uint64) {
		// Cap to avoid slow tests
		if numEntries > 100 {
			numEntries = numEntries % 101
		}

		// Setup identical queues on both states
		stateEVM := createFuzzStateDB(t)
		stateNative := createFuzzStateDB(t)

		setupFuzzWithdrawalQueue(stateEVM, numEntries)
		setupFuzzWithdrawalQueue(stateNative, numEntries)

		// Execute EVM version
		var reqEVM [][]byte
		evmEVM := createFuzzEVM(stateEVM, false, 1, 1700000000)
		if err := ProcessWithdrawalQueue(&reqEVM, evmEVM); err != nil {
			t.Fatalf("EVM ProcessWithdrawalQueue failed: %v", err)
		}

		// Execute native version
		var reqNative [][]byte
		evmNative := createFuzzEVM(stateNative, true, 1, 1700000000)
		if err := ProcessWithdrawalQueue(&reqNative, evmNative); err != nil {
			t.Fatalf("Native ProcessWithdrawalQueue failed: %v", err)
		}

		// Compare return values
		if len(reqEVM) != len(reqNative) {
			t.Fatalf("request count mismatch: EVM=%d, Native=%d", len(reqEVM), len(reqNative))
		}

		for i := range reqEVM {
			if !bytes.Equal(reqEVM[i], reqNative[i]) {
				t.Fatalf("request %d mismatch:\n  EVM=%x\n  Native=%x", i, reqEVM[i], reqNative[i])
			}
		}

		// Compare queue state slots
		compareStorageSlots(t, params.WithdrawalQueueAddress, stateEVM, stateNative,
			[]uint64{
				native_syscalls.SlotExcess,
				native_syscalls.SlotCount,
				native_syscalls.SlotQueueHead,
				native_syscalls.SlotQueueTail,
			})
	})
}

// setupFuzzConsolidationQueue sets up a consolidation queue with the specified number of entries.
// Each entry uses deterministic data based on its index for reproducibility.
// This matches the storage layout expected by the EIP-7251 consolidation queue contract.
func setupFuzzConsolidationQueue(statedb *state.StateDB, numEntries uint64) {
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

// FuzzConsolidationQueue_Equivalence tests EVM vs native consolidation queue.
// The consolidation queue dequeues up to 2 entries per block and returns them serialized.
func FuzzConsolidationQueue_Equivalence(f *testing.F) {
	// Add seed corpus with interesting queue sizes
	f.Add(uint64(0))  // Empty queue
	f.Add(uint64(1))  // Single entry
	f.Add(uint64(2))  // Exactly max per block
	f.Add(uint64(3))  // Just over max
	f.Add(uint64(5))  // Multiple blocks worth
	f.Add(uint64(10)) // Well over max

	f.Fuzz(func(t *testing.T, numEntries uint64) {
		// Cap to avoid slow tests
		if numEntries > 50 {
			numEntries = numEntries % 51
		}

		// Setup identical queues on both states
		stateEVM := createFuzzStateDB(t)
		stateNative := createFuzzStateDB(t)

		setupFuzzConsolidationQueue(stateEVM, numEntries)
		setupFuzzConsolidationQueue(stateNative, numEntries)

		// Execute EVM version
		var reqEVM [][]byte
		evmEVM := createFuzzEVM(stateEVM, false, 1, 1700000000)
		if err := ProcessConsolidationQueue(&reqEVM, evmEVM); err != nil {
			t.Fatalf("EVM ProcessConsolidationQueue failed: %v", err)
		}

		// Execute native version
		var reqNative [][]byte
		evmNative := createFuzzEVM(stateNative, true, 1, 1700000000)
		if err := ProcessConsolidationQueue(&reqNative, evmNative); err != nil {
			t.Fatalf("Native ProcessConsolidationQueue failed: %v", err)
		}

		// Compare return values
		if len(reqEVM) != len(reqNative) {
			t.Fatalf("request count mismatch: EVM=%d, Native=%d", len(reqEVM), len(reqNative))
		}

		for i := range reqEVM {
			if !bytes.Equal(reqEVM[i], reqNative[i]) {
				t.Fatalf("request %d mismatch:\n  EVM=%x\n  Native=%x", i, reqEVM[i], reqNative[i])
			}
		}

		// Compare queue state slots
		compareStorageSlots(t, params.ConsolidationQueueAddress, stateEVM, stateNative,
			[]uint64{
				native_syscalls.SlotExcess,
				native_syscalls.SlotCount,
				native_syscalls.SlotQueueHead,
				native_syscalls.SlotQueueTail,
			})
	})
}

// FuzzBeaconBlockRoot_RingBufferCollisions tests that different timestamps mapping to
// the same ring buffer slot correctly overwrite each other.
func FuzzBeaconBlockRoot_RingBufferCollisions(f *testing.F) {
	// Pairs of timestamps that should map to the same slot
	f.Add(uint64(0), uint64(8191), []byte{0x11}, []byte{0x22})
	f.Add(uint64(1), uint64(8192), []byte{0x33}, []byte{0x44})
	f.Add(uint64(100), uint64(8291), []byte{0x55}, []byte{0x66})

	f.Fuzz(func(t *testing.T, ts1, ts2 uint64, root1Bytes, root2Bytes []byte) {
		// Ensure they map to the same slot
		if ts1%native_syscalls.RingBufferSize != ts2%native_syscalls.RingBufferSize {
			return
		}

		// Convert []byte to common.Hash
		var root1, root2 common.Hash
		copy(root1[:], root1Bytes)
		copy(root2[:], root2Bytes)

		// Test EVM version
		stateEVM := createFuzzStateDB(t)
		evmEVM := createFuzzEVM(stateEVM, false, 1, ts1)
		ProcessBeaconBlockRoot(root1, evmEVM)

		evmEVM.Context.Time = ts2
		ProcessBeaconBlockRoot(root2, evmEVM)

		// Test native version
		stateNative := createFuzzStateDB(t)
		evmNative := createFuzzEVM(stateNative, true, 1, ts1)
		ProcessBeaconBlockRoot(root1, evmNative)

		evmNative.Context.Time = ts2
		ProcessBeaconBlockRoot(root2, evmNative)

		// Compare storage - should have the second values
		slot := ts2 % native_syscalls.RingBufferSize
		rootSlot := slot + native_syscalls.RingBufferSize

		compareStorageSlots(t, params.BeaconRootsAddress, stateEVM, stateNative,
			[]uint64{slot, rootSlot})

		// Verify the latest values are stored
		storedTimestamp := stateEVM.GetState(params.BeaconRootsAddress, uint64ToHashTest(slot))
		expectedTimestamp := uint64ToHashTest(ts2)
		if storedTimestamp != expectedTimestamp {
			t.Fatalf("timestamp not overwritten correctly: got %x, want %x", storedTimestamp, expectedTimestamp)
		}

		storedRoot := stateEVM.GetState(params.BeaconRootsAddress, uint64ToHashTest(rootSlot))
		if storedRoot != root2 {
			t.Fatalf("root not overwritten correctly: got %x, want %x", storedRoot, root2)
		}
	})
}

// FuzzHistoryStorage_RingBufferCollisions tests that different block numbers mapping to
// the same ring buffer slot correctly overwrite each other.
func FuzzHistoryStorage_RingBufferCollisions(f *testing.F) {
	// Pairs of block numbers that should map to the same slot
	f.Add(uint64(1), uint64(8192), []byte{0x11}, []byte{0x22})
	f.Add(uint64(2), uint64(8193), []byte{0x33}, []byte{0x44})
	f.Add(uint64(100), uint64(8291), []byte{0x55}, []byte{0x66})

	f.Fuzz(func(t *testing.T, bn1, bn2 uint64, hash1Bytes, hash2Bytes []byte) {
		// Skip invalid block numbers
		if bn1 == 0 || bn2 == 0 {
			return
		}

		// Ensure they map to the same slot
		if (bn1-1)%native_syscalls.RingBufferSize != (bn2-1)%native_syscalls.RingBufferSize {
			return
		}

		// Convert []byte to common.Hash
		var hash1, hash2 common.Hash
		copy(hash1[:], hash1Bytes)
		copy(hash2[:], hash2Bytes)

		// Test EVM version
		stateEVM := createFuzzStateDB(t)
		evmEVM := createFuzzEVM(stateEVM, false, bn1, 1700000000)
		ProcessParentBlockHash(hash1, evmEVM)

		evmEVM.Context.BlockNumber = new(big.Int).SetUint64(bn2)
		ProcessParentBlockHash(hash2, evmEVM)

		// Test native version
		stateNative := createFuzzStateDB(t)
		evmNative := createFuzzEVM(stateNative, true, bn1, 1700000000)
		ProcessParentBlockHash(hash1, evmNative)

		evmNative.Context.BlockNumber = new(big.Int).SetUint64(bn2)
		ProcessParentBlockHash(hash2, evmNative)

		// Compare storage - should have the second value
		slot := (bn2 - 1) % native_syscalls.RingBufferSize

		compareStorageSlots(t, params.HistoryStorageAddress, stateEVM, stateNative, []uint64{slot})

		// Verify the latest value is stored
		storedHash := stateEVM.GetState(params.HistoryStorageAddress, uint64ToHashTest(slot))
		if storedHash != hash2 {
			t.Fatalf("hash not overwritten correctly: got %x, want %x", storedHash, hash2)
		}
	})
}

// FuzzWithdrawalQueue_PartialDequeue tests that partial dequeues work correctly
// when the queue has more entries than can be dequeued in one block.
func FuzzWithdrawalQueue_PartialDequeue(f *testing.F) {
	// Test various queue states after multiple dequeue operations
	f.Add(uint64(20), uint64(1)) // 20 entries, dequeue once
	f.Add(uint64(50), uint64(2)) // 50 entries, dequeue twice
	f.Add(uint64(32), uint64(2)) // 32 entries, dequeue twice (exactly empties queue)

	f.Fuzz(func(t *testing.T, numEntries uint64, numDequeues uint64) {
		// Cap values
		if numEntries > 100 {
			numEntries = numEntries % 101
		}
		if numDequeues > 10 {
			numDequeues = numDequeues % 11
		}
		if numDequeues == 0 {
			numDequeues = 1
		}

		// Setup identical queues
		stateEVM := createFuzzStateDB(t)
		stateNative := createFuzzStateDB(t)

		setupFuzzWithdrawalQueue(stateEVM, numEntries)
		setupFuzzWithdrawalQueue(stateNative, numEntries)

		evmEVM := createFuzzEVM(stateEVM, false, 1, 1700000000)
		evmNative := createFuzzEVM(stateNative, true, 1, 1700000000)

		// Perform multiple dequeue operations
		for i := uint64(0); i < numDequeues; i++ {
			var reqEVM, reqNative [][]byte

			if err := ProcessWithdrawalQueue(&reqEVM, evmEVM); err != nil {
				t.Fatalf("EVM ProcessWithdrawalQueue iteration %d failed: %v", i, err)
			}
			if err := ProcessWithdrawalQueue(&reqNative, evmNative); err != nil {
				t.Fatalf("Native ProcessWithdrawalQueue iteration %d failed: %v", i, err)
			}

			// Compare results
			if len(reqEVM) != len(reqNative) {
				t.Fatalf("iteration %d: request count mismatch: EVM=%d, Native=%d", i, len(reqEVM), len(reqNative))
			}

			for j := range reqEVM {
				if !bytes.Equal(reqEVM[j], reqNative[j]) {
					t.Fatalf("iteration %d, request %d mismatch", i, j)
				}
			}
		}

		// Compare final queue state
		compareStorageSlots(t, params.WithdrawalQueueAddress, stateEVM, stateNative,
			[]uint64{
				native_syscalls.SlotExcess,
				native_syscalls.SlotCount,
				native_syscalls.SlotQueueHead,
				native_syscalls.SlotQueueTail,
			})
	})
}

// FuzzConsolidationQueue_PartialDequeue tests that partial dequeues work correctly
// when the queue has more entries than can be dequeued in one block.
func FuzzConsolidationQueue_PartialDequeue(f *testing.F) {
	// Test various queue states after multiple dequeue operations
	f.Add(uint64(5), uint64(1))  // 5 entries, dequeue once
	f.Add(uint64(10), uint64(3)) // 10 entries, dequeue 3 times
	f.Add(uint64(6), uint64(3))  // 6 entries, dequeue 3 times (exactly empties queue)

	f.Fuzz(func(t *testing.T, numEntries uint64, numDequeues uint64) {
		// Cap values
		if numEntries > 50 {
			numEntries = numEntries % 51
		}
		if numDequeues > 10 {
			numDequeues = numDequeues % 11
		}
		if numDequeues == 0 {
			numDequeues = 1
		}

		// Setup identical queues
		stateEVM := createFuzzStateDB(t)
		stateNative := createFuzzStateDB(t)

		setupFuzzConsolidationQueue(stateEVM, numEntries)
		setupFuzzConsolidationQueue(stateNative, numEntries)

		evmEVM := createFuzzEVM(stateEVM, false, 1, 1700000000)
		evmNative := createFuzzEVM(stateNative, true, 1, 1700000000)

		// Perform multiple dequeue operations
		for i := uint64(0); i < numDequeues; i++ {
			var reqEVM, reqNative [][]byte

			if err := ProcessConsolidationQueue(&reqEVM, evmEVM); err != nil {
				t.Fatalf("EVM ProcessConsolidationQueue iteration %d failed: %v", i, err)
			}
			if err := ProcessConsolidationQueue(&reqNative, evmNative); err != nil {
				t.Fatalf("Native ProcessConsolidationQueue iteration %d failed: %v", i, err)
			}

			// Compare results
			if len(reqEVM) != len(reqNative) {
				t.Fatalf("iteration %d: request count mismatch: EVM=%d, Native=%d", i, len(reqEVM), len(reqNative))
			}

			for j := range reqEVM {
				if !bytes.Equal(reqEVM[j], reqNative[j]) {
					t.Fatalf("iteration %d, request %d mismatch", i, j)
				}
			}
		}

		// Compare final queue state
		compareStorageSlots(t, params.ConsolidationQueueAddress, stateEVM, stateNative,
			[]uint64{
				native_syscalls.SlotExcess,
				native_syscalls.SlotCount,
				native_syscalls.SlotQueueHead,
				native_syscalls.SlotQueueTail,
			})
	})
}
