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

// createBenchNativeSyscallsStateDB creates a StateDB for benchmarking.
func createBenchNativeSyscallsStateDB(b *testing.B) *state.StateDB {
	statedb, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		b.Fatalf("Failed to create state: %v", err)
	}
	return statedb
}

// BenchmarkBeaconBlockRoot_Native benchmarks the native Go implementation.
func BenchmarkBeaconBlockRoot_Native(b *testing.B) {
	beaconRoot := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statedb := createBenchNativeSyscallsStateDB(b)
		native_syscalls.ExecuteBeaconBlockRoot(statedb, beaconRoot, uint64(1700000000+i))
	}
}

// BenchmarkHistoryStorage_Native benchmarks the native Go implementation.
func BenchmarkHistoryStorage_Native(b *testing.B) {
	parentHash := common.HexToHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statedb := createBenchNativeSyscallsStateDB(b)
		native_syscalls.ExecuteHistoryStorage(statedb, parentHash, uint64(1000+i))
	}
}

// setupBenchWithdrawalQueueTest sets up a withdrawal queue with test entries for benchmarking.
func setupBenchWithdrawalQueueTest(statedb *state.StateDB, numEntries uint64) {
	addr := params.WithdrawalQueueAddress

	statedb.SetState(addr, uint64ToHashTest(testSlotQueueTail), uint64ToHashTest(numEntries))
	statedb.SetState(addr, uint64ToHashTest(testSlotCount), uint64ToHashTest(numEntries))

	for i := uint64(0); i < numEntries; i++ {
		baseSlot := testSlotQueueStart + i*testWithdrawalQueueEntrySlots

		var addrHash common.Hash
		addrHash[12] = byte(i + 1)
		addrHash[31] = byte(i + 1)
		statedb.SetState(addr, uint64ToHashTest(baseSlot), addrHash)

		var pubkey1 common.Hash
		for j := 0; j < 32; j++ {
			pubkey1[j] = byte(i + uint64(j))
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+1), pubkey1)

		var slot2 common.Hash
		for j := 0; j < 16; j++ {
			slot2[j] = byte(i + uint64(j) + 32)
		}
		slot2[30] = byte(i >> 8)
		slot2[31] = byte(i)
		statedb.SetState(addr, uint64ToHashTest(baseSlot+2), slot2)
	}
}

// BenchmarkWithdrawalQueue_Native_Full benchmarks the native Go implementation with a full queue (16 entries).
func BenchmarkWithdrawalQueue_Native_Full(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statedb := createBenchNativeSyscallsStateDB(b)
		setupBenchWithdrawalQueueTest(statedb, 16) // Max per block
		_ = native_syscalls.ExecuteWithdrawalQueue(statedb)
	}
}

// BenchmarkWithdrawalQueue_Native_Empty benchmarks with an empty queue.
func BenchmarkWithdrawalQueue_Native_Empty(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statedb := createBenchNativeSyscallsStateDB(b)
		_ = native_syscalls.ExecuteWithdrawalQueue(statedb)
	}
}

// setupBenchConsolidationQueueTest sets up a consolidation queue with test entries for benchmarking.
func setupBenchConsolidationQueueTest(statedb *state.StateDB, numEntries uint64) {
	addr := params.ConsolidationQueueAddress

	statedb.SetState(addr, uint64ToHashTest(testSlotQueueTail), uint64ToHashTest(numEntries))
	statedb.SetState(addr, uint64ToHashTest(testSlotCount), uint64ToHashTest(numEntries))

	for i := uint64(0); i < numEntries; i++ {
		baseSlot := testSlotQueueStart + i*testConsolidationQueueEntrySlots

		var addrHash common.Hash
		addrHash[12] = byte(i + 1)
		addrHash[31] = byte(i + 1)
		statedb.SetState(addr, uint64ToHashTest(baseSlot), addrHash)

		var pubkey1 common.Hash
		for j := 0; j < 32; j++ {
			pubkey1[j] = byte(i + uint64(j))
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+1), pubkey1)

		var slot2 common.Hash
		for j := 0; j < 32; j++ {
			slot2[j] = byte(i + uint64(j) + 32)
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+2), slot2)

		var slot3 common.Hash
		for j := 0; j < 32; j++ {
			slot3[j] = byte(i + uint64(j) + 64)
		}
		statedb.SetState(addr, uint64ToHashTest(baseSlot+3), slot3)
	}
}

// BenchmarkConsolidationQueue_Native_Full benchmarks the native Go implementation with a full queue (2 entries).
func BenchmarkConsolidationQueue_Native_Full(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statedb := createBenchNativeSyscallsStateDB(b)
		setupBenchConsolidationQueueTest(statedb, 2) // Max per block
		_ = native_syscalls.ExecuteConsolidationQueue(statedb)
	}
}

// BenchmarkConsolidationQueue_Native_Empty benchmarks with an empty queue.
func BenchmarkConsolidationQueue_Native_Empty(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		statedb := createBenchNativeSyscallsStateDB(b)
		_ = native_syscalls.ExecuteConsolidationQueue(statedb)
	}
}
