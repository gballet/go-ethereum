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

package native_syscalls

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// ExecuteConsolidationQueue implements the EIP-7251 consolidation queue contract natively.
//
// Storage layout:
//   - Slot 0: excess_consolidations (for fee calculation)
//   - Slot 1: consolidation_count
//   - Slot 2: queue_head
//   - Slot 3: queue_tail
//   - Slots 4+: queue entries (4 slots each)
//
// Each queue entry (4 slots):
//   - Slot 0: Source address (right-aligned in 32 bytes)
//   - Slot 1: Source pubkey bytes 0-31
//   - Slot 2: Source pubkey bytes 32-47 (16 bytes) + Target pubkey bytes 0-15 (16 bytes)
//   - Slot 3: Target pubkey bytes 16-47 (32 bytes)
//
// The system call dequeues up to 2 consolidation requests per block and returns
// them serialized as 116 bytes each: [source_address(20) + source_pubkey(48) + target_pubkey(48)].
func ExecuteConsolidationQueue(statedb StateDB) []byte {
	addr := params.ConsolidationQueueAddress

	// Add address to access list for EIP-2929 compliance
	statedb.AddAddressToAccessList(addr)

	// Update excess counter (must be done before dequeuing per EIP-7251)
	// Formula: new_excess = max(0, previous_excess + count - TARGET)
	previousExcess := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotExcess)))
	count := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotCount)))
	var newExcess uint64
	if previousExcess+count > TargetConsolidationsPerBlock {
		newExcess = previousExcess + count - TargetConsolidationsPerBlock
	}
	statedb.SetState(addr, uint64ToHash(SlotExcess), uint64ToHash(newExcess))

	// Read queue head and tail
	head := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotQueueHead)))
	tail := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotQueueTail)))

	// Calculate number of items to dequeue
	queueLen := tail - head
	numToDequeue := queueLen
	if numToDequeue > MaxConsolidationsPerBlock {
		numToDequeue = MaxConsolidationsPerBlock
	}

	if numToDequeue == 0 {
		statedb.Finalise(true)
		return nil
	}

	// Allocate result buffer
	result := make([]byte, numToDequeue*ConsolidationRequestSize)

	// Dequeue items
	for i := uint64(0); i < numToDequeue; i++ {
		entryIndex := head + i
		baseSlot := SlotQueueStart + entryIndex*ConsolidationQueueEntrySlots

		// Read entry slots
		slot0 := statedb.GetState(addr, uint64ToHash(baseSlot))     // source address
		slot1 := statedb.GetState(addr, uint64ToHash(baseSlot+1))   // source pubkey[0:32]
		slot2 := statedb.GetState(addr, uint64ToHash(baseSlot+2))   // source pubkey[32:48] + target pubkey[0:16]
		slot3 := statedb.GetState(addr, uint64ToHash(baseSlot+3))   // target pubkey[16:48]

		// Extract and serialize
		offset := i * ConsolidationRequestSize

		// Source address (20 bytes, right-aligned in slot0)
		copy(result[offset:offset+20], slot0[12:32])

		// Source pubkey bytes 0-31
		copy(result[offset+20:offset+52], slot1[:])

		// Source pubkey bytes 32-47 (first 16 bytes of slot2)
		copy(result[offset+52:offset+68], slot2[0:16])

		// Target pubkey bytes 0-15 (last 16 bytes of slot2)
		copy(result[offset+68:offset+84], slot2[16:32])

		// Target pubkey bytes 16-47 (slot3)
		copy(result[offset+84:offset+116], slot3[:])
	}

	// Update queue head
	newHead := head + numToDequeue
	statedb.SetState(addr, uint64ToHash(SlotQueueHead), uint64ToHash(newHead))

	// If queue is now empty, reset head and tail to 0
	if newHead == tail {
		statedb.SetState(addr, uint64ToHash(SlotQueueHead), common.Hash{})
		statedb.SetState(addr, uint64ToHash(SlotQueueTail), common.Hash{})
	}

	// Reset count to 0 (count is used for fee calculation, reset after each block)
	statedb.SetState(addr, uint64ToHash(SlotCount), common.Hash{})

	statedb.Finalise(true)
	return result
}
