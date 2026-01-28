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

// ExecuteWithdrawalQueue implements the EIP-7002 withdrawal queue contract natively.
//
// Storage layout:
//   - Slot 0: excess_withdrawals (for fee calculation)
//   - Slot 1: withdrawal_count
//   - Slot 2: queue_head
//   - Slot 3: queue_tail
//   - Slots 4+: queue entries (3 slots each)
//
// Each queue entry (3 slots):
//   - Slot 0: Source address (right-aligned in 32 bytes)
//   - Slot 1: Validator pubkey bytes 0-31
//   - Slot 2: Validator pubkey bytes 32-47 (bytes 0-15) + amount (bytes 16-23, big-endian)
//
// The system call dequeues up to 16 withdrawal requests per block and returns
// them serialized as 76 bytes each: [address(20) + pubkey(48) + amount(8)].
func ExecuteWithdrawalQueue(statedb StateDB) []byte {
	addr := params.WithdrawalQueueAddress

	// Add address to access list for EIP-2929 compliance
	statedb.AddAddressToAccessList(addr)

	// Update excess counter (must be done before dequeuing per EIP-7002)
	// Formula: new_excess = max(0, previous_excess + count - TARGET)
	previousExcess := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotExcess)))
	count := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotCount)))
	var newExcess uint64
	if previousExcess+count > TargetWithdrawalsPerBlock {
		newExcess = previousExcess + count - TargetWithdrawalsPerBlock
	}
	statedb.SetState(addr, uint64ToHash(SlotExcess), uint64ToHash(newExcess))

	// Read queue head and tail
	head := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotQueueHead)))
	tail := hashToUint64(statedb.GetState(addr, uint64ToHash(SlotQueueTail)))

	// Calculate number of items to dequeue
	queueLen := tail - head
	numToDequeue := queueLen
	if numToDequeue > MaxWithdrawalsPerBlock {
		numToDequeue = MaxWithdrawalsPerBlock
	}

	if numToDequeue == 0 {
		statedb.Finalise(true)
		return nil
	}

	// Allocate result buffer
	result := make([]byte, numToDequeue*WithdrawalRequestSize)

	// Dequeue items
	for i := uint64(0); i < numToDequeue; i++ {
		entryIndex := head + i
		baseSlot := SlotQueueStart + entryIndex*WithdrawalQueueEntrySlots

		// Read entry slots
		slot0 := statedb.GetState(addr, uint64ToHash(baseSlot))     // address
		slot1 := statedb.GetState(addr, uint64ToHash(baseSlot+1))   // pubkey[0:32]
		slot2 := statedb.GetState(addr, uint64ToHash(baseSlot+2))   // pubkey[32:48] + amount

		// Extract and serialize: address (20 bytes)
		offset := i * WithdrawalRequestSize
		copy(result[offset:offset+20], slot0[12:32]) // address is right-aligned

		// Pubkey bytes 0-31
		copy(result[offset+20:offset+52], slot1[:])

		// Pubkey bytes 32-47 (first 16 bytes of slot2)
		copy(result[offset+52:offset+68], slot2[0:16])

		// Amount (8 bytes from slot2 bytes 16-23, output as little-endian per EIP-7002)
		// Storage is big-endian, but EIP specifies little-endian output
		for j := uint64(0); j < 8; j++ {
			result[offset+68+j] = slot2[23-j]
		}
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
