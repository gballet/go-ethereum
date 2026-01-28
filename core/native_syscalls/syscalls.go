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

// Package native_syscalls provides native Go implementations of EVM system contracts.
// These implementations bypass EVM interpretation overhead for performance benchmarking.
package native_syscalls

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// RingBufferSize is the size of the ring buffer used by beacon roots and history storage.
// This is 8191 (0x1fff) as specified in EIP-4788 and EIP-2935.
const RingBufferSize = 8191

// Storage slot indices for queue contracts (EIP-7002 and EIP-7251)
const (
	SlotExcess      = 0 // Storage slot for excess requests (used in fee calculation)
	SlotCount       = 1 // Storage slot for request count
	SlotQueueHead   = 2 // Storage slot for queue head pointer
	SlotQueueTail   = 3 // Storage slot for queue tail pointer
	SlotQueueStart  = 4 // First storage slot for queue entries
)

// Queue limits per block
const (
	MaxWithdrawalsPerBlock     = 16 // Maximum withdrawal requests dequeued per block (EIP-7002)
	MaxConsolidationsPerBlock  = 2  // Maximum consolidation requests dequeued per block (EIP-7251)
)

// Target requests per block (for excess calculation)
const (
	TargetWithdrawalsPerBlock    = 2 // Target withdrawal requests per block (EIP-7002)
	TargetConsolidationsPerBlock = 1 // Target consolidation requests per block (EIP-7251)
)

// Request sizes in bytes
const (
	WithdrawalRequestSize    = 76  // 20 (address) + 48 (pubkey) + 8 (amount)
	ConsolidationRequestSize = 116 // 20 (source addr) + 48 (source pubkey) + 48 (target pubkey)
)

// Queue entry sizes in storage slots
const (
	WithdrawalQueueEntrySlots    = 3 // Each withdrawal entry uses 3 storage slots
	ConsolidationQueueEntrySlots = 4 // Each consolidation entry uses 4 storage slots
)

// StateDB is a minimal interface for state access needed by native syscalls.
// This mirrors the essential methods from vm.StateDB.
type StateDB interface {
	GetState(addr common.Address, key common.Hash) common.Hash
	SetState(addr common.Address, key common.Hash, value common.Hash) common.Hash
	AddAddressToAccessList(addr common.Address)
	Finalise(deleteEmptyObjects bool)
}

// uint64ToHash converts a uint64 to a common.Hash (32-byte big-endian).
func uint64ToHash(v uint64) common.Hash {
	u := uint256.NewInt(v)
	return u.Bytes32()
}

// hashToUint64 converts a common.Hash to uint64 (reading big-endian).
func hashToUint64(h common.Hash) uint64 {
	var u uint256.Int
	u.SetBytes(h[:])
	return u.Uint64()
}
