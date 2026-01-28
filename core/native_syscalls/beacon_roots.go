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

// ExecuteBeaconBlockRoot implements the EIP-4788 beacon block root storage contract natively.
//
// The contract stores beacon roots in a ring buffer:
//   - timestamp_slot = block.timestamp % 8191
//   - root_slot = timestamp_slot + 8191
//   - storage[timestamp_slot] = block.timestamp
//   - storage[root_slot] = beacon_root
//
// This allows later verification that a beacon root corresponds to the correct timestamp.
func ExecuteBeaconBlockRoot(statedb StateDB, beaconRoot common.Hash, timestamp uint64) {
	// Add address to access list for EIP-2929 compliance
	statedb.AddAddressToAccessList(params.BeaconRootsAddress)

	// Calculate ring buffer slots
	timestampSlot := timestamp % RingBufferSize
	rootSlot := timestampSlot + RingBufferSize

	// Store timestamp at timestamp_slot
	timestampKey := uint64ToHash(timestampSlot)
	timestampValue := uint64ToHash(timestamp)
	statedb.SetState(params.BeaconRootsAddress, timestampKey, timestampValue)

	// Store beacon root at root_slot
	rootKey := uint64ToHash(rootSlot)
	statedb.SetState(params.BeaconRootsAddress, rootKey, beaconRoot)

	// Finalize state changes
	statedb.Finalise(true)
}
