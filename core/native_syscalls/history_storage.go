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

// ExecuteHistoryStorage implements the EIP-2935 history storage contract natively.
//
// The contract stores parent block hashes in a ring buffer:
//   - slot = (block_number - 1) % 8191
//   - storage[slot] = parent_hash
//
// This allows blocks to access historical block hashes beyond the default 256-block limit.
func ExecuteHistoryStorage(statedb StateDB, parentHash common.Hash, blockNumber uint64) {
	// Add address to access list for EIP-2929 compliance
	statedb.AddAddressToAccessList(params.HistoryStorageAddress)

	// Calculate ring buffer slot using (block_number - 1) to get parent's position
	slot := (blockNumber - 1) % RingBufferSize

	// Store parent hash at calculated slot
	slotKey := uint64ToHash(slot)
	statedb.SetState(params.HistoryStorageAddress, slotKey, parentHash)

	// Finalize state changes
	statedb.Finalise(true)
}
