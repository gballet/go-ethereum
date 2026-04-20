// Copyright 2026 The go-ethereum Authors
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

package overlay

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/params"
)

type StateDB interface {
	SetCode(addr common.Address, code []byte, change tracing.CodeChangeReason) []byte
	SetNonce(addr common.Address, nonce uint64, change tracing.NonceChangeReason)
	SetState(addr common.Address, key, value common.Hash) common.Hash
}

var transitionStatusByteCode []byte = []byte{
	0x60, 0x00, // PUSH1 <calldata offset>
	0x35,       // CALLDATALOAD
	0x54,       // SLOAD
	0x60, 0x00, // PUSH1 <mem dest>
	0x52,       // MSTORE
	0x60, 0x20, // PUSH1 <return size>
	0x60, 0x00, // PUSH1 <return offset>
	0xf3, // RETURN
}

func InitializeBinaryTransitionRegistry(statedb StateDB) {
	// The address is a placeholder, so until the EIP gets CFId, just deploy the code when the transition
	// is detected.
	statedb.SetCode(params.BinaryTransitionRegistryAddress, transitionStatusByteCode, tracing.CodeChangeUnspecified)
	statedb.SetNonce(params.BinaryTransitionRegistryAddress, 1, tracing.NonceChangeUnspecified)
	statedb.SetState(params.BinaryTransitionRegistryAddress, common.Hash{}, common.Hash{1})
}
