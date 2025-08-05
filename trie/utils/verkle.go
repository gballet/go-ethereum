// Copyright 2021 go-ethereum Authors
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

package utils

import (
	"bytes"
	"crypto/sha256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-verkle"
	"github.com/holiman/uint256"
)

const (
	BasicDataLeafKey = 0
	CodeHashLeafKey  = 1

	BasicDataVersionOffset  = 0
	BasicDataCodeSizeOffset = 5
	BasicDataNonceOffset    = 8
	BasicDataBalanceOffset  = 16

	maxPointCacheByteSize = 100 << 20
)

var (
	zero                                [32]byte
	VerkleNodeWidthLog2                 = 8
	HeaderStorageOffset                 = uint256.NewInt(64)
	mainStorageOffsetLshVerkleNodeWidth = new(uint256.Int).Lsh(uint256.NewInt(1), 248-uint(VerkleNodeWidthLog2))
	CodeOffset                          = uint256.NewInt(128)
	MainStorageOffset                   = new(uint256.Int).Lsh(uint256.NewInt(1), 248 /* 8 * 31*/)
	VerkleNodeWidth                     = uint256.NewInt(256)
	codeStorageDelta                    = uint256.NewInt(0).Sub(CodeOffset, HeaderStorageOffset)

	getTreePolyIndex0Point *verkle.Point
)

func GetTreeKey(addr common.Address, key []byte) []byte {
	hasher := sha256.New()
	hasher.Write(zero[:12])
	hasher.Write(addr[:])
	k := hasher.Sum(key[:31])
	k[31] = key[31]
	return k
}

func GetTreeKeyCodeHash(addr common.Address) []byte {
	var k [32]byte
	k[31] = CodeHashLeafKey
	return GetTreeKey(addr, k[:])
}

func GetTreeKeyStorageSlot(address common.Address, key []byte) []byte {
	var k [32]byte

	// Case when the key belongs to the account header
	if bytes.Equal(key[:31], zero[:31]) && key[31] < 64 {
		k[31] = 64 + key[31]
		return GetTreeKey(address, k[:])
	}

	// Set the main storage offset
	// note that the first 64 bytes of the main offset storage
	// are unreachable, which is consistent with the spec and
	// what verkle does.
	k[0] = 1 // 1 << 248
	copy(k[1:], key[:31])
	k[31] = key[31]

	return GetTreeKey(address, k[:])
}

func GetTreeKeyCodeChunk(address common.Address, chunknr *uint256.Int) []byte {
	chunkOffset := new(uint256.Int).Add(CodeOffset, chunknr).Bytes()
	return GetTreeKey(address, chunkOffset)
}
