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

//go:build zisk

package main

import "unsafe"

// ziskInputAddr is where the ZisK zkVM maps the program input: an 8-byte
// little-endian length followed by the data. The 8 bytes before it are the
// free-input register, not part of the input.
const ziskInputAddr uintptr = 0x40000008

// getInput returns the RLP-encoded payload from the ZisK input region, without
// copying it.
func getInput() []byte {
	length := *(*uint64)(unsafe.Pointer(ziskInputAddr))
	return unsafe.Slice((*byte)(unsafe.Pointer(ziskInputAddr+8)), length)
}
