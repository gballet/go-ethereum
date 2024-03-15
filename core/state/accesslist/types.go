// Copyright 2020 The go-ethereum Authors
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

package accesslist

// AccessType specifies if a state access is for reading or writing. This
// is necessary because verkle charges different costs depending on the
// type of access.
type AccessType bool

var (
	AccessListRead  = AccessType(false)
	AccessListWrite = AccessType(true)
)

// ItemType is used in verkle mode to specify what item of an account
// is being accessed. This is necessary because verkle charges gas each
// time a new account item is accessed.
type ItemType uint64

const (
	Version = ItemType(1 << iota)
	Balance
	Nonce
	CodeHash
	CodeSize
	LastHeaderItem
)

const ALAllItems = Version | Balance | Nonce | CodeSize | CodeHash
const ALNoItems = ItemType(0)
