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

package arena

import "unsafe"

// BumpAllocator is a simple bump/arena allocator that sub-allocates from a
// pre-allocated byte slab. It is not thread-safe. All allocated memory is
// freed at once via Reset.
//
// Zeroing is performed lazily at allocation time (not on Reset), using a
// portable byte loop with no runtime dependencies.
type BumpAllocator struct {
	slab   []byte
	offset uintptr
}

// NewBumpAllocator creates a BumpAllocator backed by the given slab. The slab
// can be any []byte, including one backed by mmap'd memory.
func NewBumpAllocator(slab []byte) *BumpAllocator {
	return &BumpAllocator{slab: slab}
}

// RawAlloc returns a pointer to a zeroed region of at least `size` bytes,
// aligned to `align`, from the slab. It panics if the slab is exhausted.
func (b *BumpAllocator) RawAlloc(size, align uintptr) unsafe.Pointer {
	// Align the current offset up to the required alignment.
	aligned := (b.offset + align - 1) &^ (align - 1)
	end := aligned + size
	if end > uintptr(len(b.slab)) {
		panic("arena: bump allocator out of memory")
	}

	// Zero the region (portable, no runtime dependency).
	region := b.slab[aligned:end]
	for i := range region {
		region[i] = 0
	}

	b.offset = end
	return unsafe.Pointer(&b.slab[aligned])
}

// Reset rewinds the allocator to the beginning of the slab. Zeroing is
// deferred to the next RawAlloc call, so Reset is O(1).
func (b *BumpAllocator) Reset() {
	b.offset = 0
}

// Remaining returns the number of bytes left in the slab (before alignment).
func (b *BumpAllocator) Remaining() uintptr {
	return uintptr(len(b.slab)) - b.offset
}

// Used returns the number of bytes allocated so far.
func (b *BumpAllocator) Used() uintptr {
	return b.offset
}
