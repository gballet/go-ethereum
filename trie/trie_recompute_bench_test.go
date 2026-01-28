// Copyright 2025 The go-ethereum Authors
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

package trie

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/core/rawdb"
)

// BenchmarkTrieRecomputeDepths benchmarks the time to compute the hash of tries
// with various numbers of entries, ranging from 16^0 to 16^6.
func BenchmarkTrieRecomputeDepths(b *testing.B) {
	// Test different powers of 16
	// 16^0=1, 16^1=16, 16^2=256, 16^3=4096, 16^4=65536, 16^5=1048576, 16^6=16777216
	powers := []struct {
		power int
		size  int
	}{
		{0, 1},
		{1, 16},
		{2, 256},
		{3, 4096},
		{4, 65536},
		{5, 1048576},
		{6, 16777216},
	}

	for _, p := range powers {
		// Run initial hash computation benchmark
		b.Run(fmt.Sprintf("InitialHash_16^%d", p.power), func(b *testing.B) {
			benchmarkInitialHash(b, p.size)
		})

		// Run recomputation benchmark after modifications
		b.Run(fmt.Sprintf("Recompute_16^%d", p.power), func(b *testing.B) {
			benchmarkRecompute(b, p.size)
		})
	}
}

// benchmarkInitialHash measures the time to compute the initial hash of a fresh trie
func benchmarkInitialHash(b *testing.B, numEntries int) {
	// Generate random key-value pairs
	keys := make([][]byte, numEntries)
	values := make([][]byte, numEntries)

	for i := 0; i < numEntries; i++ {
		// Use 32-byte keys and values (standard Ethereum size)
		keys[i] = make([]byte, 32)
		values[i] = make([]byte, 32)

		if _, err := rand.Read(keys[i]); err != nil {
			b.Fatalf("Failed to generate random key: %v", err)
		}
		if _, err := rand.Read(values[i]); err != nil {
			b.Fatalf("Failed to generate random value: %v", err)
		}
	}

	// Reset timer before the measured operations
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Create a fresh trie for each iteration
		db := newTestDatabase(rawdb.NewMemoryDatabase(), rawdb.HashScheme)
		trie := NewEmpty(db)

		// Insert all key-value pairs
		for j := 0; j < numEntries; j++ {
			trie.MustUpdate(keys[j], values[j])
		}

		b.StartTimer()

		// Measure the time to compute the hash
		trie.Hash()
	}
}

// benchmarkRecompute measures the time to recompute the hash after modifying some entries
func benchmarkRecompute(b *testing.B, numEntries int) {
	// Generate random key-value pairs
	keys := make([][]byte, numEntries)
	values := make([][]byte, numEntries)

	for i := 0; i < numEntries; i++ {
		keys[i] = make([]byte, 32)
		values[i] = make([]byte, 32)

		if _, err := rand.Read(keys[i]); err != nil {
			b.Fatalf("Failed to generate random key: %v", err)
		}
		if _, err := rand.Read(values[i]); err != nil {
			b.Fatalf("Failed to generate random value: %v", err)
		}
	}

	// Setup: Create and populate the trie
	db := newTestDatabase(rawdb.NewMemoryDatabase(), rawdb.HashScheme)
	trie := NewEmpty(db)

	for i := 0; i < numEntries; i++ {
		trie.MustUpdate(keys[i], values[i])
	}

	// Compute initial hash
	trie.Hash()

	// Prepare modified values for recomputation
	// Modify approximately 10% of entries (minimum 1)
	numModifications := numEntries / 10
	if numModifications < 1 {
		numModifications = 1
	}

	modifiedValues := make([][]byte, numModifications)
	for i := 0; i < numModifications; i++ {
		modifiedValues[i] = make([]byte, 32)
		if _, err := rand.Read(modifiedValues[i]); err != nil {
			b.Fatalf("Failed to generate random value: %v", err)
		}
	}

	// Reset timer before the measured operations
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		// Modify some entries
		for j := 0; j < numModifications; j++ {
			trie.MustUpdate(keys[j], modifiedValues[j])
		}

		b.StartTimer()

		// Measure the time to recompute the hash
		trie.Hash()

		b.StopTimer()

		// Restore original values for next iteration
		for j := 0; j < numModifications; j++ {
			trie.MustUpdate(keys[j], values[j])
		}
	}
}

// BenchmarkTrieRecomputeMemory provides memory statistics for tries of various sizes
func BenchmarkTrieRecomputeMemory(b *testing.B) {
	powers := []struct {
		power int
		size  int
	}{
		{0, 1},
		{1, 16},
		{2, 256},
		{3, 4096},
		{4, 65536},
		{5, 1048576},
		{6, 16777216},
	}

	for _, p := range powers {
		b.Run(fmt.Sprintf("Memory_16^%d", p.power), func(b *testing.B) {
			// Generate random key-value pairs
			keys := make([][]byte, p.size)
			values := make([][]byte, p.size)

			for i := 0; i < p.size; i++ {
				keys[i] = make([]byte, 32)
				values[i] = make([]byte, 32)

				if _, err := rand.Read(keys[i]); err != nil {
					b.Fatalf("Failed to generate random key: %v", err)
				}
				if _, err := rand.Read(values[i]); err != nil {
					b.Fatalf("Failed to generate random value: %v", err)
				}
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Create a fresh trie
				db := newTestDatabase(rawdb.NewMemoryDatabase(), rawdb.HashScheme)
				trie := NewEmpty(db)

				// Insert all key-value pairs
				for j := 0; j < p.size; j++ {
					trie.MustUpdate(keys[j], values[j])
				}

				// Compute the hash to build the complete trie
				trie.Hash()
			}
		})
	}
}