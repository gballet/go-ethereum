// Copyright 2022 go-ethereum Authors
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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"runtime"
	"sync"
	"testing"

	"github.com/gballet/go-verkle"
	"github.com/holiman/uint256"
)

func TestGetTreeKey(t *testing.T) {
	var addr [32]byte
	for i := 0; i < 16; i++ {
		addr[1+2*i] = 0xff
	}
	n := uint256.NewInt(1)
	n = n.Lsh(n, 129)
	n.Add(n, uint256.NewInt(3))
	tk := GetTreeKey(addr[:], n, 1)

	got := hex.EncodeToString(tk)
	exp := "f42f932f43faf5d14b292b9009c45c28da61dbf66e20dbedc2e02dfd64ff5a01"
	if got != exp {
		t.Fatalf("Generated trie key is incorrect: %s != %s", got, exp)
	}
}

func TestPedersenHashDistribution(t *testing.T) {
	maxRoutines := runtime.NumCPU()
	histogramBuckets := make([]map[byte]int64, maxRoutines)

	const numIterations = 1_000_000
	fmt.Printf("Generating...\n")
	var wg sync.WaitGroup
	for i := 0; i < maxRoutines; i++ {
		wg.Add(1)
		go func(buckNum int) {
			defer wg.Done()

			histogramBuckets[buckNum] = make(map[byte]int64, 256)
			rseed := rand.NewSource(int64(buckNum + 42))
			r := rand.New(rseed)

			var randTreeIndex uint256.Int
			var randAddr [32]byte
			for i := 0; i < numIterations; i++ {
				r.Read(randAddr[:]) // Read 32 bytes (guaranteed) to generate rand tree index.
				randTreeIndex.SetBytes(randAddr[:])
				r.Read(randAddr[:])                               // Guaranteed to read 32 bytes, to have rand addr.
				key := GetTreeKey(randAddr[:], &randTreeIndex, 0) // subIndex is irrelevant.

				for i := 0; i < 256; i++ {
					bit := (key[i/8] >> (i % 8)) & 1
					histogramBuckets[buckNum][byte(i)] += int64(bit) // No concurrent access, so it's safe (and fast).
				}
			}
		}(i)
	}
	wg.Wait()

	fmt.Printf("Aggregating...\n")
	histogram := make(map[byte]int64, 256-8)
	for i := range histogramBuckets {
		for bn, count := range histogramBuckets[i] {
			histogram[bn] += count
		}
	}

	expCountPerBit := int64(numIterations * maxRoutines / 2)
	for i := 0; i < 256-8; i++ {
		fmt.Printf("Bit %d: %d (deviation from expected %.02f%%)\n", i, histogram[byte(i)], float64(histogram[byte(i)]-expCountPerBit)/float64(expCountPerBit)*100)
	}
}

func TestConstantPoint(t *testing.T) {
	var expectedPoly [1]verkle.Fr

	cfg := verkle.GetConfig()
	verkle.FromLEBytes(&expectedPoly[0], []byte{2, 64})
	expected := cfg.CommitToPoly(expectedPoly[:], 1)

	if !verkle.Equal(expected, getTreePolyIndex0Point) {
		t.Fatalf("Marshalled constant value is incorrect: %x != %x", expected.Bytes(), getTreePolyIndex0Point.Bytes())
	}
}

func BenchmarkPedersenHash(b *testing.B) {
	var addr, v [32]byte

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rand.Read(v[:])
		rand.Read(addr[:])
		GetTreeKeyCodeSize(addr[:])
	}
}

func sha256GetTreeKeyCodeSize(addr []byte) []byte {
	digest := sha256.New()
	digest.Write(addr)
	treeIndexBytes := new(big.Int).Bytes()
	var payload [32]byte
	copy(payload[:len(treeIndexBytes)], treeIndexBytes)
	digest.Write(payload[:])
	h := digest.Sum(nil)
	h[31] = CodeKeccakLeafKey
	return h
}

func BenchmarkSha256Hash(b *testing.B) {
	var addr, v [32]byte

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		rand.Read(v[:])
		rand.Read(addr[:])
		sha256GetTreeKeyCodeSize(addr[:])
	}
}
