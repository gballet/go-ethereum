// Copyright 2026 go-ethereum Authors
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

package archive

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// resetArchiveState drops the cached file handle and semaphore so the next
// resolver call reopens against the current ArchiveDataDir / ArchiveReadConcurrency.
func resetArchiveState() {
	archiveMu.Lock()
	if archiveFile != nil {
		archiveFile.Close()
		archiveFile = nil
	}
	archivePath = ""
	coldReadSem = nil
	archiveMu.Unlock()
}

func recordsEqual(got, want []*Record) error {
	if len(got) != len(want) {
		return fmt.Errorf("got %d records, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].Path, want[i].Path) || !bytes.Equal(got[i].Value, want[i].Value) {
			return fmt.Errorf("record %d mismatch: got {%x,%x} want {%x,%x}",
				i, got[i].Path, got[i].Value, want[i].Path, want[i].Value)
		}
	}
	return nil
}

// TestArchivedNodeResolverConcurrencyCap verifies the two properties the cold-read
// fix relies on:
//
//  1. Correctness under concurrency: many goroutines resolving simultaneously all
//     get byte-correct records back (handle is read via positioned ReadAt, safe
//     for parallel use).
//  2. The semaphore caps simultaneous archive reads at ArchiveReadConcurrency even
//     when the fan-out (2000) is far larger than the cap (8). This is the property
//     that prevents OS-thread exhaustion on cold blocks: without it, every caller
//     would block in pread at once and pin a thread.
//
// Run with -race to also assert the cached handle + semaphore are data-race free.
func TestArchivedNodeResolverConcurrencyCap(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "geth"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(dir, "geth", "nodearchive")

	w, err := NewArchiveWriter(path)
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	// Write a set of distinct subtrees; remember each one's (offset,size) and the
	// records we expect to read back. Values are a few KB so each read is long
	// enough to actually overlap with others under load.
	const subtrees = 64
	type loc struct{ offset, size uint64 }
	locs := make([]loc, subtrees)
	want := make([][]*Record, subtrees)
	for i := 0; i < subtrees; i++ {
		recs := []*Record{
			{Path: []byte{byte(i), 0x01}, Value: bytes.Repeat([]byte{byte(i)}, 4096)},
			{Path: []byte{byte(i), 0x02}, Value: bytes.Repeat([]byte{byte(i) + 1}, 2053)},
		}
		off, sz, err := w.WriteSubtree(recs)
		if err != nil {
			t.Fatalf("write subtree %d: %v", i, err)
		}
		locs[i] = loc{off, sz}
		want[i] = recs
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Point the resolver at our archive, force a small cap, and a fresh handle/sem.
	oldDir, oldCap := ArchiveDataDir, ArchiveReadConcurrency
	ArchiveDataDir = dir
	ArchiveReadConcurrency = 8
	resetArchiveState()
	coldReadHighWater.Store(0)
	defer func() {
		ArchiveDataDir, ArchiveReadConcurrency = oldDir, oldCap
		resetArchiveState()
	}()

	const goroutines = 2000
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	start := make(chan struct{}) // release all goroutines at once to maximize overlap
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			<-start
			i := g % subtrees
			got, err := ArchivedNodeResolver(locs[i].offset, locs[i].size)
			if err != nil {
				errCh <- fmt.Errorf("resolve %d: %w", i, err)
				return
			}
			if err := recordsEqual(got, want[i]); err != nil {
				errCh <- fmt.Errorf("subtree %d: %w", i, err)
			}
		}(g)
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	hw := ColdReadHighWater()
	if hw > int64(ArchiveReadConcurrency) {
		t.Fatalf("cold-read high-water %d exceeds cap %d: semaphore is not bounding concurrency", hw, ArchiveReadConcurrency)
	}
	if hw < 2 {
		t.Logf("warning: peak concurrency was %d; the test may not have exercised real overlap", hw)
	}
	t.Logf("ok: %d concurrent resolvers, peak concurrency %d <= cap %d", goroutines, hw, ArchiveReadConcurrency)
}
