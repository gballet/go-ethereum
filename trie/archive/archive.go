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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/rlp"
)

// ResolverFn is a callback to resolve expired nodes from an archive file.
// Given an offset and size, it returns the serialized node data from the archive.
type ResolverFn func(offset, size uint64) ([]*Record, error)

// OffsetSize is the size of the file offset in bytes.
const OffsetSize = 8

var (
	EmptyArchiveRecord = errors.New("empty record")                             // The archive contained a size-zero record.
	ErrNoResolver      = errors.New("no archive resolver set for expired node") // An expired node is accessed without a resolver.
)

// Record contains an archive file record. It is not the most optimal
// structure, since any modification to it will need to be overwritten.
type Record struct {
	Path  []byte
	Value []byte
}

// ArchiveDataDir is the data directory where the archive file is stored.
var ArchiveDataDir string

// ArchiveReadConcurrency bounds the number of goroutines that may be
// simultaneously blocked inside an archive (cold flat-file) read. Each such
// goroutine sits in a blocking pread and pins one OS thread; without a bound, a
// block that fans out one resolver call per mutated account can pin tens of
// thousands of threads and trip the Go runtime's thread limit (maxmcount=10000
// -> "thread exhaustion"). Callers that cannot get a slot park on the semaphore
// (holding no OS thread) until one frees. This throttle only engages on the
// cold path: when no nodes are archived the resolver is never called, so
// all-NVMe execution is completely unaffected.
//
// The default is provisional; the production value is derived empirically per
// device (see the article's parameter sweep). Override at startup via the
// GETH_ARCHIVE_READ_CONCURRENCY environment variable.
var ArchiveReadConcurrency = envInt("GETH_ARCHIVE_READ_CONCURRENCY", 256)

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// Archive read state. A single file handle is cached and read concurrently via
// ReadAt (positioned read, no shared offset, safe for parallel use), replacing
// the previous open/seek/read/close on every call. The cold-read semaphore caps
// concurrency. All guarded by archiveMu; the handle is (re)opened when
// ArchiveDataDir changes (tests point it at different temp dirs) and the
// semaphore is (re)sized to ArchiveReadConcurrency. In a running node both are
// fixed at startup, so after the first call this is a cheap pointer fetch.
var (
	archiveMu   sync.Mutex
	archiveFile *os.File
	archivePath string
	coldReadSem chan struct{}

	coldReadInFlight  atomic.Int64
	coldReadHighWater atomic.Int64
)

// ColdReadHighWater returns the peak number of archive reads observed running
// concurrently since process start. Exposed for tests and operational metrics.
func ColdReadHighWater() int64 { return coldReadHighWater.Load() }

// archiveReader returns the cached archive file handle and the cold-read
// semaphore, opening/reopening the file if ArchiveDataDir changed and resizing
// the semaphore to the current ArchiveReadConcurrency.
func archiveReader() (*os.File, chan struct{}, error) {
	path := filepath.Join(ArchiveDataDir, "geth", "nodearchive")

	archiveMu.Lock()
	defer archiveMu.Unlock()

	if archiveFile == nil || archivePath != path {
		f, err := os.Open(path)
		if err != nil {
			return nil, nil, fmt.Errorf("error opening archive file: %w", err)
		}
		if archiveFile != nil {
			archiveFile.Close()
		}
		archiveFile, archivePath = f, path
	}
	if coldReadSem == nil || cap(coldReadSem) != ArchiveReadConcurrency {
		coldReadSem = make(chan struct{}, ArchiveReadConcurrency)
	}
	return archiveFile, coldReadSem, nil
}

// boundedReadAt performs file.ReadAt(data, offset) while holding one slot of the
// cold-read semaphore, so no more than cap(sem) goroutines are ever blocked in a
// pread at once. The defers guarantee the slot is returned and the in-flight
// gauge decremented even if ReadAt panics or a future early-return is added in
// this window; crucially they also release BEFORE the caller's RLP decode, so
// the CPU-bound decode never occupies a disk-read slot.
func boundedReadAt(file *os.File, sem chan struct{}, data []byte, offset uint64) (int, error) {
	sem <- struct{}{}
	defer func() { <-sem }()
	inflight := coldReadInFlight.Add(1)
	defer coldReadInFlight.Add(-1)
	for {
		hw := coldReadHighWater.Load()
		if inflight <= hw || coldReadHighWater.CompareAndSwap(hw, inflight) {
			break
		}
	}
	return file.ReadAt(data, int64(offset))
}

// ArchivedNodeResolver takes a buffer containing the archive data
// held by an expiring node (an offset and a size) and returns a
// list of records, which is a list of serialized leaf nodes. The
// caller knows the context (MPT, binary trie) and is responsible
// for decoding the nodes.
func ArchivedNodeResolver(offset, size uint64) ([]*Record, error) {
	file, sem, err := archiveReader()
	if err != nil {
		return nil, err
	}

	data := make([]byte, size)

	// The semaphore bounds concurrent cold reads to cap(sem); excess callers park
	// on the channel (holding no OS thread), which is what prevents the cold path
	// from exhausting OS threads. It guards only the blocking read, not the decode.
	n, rerr := boundedReadAt(file, sem, data, offset)
	// ReadAt may return io.EOF together with a full read when the record sits at
	// the very end of the file; a full read is success regardless of that EOF.
	if rerr != nil && !(rerr == io.EOF && uint64(n) == size) {
		return nil, fmt.Errorf("error reading data from archive: %w", rerr)
	}

	var records []*Record
	stream := rlp.NewStream(bytes.NewReader(data), uint64(len(data)))
	for len(data) > 0 {
		_, size, err := stream.Kind()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error getting rlp kind from archive data: %w", err)
		}
		var record Record
		err = stream.Decode(&record)
		if err != nil {
			return nil, fmt.Errorf("error decoding rlp record from archive data (offset=%d, size=%d): %w", offset, size, err)
		}
		records = append(records, &record)
	}
	return records, nil
}
