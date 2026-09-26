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

package core

import (
	"runtime"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/bitutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

// receiptDigest holds the two values the block validator needs from the
// receipts of a block.
type receiptDigest struct {
	bloom types.Bloom // bloom filter of the block, the receipt blooms merged
	root  common.Hash // root of the receipt trie
}

// receiptPipeline turns the receipts of a block into their digest on a
// goroutine of its own, fed as each transaction finishes so the hashing
// overlaps the transactions still to run. When the runtime has a single P,
// there is nothing to overlap with and the receipts are digested inline as
// they are added. Only the goroutine processing the block may drive it.
type receiptPipeline struct {
	feed   chan *types.Receipt // nil when digesting inline
	done   chan struct{}
	closed bool

	// bloomed tells the pipeline that the receipts arrive with their bloom
	// filter already computed.
	bloomed bool

	bloom    types.Bloom
	receipts types.Receipts
	stream   *types.ListHashStream

	// digest is the result. It is only valid once the pipeline is joined.
	digest receiptDigest
}

// newReceiptPipeline starts the pipeline for a block of txs transactions. Set
// bloomed when the receipts already carry their bloom filter, the pipeline then
// uses it rather than hashing the logs again.
func newReceiptPipeline(txs int, bloomed bool) *receiptPipeline {
	p := &receiptPipeline{
		bloomed:  bloomed,
		receipts: make(types.Receipts, 0, txs),
		stream:   types.NewListHashStream(trie.NewStackTrie(nil)),
	}
	if runtime.GOMAXPROCS(0) > 1 {
		p.feed = make(chan *types.Receipt, txs)
		p.done = make(chan struct{})
		go p.run()
	}
	return p
}

// run consumes the receipts of the block and computes their digest.
func (p *receiptPipeline) run() {
	defer close(p.done)

	for receipt := range p.feed {
		p.digestReceipt(receipt)
	}
	p.finish()
}

// digestReceipt folds a receipt into the bloom filter and the receipt trie.
func (p *receiptPipeline) digestReceipt(receipt *types.Receipt) {
	if !p.bloomed {
		receipt.Bloom = types.CreateBloom(receipt)
	}
	if len(receipt.Logs) != 0 {
		bitutil.ORBytes(p.bloom[:], p.bloom[:], receipt.Bloom[:])
	}
	// The receipt encoding covers the bloom, so the trie is fed after it.
	p.receipts = append(p.receipts, receipt)
	p.stream.Update(p.receipts)
}

// finish computes the digest once all receipts have been folded in.
func (p *receiptPipeline) finish() {
	p.digest = receiptDigest{
		bloom: p.bloom,
		root:  p.stream.Hash(),
	}
}

// add hands a receipt over. It must not be touched again until the pipeline
// has been joined, the pipeline fills in its bloom filter.
func (p *receiptPipeline) add(receipt *types.Receipt) {
	if p.feed == nil {
		p.digestReceipt(receipt)
		return
	}
	p.feed <- receipt
}

// close tells the pipeline that no more receipts are coming, so it can finish
// the trie while the processor wraps the block up. Calling it twice is fine,
// both joining and abandoning a block go through here.
func (p *receiptPipeline) close() {
	if !p.closed {
		p.closed = true
		if p.feed != nil {
			close(p.feed)
		}
	}
}

// join waits for the pipeline to drain and returns the digest of the receipts
// it was given.
func (p *receiptPipeline) join() receiptDigest {
	p.close()
	if p.done != nil {
		<-p.done
	} else {
		p.finish()
	}
	return p.digest
}

// blockBloom returns the bloom filter of the processed block, merged alongside
// execution if a pipeline ran, and from the receipts here if none did.
func (r *ProcessResult) blockBloom() types.Bloom {
	if r.digest != nil {
		return r.digest.bloom
	}
	return types.MergeBloom(r.Receipts)
}

// receiptRoot returns the root of the receipt trie of the processed block,
// built alongside execution if a pipeline ran, and from the receipts here if
// none did.
func (r *ProcessResult) receiptRoot() common.Hash {
	if r.digest != nil {
		return r.digest.root
	}
	return types.DeriveSha(r.Receipts, trie.NewStackTrie(nil))
}
