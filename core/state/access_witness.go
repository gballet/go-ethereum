// Copyright 2021 The go-ethereum Authors
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

package state

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// mode specifies how a tree location has been accessed
// for the byte value:
// * the first bit is set if the branch has been edited
// * the second bit is set if the branch has been read
type mode byte

const (
	AccessWitnessReadFlag  = mode(1)
	AccessWitnessWriteFlag = mode(2)
)

var zeroTreeIndex uint256.Int

// AccessWitness lists the locations of the state that are being accessed
// during the production of a block.
type AccessWitness struct {
	branches map[branchAccessKey]mode
	chunks   map[chunkAccessKey]mode

	pointCache *utils.PointCache

	treeLoaderChunks chan chunkAccessKey
	tree             *trie.VerkleTrie
	treeLoaderQuit   chan struct{}
	treeLoaderClosed chan struct{}
	treeLoaderErr    error
}

func NewAccessWitness(pointCache *utils.PointCache) *AccessWitness {
	return &AccessWitness{
		branches:   make(map[branchAccessKey]mode),
		chunks:     make(map[chunkAccessKey]mode),
		pointCache: pointCache,
	}
}

func NewAccessWitnessWithTreeLoader(pointCache *utils.PointCache, trie *trie.VerkleTrie) *AccessWitness {
	aw := NewAccessWitness(pointCache)
	aw.treeLoaderChunks = make(chan chunkAccessKey, 1024)
	aw.tree = trie
	go aw.backgroundTreeLoader()

	return aw
}

// Merge is used to merge the witness that got generated during the execution
// of a tx, with the accumulation of witnesses that were generated during the
// execution of all the txs preceding this one in a given block.
func (aw *AccessWitness) Merge(other *AccessWitness) {
	for k := range other.branches {
		aw.branches[k] |= other.branches[k]
	}
	for k, chunk := range other.chunks {
		// If the to-be-merged chunk isn't already present,
		// schedule to be warmed up in the loding witness tree.
		if aw.treeLoaderChunks != nil {
			if _, ok := aw.chunks[k]; !ok {
				aw.treeLoaderChunks <- k
			}
		}
		aw.chunks[k] |= chunk
	}
}

// Key returns, predictably, the list of keys that were touched during the
// buildup of the access witness.
func (aw *AccessWitness) Keys() [][]byte {
	// TODO: consider if parallelizing this is worth it, probably depending on len(aw.chunks).
	keys := make([][]byte, 0, len(aw.chunks))
	for chunk := range aw.chunks {
		basePoint := aw.pointCache.GetTreeKeyHeader(chunk.addr[:])
		key := utils.GetTreeKeyWithEvaluatedAddess(basePoint, &chunk.treeIndex, chunk.leafKey)
		keys = append(keys, key)
	}
	return keys
}

func (aw *AccessWitness) Copy() *AccessWitness {
	naw := &AccessWitness{
		branches:   make(map[branchAccessKey]mode),
		chunks:     make(map[chunkAccessKey]mode),
		pointCache: aw.pointCache,
	}
	naw.Merge(aw)
	return naw
}

func (aw *AccessWitness) TouchAndChargeProofOfAbsence(addr []byte) uint64 {
	var gas uint64
	gas += aw.TouchAddressOnReadAndComputeGas(addr, zeroTreeIndex, utils.VersionLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(addr, zeroTreeIndex, utils.BalanceLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(addr, zeroTreeIndex, utils.CodeSizeLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(addr, zeroTreeIndex, utils.CodeKeccakLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(addr, zeroTreeIndex, utils.NonceLeafKey)
	return gas
}

func (aw *AccessWitness) TouchAndChargeMessageCall(addr []byte) uint64 {
	var gas uint64
	gas += aw.TouchAddressOnReadAndComputeGas(addr, zeroTreeIndex, utils.VersionLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(addr, zeroTreeIndex, utils.CodeSizeLeafKey)
	return gas
}

func (aw *AccessWitness) TouchAndChargeValueTransfer(callerAddr, targetAddr []byte) uint64 {
	var gas uint64
	gas += aw.TouchAddressOnWriteAndComputeGas(callerAddr, zeroTreeIndex, utils.BalanceLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(targetAddr, zeroTreeIndex, utils.BalanceLeafKey)
	return gas
}

// TouchAndChargeContractCreateInit charges access costs to initiate
// a contract creation
func (aw *AccessWitness) TouchAndChargeContractCreateInit(addr []byte, createSendsValue bool) uint64 {
	var gas uint64
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.VersionLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.NonceLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.CodeKeccakLeafKey)
	if createSendsValue {
		gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.BalanceLeafKey)
	}
	return gas
}

// TouchAndChargeContractCreateCompleted charges access access costs after
// the completion of a contract creation to populate the created account in
// the tree
func (aw *AccessWitness) TouchAndChargeContractCreateCompleted(addr []byte) uint64 {
	var gas uint64
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.VersionLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.BalanceLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.CodeSizeLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.CodeKeccakLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(addr, zeroTreeIndex, utils.NonceLeafKey)
	return gas
}

func (aw *AccessWitness) TouchTxOriginAndComputeGas(originAddr []byte) uint64 {
	var gas uint64
	gas += aw.TouchAddressOnReadAndComputeGas(originAddr, zeroTreeIndex, utils.VersionLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(originAddr, zeroTreeIndex, utils.CodeSizeLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(originAddr, zeroTreeIndex, utils.CodeKeccakLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(originAddr, zeroTreeIndex, utils.NonceLeafKey)
	gas += aw.TouchAddressOnWriteAndComputeGas(originAddr, zeroTreeIndex, utils.BalanceLeafKey)
	return gas
}

func (aw *AccessWitness) TouchTxExistingAndComputeGas(targetAddr []byte, sendsValue bool) uint64 {
	var gas uint64
	gas += aw.TouchAddressOnReadAndComputeGas(targetAddr, zeroTreeIndex, utils.VersionLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(targetAddr, zeroTreeIndex, utils.CodeSizeLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(targetAddr, zeroTreeIndex, utils.CodeKeccakLeafKey)
	gas += aw.TouchAddressOnReadAndComputeGas(targetAddr, zeroTreeIndex, utils.NonceLeafKey)
	if sendsValue {
		gas += aw.TouchAddressOnWriteAndComputeGas(targetAddr, zeroTreeIndex, utils.BalanceLeafKey)
	} else {
		gas += aw.TouchAddressOnReadAndComputeGas(targetAddr, zeroTreeIndex, utils.BalanceLeafKey)
	}
	return gas
}

func (aw *AccessWitness) TouchAddressOnWriteAndComputeGas(addr []byte, treeIndex uint256.Int, subIndex byte) uint64 {
	return aw.touchAddressAndChargeGas(addr, treeIndex, subIndex, true)
}

func (aw *AccessWitness) TouchAddressOnReadAndComputeGas(addr []byte, treeIndex uint256.Int, subIndex byte) uint64 {
	return aw.touchAddressAndChargeGas(addr, treeIndex, subIndex, false)
}

func (aw *AccessWitness) touchAddressAndChargeGas(addr []byte, treeIndex uint256.Int, subIndex byte, isWrite bool) uint64 {
	stemRead, selectorRead, stemWrite, selectorWrite, selectorFill := aw.touchAddress(addr, treeIndex, subIndex, isWrite)

	var gas uint64
	if stemRead {
		gas += params.WitnessBranchReadCost
	}
	if selectorRead {
		gas += params.WitnessChunkReadCost
	}
	if stemWrite {
		gas += params.WitnessBranchWriteCost
	}
	if selectorWrite {
		gas += params.WitnessChunkWriteCost
	}
	if selectorFill {
		gas += params.WitnessChunkFillCost
	}

	return gas
}

// touchAddress adds any missing access event to the witness.
func (aw *AccessWitness) touchAddress(addr []byte, treeIndex uint256.Int, subIndex byte, isWrite bool) (bool, bool, bool, bool, bool) {
	branchKey := newBranchAccessKey(addr, treeIndex)
	chunkKey := newChunkAccessKey(branchKey, subIndex)

	// Read access.
	var branchRead, chunkRead bool
	if _, hasStem := aw.branches[branchKey]; !hasStem {
		branchRead = true
		aw.branches[branchKey] = AccessWitnessReadFlag
	}
	if _, hasSelector := aw.chunks[chunkKey]; !hasSelector {
		chunkRead = true
		aw.chunks[chunkKey] = AccessWitnessReadFlag
	}

	// Write access.
	var branchWrite, chunkWrite, chunkFill bool
	if isWrite {
		if (aw.branches[branchKey] & AccessWitnessWriteFlag) == 0 {
			branchWrite = true
			aw.branches[branchKey] |= AccessWitnessWriteFlag
		}

		chunkValue := aw.chunks[chunkKey]
		if (chunkValue & AccessWitnessWriteFlag) == 0 {
			chunkWrite = true
			aw.chunks[chunkKey] |= AccessWitnessWriteFlag
		}

		// TODO: charge chunk filling costs if the leaf was previously empty in the state
	}

	return branchRead, chunkRead, branchWrite, chunkWrite, chunkFill
}

func (aw *AccessWitness) GetLoadedTree() (*trie.VerkleTrie, error) {
	// Signal that we are done sending chunks to load the tree.
	aw.treeLoaderQuit <- struct{}{}
	// Wait for the background loader to finish loading pending keys.
	<-aw.treeLoaderClosed

	// If the background loader encountered an error, return it.
	if aw.treeLoaderErr != nil {
		return nil, fmt.Errorf("loading the witness tree failed: %s", aw.treeLoaderErr)
	}

	// The tree is fully loaded and ready to support proof generation.
	return aw.tree, nil
}

func (aw *AccessWitness) backgroundTreeLoader() {
	defer close(aw.treeLoaderClosed)
	for {
		select {
		case chunk := <-aw.treeLoaderChunks:
			basePoint := aw.pointCache.GetTreeKeyHeader(chunk.addr[:])
			key := utils.GetTreeKeyWithEvaluatedAddess(basePoint, &chunk.treeIndex, chunk.leafKey)
			if err := aw.tree.LoadHashedKeyForProof(key); err != nil {
				aw.treeLoaderErr = err
				return
			}
		case <-aw.treeLoaderQuit:
			return
		}
	}
}

type branchAccessKey struct {
	addr      common.Address
	treeIndex uint256.Int
}

func newBranchAccessKey(addr []byte, treeIndex uint256.Int) branchAccessKey {
	var sk branchAccessKey
	copy(sk.addr[:], addr)
	sk.treeIndex = treeIndex
	return sk
}

type chunkAccessKey struct {
	branchAccessKey
	leafKey byte
}

func newChunkAccessKey(branchKey branchAccessKey, leafKey byte) chunkAccessKey {
	var lk chunkAccessKey
	lk.branchAccessKey = branchKey
	lk.leafKey = leafKey
	return lk
}
