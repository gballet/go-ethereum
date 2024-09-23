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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// mode specifies how a tree location has been accessed
// for the byte value:
// * the first bit is set if the branch has been edited
// * the second bit is set if the branch has been read
type mode byte

// UseGasFn is a function that can be used to charge gas for a given amount.
type UseGasFn func(uint64) bool

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
}

func NewAccessWitness(pointCache *utils.PointCache) *AccessWitness {
	return &AccessWitness{
		branches:   make(map[branchAccessKey]mode),
		chunks:     make(map[chunkAccessKey]mode),
		pointCache: pointCache,
	}
}

// Merge is used to merge the witness that got generated during the execution
// of a tx, with the accumulation of witnesses that were generated during the
// execution of all the txs preceding this one in a given block.
func (aw *AccessWitness) Merge(other *AccessWitness) {
	for k := range other.branches {
		aw.branches[k] |= other.branches[k]
	}
	for k, chunk := range other.chunks {
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

func (aw *AccessWitness) TouchFullAccount(addr []byte, isWrite bool, useGasFn UseGasFn) bool {
	for i := utils.BasicDataLeafKey; i <= utils.CodeHashLeafKey; i++ {
		if _, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, byte(i), isWrite, useGasFn); !ok {
			return false
		}
	}
	return true
}

func (aw *AccessWitness) TouchAndChargeMessageCall(addr []byte, useGasFn UseGasFn) bool {
	chargedGas, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, false, useGasFn)
	return ok && (chargedGas > 0 || useGasFn(params.WarmStorageReadCostEIP2929))
}

func (aw *AccessWitness) TouchAndChargeValueTransfer(callerAddr, targetAddr []byte, useGasFn UseGasFn) bool {
	_, ok := aw.touchAddressAndChargeGas(callerAddr, zeroTreeIndex, utils.BasicDataLeafKey, true, useGasFn)
	if !ok {
		return false
	}
	_, ok = aw.touchAddressAndChargeGas(targetAddr, zeroTreeIndex, utils.BasicDataLeafKey, true, useGasFn)
	return ok
}

// TouchAndChargeContractCreateCheck charges access costs before
// a contract creation is initiated. It is just reads, because the
// address collision is done before the transfer, and so no write
// are guaranteed to happen at this point.
func (aw *AccessWitness) TouchAndChargeContractCreateCheck(addr []byte, useGasFn UseGasFn) bool {
	if _, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, false, useGasFn); !ok {
		return false
	}
	_, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, false, useGasFn)
	return ok
}

// TouchAndChargeContractCreateInit charges access costs to initiate
// a contract creation.
func (aw *AccessWitness) TouchAndChargeContractCreateInit(addr []byte, useGasFn UseGasFn) bool {
	if _, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, true, useGasFn); !ok {
		return false
	}
	_, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, true, useGasFn)
	return ok
}

func (aw *AccessWitness) TouchTxOriginAndComputeGas(originAddr []byte) {
	for i := utils.BasicDataLeafKey; i <= utils.CodeHashLeafKey; i++ {
		aw.touchAddressAndChargeGas(originAddr, zeroTreeIndex, byte(i), i == utils.BasicDataLeafKey, nil)
	}
}

func (aw *AccessWitness) TouchTxExistingAndComputeGas(targetAddr []byte, sendsValue bool) {
	aw.touchAddressAndChargeGas(targetAddr, zeroTreeIndex, utils.BasicDataLeafKey, sendsValue, nil)
	aw.touchAddressAndChargeGas(targetAddr, zeroTreeIndex, utils.CodeHashLeafKey, false, nil)
}

func (aw *AccessWitness) TouchSlotAndChargeGas(addr []byte, slot common.Hash, isWrite bool, useGasFn UseGasFn, warmCostCharging bool) bool {
	treeIndex, subIndex := utils.GetTreeKeyStorageSlotTreeIndexes(slot.Bytes())
	chargedGas, ok := aw.touchAddressAndChargeGas(addr, *treeIndex, subIndex, isWrite, useGasFn)
	return ok && (!warmCostCharging || chargedGas > 0 || useGasFn(params.WarmStorageReadCostEIP2929))
}

func (aw *AccessWitness) touchAddressAndChargeGas(addr []byte, treeIndex uint256.Int, subIndex byte, isWrite bool, useGasFn UseGasFn) (uint64, bool) {
	branchKey := newBranchAccessKey(addr, treeIndex)
	chunkKey := newChunkAccessKey(branchKey, subIndex)

	// Read access.
	var branchRead, chunkRead bool
	if _, hasStem := aw.branches[branchKey]; !hasStem {
		branchRead = true
	}
	if _, hasSelector := aw.chunks[chunkKey]; !hasSelector {
		chunkRead = true
	}

	// Write access.
	var branchWrite, chunkWrite, chunkFill bool
	if isWrite {
		if (aw.branches[branchKey] & AccessWitnessWriteFlag) == 0 {
			branchWrite = true
		}

		chunkValue := aw.chunks[chunkKey]
		if (chunkValue & AccessWitnessWriteFlag) == 0 {
			chunkWrite = true
		}
	}

	var gas uint64
	if branchRead {
		gas += params.WitnessBranchReadCost
	}
	if chunkRead {
		gas += params.WitnessChunkReadCost
	}
	if branchWrite {
		gas += params.WitnessBranchWriteCost
	}
	if chunkWrite {
		gas += params.WitnessChunkWriteCost
	}
	if chunkFill {
		gas += params.WitnessChunkFillCost
	}

	if useGasFn != nil {
		if ok := useGasFn(gas); !ok {
			return 0, false
		}
	}

	if branchRead {
		aw.branches[branchKey] = AccessWitnessReadFlag
	}
	if branchWrite {
		aw.branches[branchKey] |= AccessWitnessWriteFlag
	}
	if chunkRead {
		aw.chunks[chunkKey] = AccessWitnessReadFlag
	}
	if chunkWrite {
		chunkWrite = true
		aw.chunks[chunkKey] |= AccessWitnessWriteFlag
	}

	return gas, true
}

type branchAccessKey struct {
	addr      common.Address
	treeIndex uint256.Int
}

func newBranchAccessKey(addr []byte, treeIndex uint256.Int) branchAccessKey {
	var sk branchAccessKey
	copy(sk.addr[20-len(addr):], addr)
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

// touchCodeChunksRangeOnReadAndChargeGas is a helper function to touch every chunk in a code range and charge witness gas costs
func (aw *AccessWitness) TouchCodeChunksRangeAndChargeGas(contractAddr []byte, startPC, size uint64, codeLen uint64, isWrite bool, useGasFn UseGasFn) bool {
	// note that in the case where the copied code is outside the range of the
	// contract code but touches the last leaf with contract code in it,
	// we don't include the last leaf of code in the AccessWitness.  The
	// reason that we do not need the last leaf is the account's code size
	// is already in the AccessWitness so a stateless verifier can see that
	// the code from the last leaf is not needed.
	if size == 0 || startPC >= codeLen {
		return true
	}

	endPC := startPC + size
	if endPC > codeLen {
		endPC = codeLen
	}
	if endPC > 0 {
		endPC -= 1 // endPC is the last bytecode that will be touched.
	}

	for chunkNumber := startPC / 31; chunkNumber <= endPC/31; chunkNumber++ {
		treeIndex := *uint256.NewInt((chunkNumber + 128) / 256)
		subIndex := byte((chunkNumber + 128) % 256)
		if _, ok := aw.touchAddressAndChargeGas(contractAddr, treeIndex, subIndex, isWrite, useGasFn); !ok {
			return false
		}
	}

	return true
}

func (aw *AccessWitness) TouchBasicData(addr []byte, isWrite bool, useGasFn UseGasFn, warmCostCharging bool) bool {
	chargedGas, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.BasicDataLeafKey, isWrite, useGasFn)
	return ok && (!warmCostCharging || chargedGas > 0 || useGasFn(params.WarmStorageReadCostEIP2929))
}

func (aw *AccessWitness) TouchCodeHash(addr []byte, isWrite bool, useGasFn UseGasFn) bool {
	chargedGas, ok := aw.touchAddressAndChargeGas(addr, zeroTreeIndex, utils.CodeHashLeafKey, isWrite, useGasFn)
	return ok && (chargedGas > 0 || useGasFn(params.WarmStorageReadCostEIP2929))
}
