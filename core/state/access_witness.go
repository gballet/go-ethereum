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
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
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

func (aw *AccessWitness) FullAccountGas(addr []byte, isWrite bool) uint64 {
	return aw.calculateWitnessGasRange(addr, zeroTreeIndex, isWrite, utils.BasicDataLeafKey, utils.CodeHashLeafKey)
}

func (aw *AccessWitness) TouchFullAccount(addr []byte, isWrite bool) {
	for i := utils.BasicDataLeafKey; i <= utils.CodeHashLeafKey; i++ {
		aw.touchLocation(addr, zeroTreeIndex, byte(i), isWrite)
	}
}

func (aw *AccessWitness) MessageCallGas(addr []byte) uint64 {
	wanted := aw.calculateWitnessGasRange(addr, zeroTreeIndex, false, utils.BasicDataLeafKey, utils.BasicDataLeafKey)
	if wanted == 0 {
		wanted = params.WarmStorageReadCostEIP2929
	}
	return wanted
}

func (aw *AccessWitness) TouchMessageCall(addr []byte) {
	aw.touchLocation(addr, zeroTreeIndex, utils.BasicDataLeafKey, false)
}

func (aw *AccessWitness) TouchValueTransfer(callerAddr, targetAddr []byte) {
	aw.touchLocation(callerAddr, zeroTreeIndex, utils.BasicDataLeafKey, true)
	aw.touchLocation(targetAddr, zeroTreeIndex, utils.BasicDataLeafKey, true)
}

func (aw *AccessWitness) ValueTransferGas(callerAddr, targetAddr []byte) uint64 {
	wanted1 := aw.calculateWitnessGasRange(callerAddr, zeroTreeIndex, true, utils.BasicDataLeafKey, utils.BasicDataLeafKey)
	wanted2 := aw.calculateWitnessGasRange(targetAddr, zeroTreeIndex, true, utils.BasicDataLeafKey, utils.BasicDataLeafKey)
	if wanted1+wanted2 == 0 {
		return params.WarmStorageReadCostEIP2929
	}
	return wanted1 + wanted2
}

// ContractCreateCheckGas charges access costs before
// a contract creation is initiated. It is just reads, because the
// address collision is done before the transfer, and so no write
// are guaranteed to happen at this point.
func (aw *AccessWitness) ContractCreateCheckGas(addr []byte) uint64 {
	return aw.calculateWitnessGasRange(addr, zeroTreeIndex, false, utils.BasicDataLeafKey, utils.CodeHashLeafKey)
}

// TouchAndChargeContractCreateCheck charges access costs before
// a contract creation is initiated. It is just reads, because the
// address collision is done before the transfer, and so no write
// are guaranteed to happen at this point.
func (aw *AccessWitness) TouchContractCreateCheck(addr []byte) {
	aw.touchLocation(addr, zeroTreeIndex, utils.BasicDataLeafKey, false)
	aw.touchLocation(addr, zeroTreeIndex, utils.CodeHashLeafKey, false)
}

// ContractCreateInitGas charges access costs to initiate a contract creation.
func (aw *AccessWitness) ContractCreateInitGas(addr []byte) uint64 {
	return aw.calculateWitnessGasRange(addr, zeroTreeIndex, true, utils.BasicDataLeafKey, utils.CodeHashLeafKey)
}

// TouchAndChargeContractCreateInit charges access costs to initiate
// a contract creation.
func (aw *AccessWitness) TouchContractCreateInit(addr []byte, availableGas uint64) {
	aw.touchLocation(addr, zeroTreeIndex, utils.BasicDataLeafKey, true)
	aw.touchLocation(addr, zeroTreeIndex, utils.CodeHashLeafKey, true)
}

func (aw *AccessWitness) TouchTxOriginAndComputeGas(originAddr []byte) {
	for i := utils.BasicDataLeafKey; i <= utils.CodeHashLeafKey; i++ {
		aw.touchLocation(originAddr, zeroTreeIndex, byte(i), i == utils.BasicDataLeafKey)
	}
}

func (aw *AccessWitness) TouchTxTarget(targetAddr []byte, sendsValue, doesntExist bool) {
	aw.touchLocation(targetAddr, zeroTreeIndex, utils.BasicDataLeafKey, sendsValue)
	// Note that we do a write-event in CodeHash without distinguishing if the tx target account
	// exists or not. Pre-7702, there's no situation in which an existing codeHash can be mutated, thus
	// doing a write-event shouldn't cause an observable difference in gas usage.
	// TODO(7702): re-check this in the spec and implementation to be sure is a correct solution after
	// EIP-7702 is implemented.
	aw.touchLocation(targetAddr, zeroTreeIndex, utils.CodeHashLeafKey, doesntExist)
}

func (aw *AccessWitness) SlotGas(addr []byte, slot common.Hash, isWrite bool) uint64 {
	treeIndex, subIndex := utils.GetTreeKeyStorageSlotTreeIndexes(slot.Bytes())
	wanted := aw.calculateWitnessGasRange(addr, *treeIndex, isWrite, uint64(subIndex), uint64(subIndex))
	if wanted == 0 {
		wanted = params.WarmStorageReadCostEIP2929
	}
	return wanted
}

func (aw *AccessWitness) TouchSlot(addr []byte, slot common.Hash, isWrite bool) {
	treeIndex, subIndex := utils.GetTreeKeyStorageSlotTreeIndexes(slot.Bytes())
	aw.touchLocation(addr, *treeIndex, subIndex, isWrite)
}

func (aw *AccessWitness) calculateWitnessGasRange(addr []byte, treeIndex uint256.Int, isWrite bool, from, to uint64) uint64 {
	var (
		gas                     uint64
		branchKey               = newBranchAccessKey(addr, treeIndex)
		branchRead, branchWrite bool
	)

	// Read access.
	if _, hasStem := aw.branches[branchKey]; !hasStem {
		branchRead = true
	}

	// Write access.
	if isWrite {
		if (aw.branches[branchKey] & AccessWitnessWriteFlag) == 0 {
			branchWrite = true
		}
	}

	if branchRead {
		gas += params.WitnessBranchReadCost
	}
	if branchWrite {
		gas += params.WitnessBranchWriteCost
	}

	for subIndex := from; subIndex <= to; subIndex++ {
		var chunkRead, chunkWrite, chunkFill bool
		chunkKey := newChunkAccessKey(branchKey, byte(subIndex))
		if _, hasSelector := aw.chunks[chunkKey]; !hasSelector {
			chunkRead = true

		}
		if isWrite && (aw.chunks[chunkKey]&AccessWitnessWriteFlag) == 0 {
			chunkWrite = true
		}
		if chunkRead {
			gas += params.WitnessChunkReadCost
		}
		if chunkWrite {
			gas += params.WitnessChunkWriteCost
		}
		if chunkFill {
			gas += params.WitnessChunkFillCost
		}
	}

	return gas
}

func (aw *AccessWitness) touchLocation(addr []byte, treeIndex uint256.Int, subIndex byte, isWrite bool) {
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
		aw.chunks[chunkKey] |= AccessWitnessWriteFlag

		if chunkFill {
			// TODO when FILL_COST is implemented
		}
	}
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

// CodeChunksRangeGas is a helper function to touch every chunk in a code range and charge witness gas costs
func (aw *AccessWitness) CodeChunksRangeGas(contractAddr []byte, startPC, size uint64, codeLen uint64, isWrite bool) (uint64, error) {
	// note that in the case where the copied code is outside the range of the
	// contract code but touches the last leaf with contract code in it,
	// we don't include the last leaf of code in the AccessWitness.  The
	// reason that we do not need the last leaf is the account's code size
	// is already in the AccessWitness so a stateless verifier can see that
	// the code from the last leaf is not needed.
	if size == 0 || startPC >= codeLen {
		return 0, nil
	}

	endPC := startPC + size
	if endPC > codeLen {
		endPC = codeLen
	}
	if endPC > 0 {
		endPC -= 1 // endPC is the last bytecode that will be touched.
	}

	var statelessGasCharged uint64
	for chunkNumber := startPC / 31; chunkNumber <= endPC/31; {
		startSubIndex := (chunkNumber + 128) % 256
		var endSubIndex uint64
		if chunkNumber < 128 {
			// special case of finding the upper boundary for the header group
			endSubIndex = min(endPC/31, 128) + 128
		} else {
			endSubIndex = min(endPC/31-chunkNumber, 255)
		}

		treeIndex := *uint256.NewInt((chunkNumber + 128) / 256)
		wanted := aw.calculateWitnessGasRange(contractAddr, treeIndex, isWrite, startSubIndex, endSubIndex)
		var overflow bool
		statelessGasCharged, overflow = math.SafeAdd(statelessGasCharged, wanted)
		if overflow {
			return 0, errors.New("gas uint overflow")
		}

		// Find the next group boundary, taking the 128 offset into account.
		if chunkNumber == 0 {
			chunkNumber = 128
		} else {
			chunkNumber += 256
		}
	}

	return statelessGasCharged, nil
}

// TouchCodeChunksRange is a helper function to touch every chunk in a code range and charge witness gas costs
func (aw *AccessWitness) TouchCodeChunksRange(contractAddr []byte, startPC, size uint64, codeLen uint64, isWrite bool) {
	// note that in the case where the copied code is outside the range of the
	// contract code but touches the last leaf with contract code in it,
	// we don't include the last leaf of code in the AccessWitness.  The
	// reason that we do not need the last leaf is the account's code size
	// is already in the AccessWitness so a stateless verifier can see that
	// the code from the last leaf is not needed.
	if size == 0 || startPC >= codeLen {
		return
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
		aw.touchLocation(contractAddr, treeIndex, subIndex, isWrite)
	}
}

func (aw *AccessWitness) TouchBasicData(addr []byte, isWrite bool) {
	aw.touchLocation(addr, zeroTreeIndex, utils.BasicDataLeafKey, isWrite)
}

func (aw *AccessWitness) BasicDataGas(addr []byte, isWrite bool, warmCostCharging bool) uint64 {
	wanted := aw.calculateWitnessGasRange(addr, zeroTreeIndex, isWrite, utils.BasicDataLeafKey, utils.BasicDataLeafKey)
	if wanted == 0 && warmCostCharging {
		wanted = params.WarmStorageReadCostEIP2929
	}
	return wanted
}

func (aw *AccessWitness) TouchCodeHash(addr []byte, isWrite bool) {
	aw.touchLocation(addr, zeroTreeIndex, utils.CodeHashLeafKey, isWrite)
}

func (aw *AccessWitness) CodeHashGas(addr []byte, isWrite bool, chargeWarmCosts bool) uint64 {
	wanted := aw.calculateWitnessGasRange(addr, zeroTreeIndex, isWrite, utils.CodeHashLeafKey, utils.CodeHashLeafKey)
	if wanted == 0 && chargeWarmCosts {
		wanted = params.WarmStorageReadCostEIP2929
	}
	return wanted
}
