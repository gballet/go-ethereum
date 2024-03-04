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

package state

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type ALAccessMode bool

var (
	AccessListRead  = ALAccessMode(false)
	AccessListWrite = ALAccessMode(true)
)

type ALAccountItem uint64

const (
	ALVersion = ALAccountItem(1 << iota)
	ALBalance
	ALNonce
	ALCodeHash
	ALCodeSize
	ALLastHeaderItem
)

const ALAllItems = ALVersion | ALBalance | ALNonce | ALCodeSize | ALCodeHash

type AccessList interface {
	ContainsAddress(address common.Address) bool
	Contains(address common.Address, slot common.Hash) (addressPresent bool, slotPresent bool)
	Copy() AccessList
	AddAddress(address common.Address, items ALAccountItem, isWrite ALAccessMode) uint64
	AddSlot(address common.Address, slot common.Hash, isWrite ALAccessMode) uint64
	DeleteSlot(address common.Address, slot common.Hash)
	DeleteAddress(address common.Address)

	TouchAndChargeValueTransfer(callerAddr, targetAddr []byte) uint64
	TouchAndChargeContractCreateInit(addr []byte, createSendsValue bool) uint64
	TouchTxOriginAndComputeGas(originAddr []byte) uint64
	TouchTxExistingAndComputeGas(targetAddr []byte, sendsValue bool) uint64
	TouchAddressOnReadAndComputeGas(addr []byte, index uint256.Int, suffix byte) uint64
	Merge(AccessList)
	Keys() [][]byte
}

type accessList2929 struct {
	addresses map[common.Address]int
	slots     []map[common.Hash]struct{}
}

// ContainsAddress returns true if the address is in the access list.
func (al *accessList2929) ContainsAddress(address common.Address) bool {
	_, ok := al.addresses[address]
	return ok
}

// Contains checks if a slot within an account is present in the access list, returning
// separate flags for the presence of the account and the slot respectively.
func (al *accessList2929) Contains(address common.Address, slot common.Hash) (addressPresent bool, slotPresent bool) {
	idx, ok := al.addresses[address]
	if !ok {
		// no such address (and hence zero slots)
		return false, false
	}
	if idx == -1 {
		// address yes, but no slots
		return true, false
	}
	_, slotPresent = al.slots[idx][slot]
	return true, slotPresent
}

// newAccessList creates a new accessList.
func newAccessList() AccessList {
	return &accessList2929{
		addresses: make(map[common.Address]int),
	}
}

// Copy creates an independent copy of an accessList.
func (a *accessList2929) Copy() AccessList {
	cp := newAccessList().(*accessList2929)
	for k, v := range a.addresses {
		cp.addresses[k] = v
	}
	cp.slots = make([]map[common.Hash]struct{}, len(a.slots))
	for i, slotMap := range a.slots {
		newSlotmap := make(map[common.Hash]struct{}, len(slotMap))
		for k := range slotMap {
			newSlotmap[k] = struct{}{}
		}
		cp.slots[i] = newSlotmap
	}
	return cp
}

// AddAddress adds an address to the access list, and returns 'true' if the operation
// caused a change (addr was not previously in the list).
func (al *accessList2929) AddAddress(address common.Address, _ ALAccountItem, _ ALAccessMode) uint64 {
	if _, present := al.addresses[address]; present {
		return params.WarmStorageReadCostEIP2929
	}
	al.addresses[address] = -1
	return params.ColdAccountAccessCostEIP2929
}

// AddSlot adds the specified (addr, slot) combo to the access list.
// Returns the gas consumed.
func (al *accessList2929) AddSlot(address common.Address, slot common.Hash, _ ALAccessMode) (gas uint64) {
	idx, addrPresent := al.addresses[address]
	if !addrPresent || idx == -1 {
		// Address not present, or addr present but no slots there
		al.addresses[address] = len(al.slots)
		slotmap := map[common.Hash]struct{}{slot: {}}
		al.slots = append(al.slots, slotmap)
		return params.WarmStorageReadCostEIP2929
	}
	// There is already an (address,slot) mapping
	slotmap := al.slots[idx]
	if _, ok := slotmap[slot]; !ok {
		slotmap[slot] = struct{}{}
		// Journal add slot change
		return params.ColdAccountAccessCostEIP2929
	}
	// No changes required
	return params.WarmStorageReadCostEIP2929
}

// DeleteSlot removes an (address, slot)-tuple from the access list.
// This operation needs to be performed in the same order as the addition happened.
// This method is meant to be used  by the journal, which maintains ordering of
// operations.
func (al *accessList2929) DeleteSlot(address common.Address, slot common.Hash) {
	idx, addrOk := al.addresses[address]
	// There are two ways this can fail
	if !addrOk {
		panic("reverting slot change, address not present in list")
	}
	slotmap := al.slots[idx]
	delete(slotmap, slot)
	// If that was the last (first) slot, remove it
	// Since additions and rollbacks are always performed in order,
	// we can delete the item without worrying about screwing up later indices
	if len(slotmap) == 0 {
		al.slots = al.slots[:idx]
		al.addresses[address] = -1
	}
}

// DeleteAddress removes an address from the access list. This operation
// needs to be performed in the same order as the addition happened.
// This method is meant to be used  by the journal, which maintains ordering of
// operations.
func (al *accessList2929) DeleteAddress(address common.Address) {
	delete(al.addresses, address)
}

func (al *accessList2929) TouchAndChargeValueTransfer(callerAddr []byte, targetAddr []byte) uint64 {
	return 0
}

func (al *accessList2929) TouchAndChargeContractCreateInit(addr []byte, createSendsValue bool) uint64 {
	return 0
}

func (al *accessList2929) TouchTxOriginAndComputeGas(originAddr []byte) uint64 {
	return 0
}

func (al *accessList2929) TouchTxExistingAndComputeGas(targetAddr []byte, sendsValue bool) uint64 {
	return 0
}

func (al *accessList2929) TouchAddressOnReadAndComputeGas(addr []byte, index uint256.Int, subIndex byte) uint64 {
	return 0
}

func (al *accessList2929) Merge(other AccessList) {}
func (al *accessList2929) Keys() [][]byte         { return nil }
