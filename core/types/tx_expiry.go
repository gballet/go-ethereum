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

package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-verkle"
	"github.com/holiman/uint256"
)

type ReviveList []ReviveValue

type ReviveValue struct {
	Stem verkle.Stem `json:"stem"`
	LastPeriod verkle.StatePeriod `json:"last_period"`
	Values [][]byte `json:"values"`
}

// ReviveTx represents an EIP-7736 resurrect transaction.
type ReviveTx struct {
	ChainID    *uint256.Int
	Nonce      uint64
	GasTipCap  *uint256.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *uint256.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *uint256.Int
	Data       []byte
	AccessList AccessList
	ReviveList ReviveList // TODO(weiihann): this should be ssz(Vector[stem,last_epoch,values], do it later

	// Signature values
	V *uint256.Int `json:"v" gencodec:"required"`
	R *uint256.Int `json:"r" gencodec:"required"`
	S *uint256.Int `json:"s" gencodec:"required"`
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *ReviveTx) copy() TxData {
	cpy := &ReviveTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(uint256.Int),
		ChainID:    new(uint256.Int),
		GasTipCap:  new(uint256.Int),
		GasFeeCap:  new(uint256.Int),
		V:          new(uint256.Int),
		R:          new(uint256.Int),
		S:          new(uint256.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}

	cpy.ReviveList = make([]ReviveValue, len(tx.ReviveList))
	for i, revive := range tx.ReviveList {
		cpy.ReviveList[i] = revive
	}

	return cpy
}

// accessors for innerTx.
func (tx *ReviveTx) txType() byte              { return ReviveTxType }
func (tx *ReviveTx) chainID() *big.Int         { return tx.ChainID.ToBig() }
func (tx *ReviveTx) accessList() AccessList    { return tx.AccessList }
func (tx *ReviveTx) data() []byte              { return tx.Data }
func (tx *ReviveTx) gas() uint64               { return tx.Gas }
func (tx *ReviveTx) gasFeeCap() *big.Int       { return tx.GasFeeCap.ToBig() }
func (tx *ReviveTx) gasTipCap() *big.Int       { return tx.GasTipCap.ToBig() }
func (tx *ReviveTx) gasPrice() *big.Int        { return tx.GasFeeCap.ToBig() }
func (tx *ReviveTx) value() *big.Int           { return tx.Value.ToBig() }
func (tx *ReviveTx) nonce() uint64             { return tx.Nonce }
func (tx *ReviveTx) to() *common.Address       { return tx.To }
func (tx *ReviveTx) blobGas() uint64           { return 0 }
func (tx *ReviveTx) blobGasFeeCap() *big.Int   { return nil }
func (tx *ReviveTx) blobHashes() []common.Hash { return nil }
func (tx *ReviveTx) reviveList() []ReviveValue { return tx.ReviveList }
func (tx *ReviveTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap.ToBig())
	}
	tip := dst.Sub(tx.GasFeeCap.ToBig(), baseFee)
	if tip.Cmp(tx.GasTipCap.ToBig()) > 0 {
		tip.Set(tx.GasTipCap.ToBig())
	}
	return tip.Add(tip, baseFee)
}

func (tx *ReviveTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V.ToBig(), tx.R.ToBig(), tx.S.ToBig()
}

func (tx *ReviveTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID.SetFromBig(chainID)
	tx.V.SetFromBig(v)
	tx.R.SetFromBig(r)
	tx.S.SetFromBig(s)
}
