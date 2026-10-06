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

package aura

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

// initiateChangeLog builds an InitiateChange(bytes32 indexed, address[]) log as
// emitted by a validator set contract.
func initiateChangeLog(t *testing.T, s *ValidatorSafeContract, emitter common.Address, parentHash common.Hash, set []common.Address) *types.Log {
	t.Helper()
	data, err := s.abi.Events["InitiateChange"].Inputs.NonIndexed().Pack(set)
	require.NoError(t, err)
	return &types.Log{
		Address: emitter,
		Topics:  []common.Hash{EVENT_NAME_HASH, parentHash},
		Data:    data,
	}
}

// auraHeader returns a pre-merge AuRa header, which RLP-encodes the step and
// signature in place of the mix digest and nonce.
func auraHeader(number uint64, parentHash common.Hash) *types.Header {
	return &types.Header{
		ParentHash: parentHash,
		Coinbase:   common.Address{0xc0},
		Number:     new(big.Int).SetUint64(number),
		Difficulty: big.NewInt(1),
		GasLimit:   10_000_000,
		Time:       number * 5,
		Step:       number,
		Signature:  make([]byte, 65),
	}
}

// TestSafeContractEpochSignal checks that a validator set change signalled by
// the InitiateChange event is detected, serialised into a pending epoch proof,
// and recovered from that proof.
func TestSafeContractEpochSignal(t *testing.T) {
	var (
		contract   = common.HexToAddress("0x22e1229a2c5b95a60983b5577f745a603284f535")
		parentHash = common.Hash{0x01}
		header     = auraHeader(1301, parentHash)
		s          = NewValidatorSafeContract(contract, nil)

		setA = []common.Address{{0xa1}, {0xa2}}
		setB = []common.Address{{0xb1}, {0xb2}, {0xb3}}
	)
	receipts := types.Receipts{
		{Status: types.ReceiptStatusSuccessful, Logs: []*types.Log{
			initiateChangeLog(t, s, contract, parentHash, setA),
		}},
		{Status: types.ReceiptStatusSuccessful, Logs: []*types.Log{
			// Ignored: emitted by another contract.
			initiateChangeLog(t, s, common.Address{0xee}, parentHash, []common.Address{{0xee}}),
			// Ignored: signals a change on top of another parent.
			initiateChangeLog(t, s, contract, common.Hash{0xff}, []common.Address{{0xff}}),
			initiateChangeLog(t, s, contract, parentHash, setB),
		}},
		{Status: types.ReceiptStatusSuccessful},
	}

	// Only the last change in the block takes effect.
	set, ok := s.extractFromEvent(header, receipts)
	require.True(t, ok)
	require.Equal(t, setB, set.validators)

	proof, err := s.signalEpochEnd(false, header, receipts)
	require.NoError(t, err)
	require.NotNil(t, proof)

	got, _, err := s.epochSet(false, header.Number.Uint64(), proof, nil)
	require.NoError(t, err)
	require.Equal(t, setB, got.validators)
}

// TestSafeContractNoEpochSignal checks that blocks without a matching
// InitiateChange event do not produce a pending epoch.
func TestSafeContractNoEpochSignal(t *testing.T) {
	var (
		contract   = common.HexToAddress("0x22e1229a2c5b95a60983b5577f745a603284f535")
		parentHash = common.Hash{0x01}
		header     = auraHeader(1301, parentHash)
		s          = NewValidatorSafeContract(contract, nil)
	)
	for name, receipts := range map[string]types.Receipts{
		"no receipts": nil,
		"no logs":     {{Status: types.ReceiptStatusSuccessful}},
		"stale parent": {{Status: types.ReceiptStatusSuccessful, Logs: []*types.Log{
			initiateChangeLog(t, s, contract, common.Hash{0xff}, []common.Address{{0xff}}),
		}}},
	} {
		proof, err := s.signalEpochEnd(false, header, receipts)
		require.NoError(t, err, name)
		require.Nil(t, proof, name)
	}
}

// TestSafeContractFirstEpoch checks that the first block of a safe contract
// validator set always signals an epoch, and that at genesis the set is
// recovered from the proof alone as the block author.
func TestSafeContractFirstEpoch(t *testing.T) {
	var (
		contract = common.HexToAddress("0x22e1229a2c5b95a60983b5577f745a603284f535")
		header   = auraHeader(0, common.Hash{})
		s        = NewValidatorSafeContract(contract, nil)
	)
	proof, err := s.signalEpochEnd(true, header, nil)
	require.NoError(t, err)
	require.NotNil(t, proof)

	set, _, err := s.epochSet(true, 0, proof, nil)
	require.NoError(t, err)
	require.Equal(t, []common.Address{header.Coinbase}, set.validators)
}
