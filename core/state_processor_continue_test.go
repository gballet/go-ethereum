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
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// TestProcessContinueOnInvalidTx covers vm.Config.ContinueOnInvalidTx, the mode
// the t8n tool runs in: its input is a bare list of transactions rather than a
// validated block, so an inapplicable transaction must be skipped and reported
// instead of invalidating everything after it.
func TestProcessContinueOnInvalidTx(t *testing.T) {
	var (
		config  = params.MergedTestChainConfig
		signer  = types.LatestSigner(config)
		key, _  = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr    = crypto.PubkeyToAddress(key.PublicKey)
		to      = common.Address{0xaa}
		gasCost = big.NewInt(875000000)
	)
	makeGasTx := func(nonce uint64, amount *big.Int, gas uint64) *types.Transaction {
		tx, err := types.SignTx(types.NewTransaction(nonce, to, amount, gas, gasCost, nil), signer, key)
		if err != nil {
			t.Fatalf("sign tx: %v", err)
		}
		return tx
	}
	makeTx := func(nonce uint64, amount *big.Int) *types.Transaction {
		return makeGasTx(nonce, amount, params.TxGas)
	}
	// The two middle transactions cannot be applied. They fail at different
	// points on purpose: the nonce is rejected before the state is touched at
	// all, while the gas limit is rejected only after the sender has already
	// been debited, which is what the rollback has to undo.
	txs := types.Transactions{
		makeTx(0, big.NewInt(1)),
		makeTx(100, big.NewInt(2)),
		makeGasTx(1, big.NewInt(5), params.TxGas-1),
		makeTx(1, big.NewInt(3)),
	}
	// The same block without the transactions that get skipped. Processing it
	// must leave the state in exactly the same place.
	cleanTxs := types.Transactions{txs[0], txs[3]}
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			addr: types.Account{Balance: big.NewInt(1000000000000000000)},
		},
	}
	engine := beacon.New(ethash.NewFaker())
	block := GenerateBadBlock(gspec.ToBlock(), engine, txs, config, false)

	newChain := func() *BlockChain {
		t.Helper()
		bc, err := NewBlockChain(rawdb.NewMemoryDatabase(), gspec, engine, nil)
		if err != nil {
			t.Fatalf("new blockchain: %v", err)
		}
		return bc
	}

	// Without the flag the block is simply invalid, which is what consensus
	// block processing must keep doing.
	t.Run("disabled", func(t *testing.T) {
		bc := newChain()
		defer bc.Stop()

		statedb, err := bc.State()
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		_, err = NewStateProcessor(bc).Process(context.Background(), block, statedb, nil, nil, vm.Config{}, nil)
		if err == nil {
			t.Fatal("processed a block with an inapplicable transaction without an error")
		}
		if !strings.Contains(err.Error(), "nonce too high") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("enabled", func(t *testing.T) {
		bc := newChain()
		defer bc.Stop()

		statedb, err := bc.State()
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		res, err := NewStateProcessor(bc).Process(context.Background(), block, statedb, nil, nil, vm.Config{ContinueOnInvalidTx: true}, nil)
		if err != nil {
			t.Fatalf("process: %v", err)
		}
		// Both offenders are reported by their position in the block.
		if len(res.Rejected) != 2 {
			t.Fatalf("rejected transactions: got %d, want 2", len(res.Rejected))
		}
		if got := []int{res.Rejected[0].Index, res.Rejected[1].Index}; got[0] != 1 || got[1] != 2 {
			t.Errorf("rejected indices: got %v, want [1 2]", got)
		}
		if !strings.Contains(res.Rejected[0].Err, "nonce too high") {
			t.Errorf("first rejection: got %q, want it to mention the nonce", res.Rejected[0].Err)
		}
		if !strings.Contains(res.Rejected[1].Err, "intrinsic gas") {
			t.Errorf("second rejection: got %q, want it to mention intrinsic gas", res.Rejected[1].Err)
		}
		// The surviving transactions are applied, and are numbered without a
		// hole where the skipped ones would have been.
		if len(res.Receipts) != 2 {
			t.Fatalf("receipts: got %d, want 2", len(res.Receipts))
		}
		for i, receipt := range res.Receipts {
			if got := receipt.TransactionIndex; got != uint(i) {
				t.Errorf("receipt %d: transaction index %d, want %d", i, got, i)
			}
			if receipt.Status != types.ReceiptStatusSuccessful {
				t.Errorf("receipt %d: unsuccessful", i)
			}
		}
		if got, want := res.Receipts[0].TxHash, txs[0].Hash(); got != want {
			t.Errorf("first receipt is for %x, want %x", got, want)
		}
		if got, want := res.Receipts[1].TxHash, txs[3].Hash(); got != want {
			t.Errorf("second receipt is for %x, want %x", got, want)
		}
		// The skipped transactions consume no gas, and the cumulative gas of the
		// surviving ones stays contiguous.
		if got, want := res.GasUsed, 2*params.TxGas; got != want {
			t.Errorf("gas used: got %d, want %d", got, want)
		}
		if got, want := res.Receipts[1].CumulativeGasUsed, 2*params.TxGas; got != want {
			t.Errorf("cumulative gas: got %d, want %d", got, want)
		}
		// The state must look as if the skipped transactions never ran: the nonce
		// only advances for the two that did, and the recipient only received
		// their values.
		if got, want := statedb.GetNonce(addr), uint64(2); got != want {
			t.Errorf("sender nonce: got %d, want %d", got, want)
		}
		if got, want := statedb.GetBalance(to).Uint64(), uint64(4); got != want {
			t.Errorf("recipient balance: got %d, want %d", got, want)
		}
		// Strongest form of the same property: a rejected transaction must leave
		// no trace at all, so the resulting state has to be indistinguishable
		// from processing a block that never contained them. This is what catches
		// a failure that is only rolled back partially, such as the sender having
		// already paid for the gas.
		rules := config.Rules(block.Number(), true, block.Time())
		cleanChain := newChain()
		defer cleanChain.Stop()

		cleanState, err := cleanChain.State()
		if err != nil {
			t.Fatalf("state: %v", err)
		}
		cleanBlock := GenerateBadBlock(gspec.ToBlock(), engine, cleanTxs, config, false)
		if _, err := NewStateProcessor(cleanChain).Process(context.Background(), cleanBlock, cleanState, nil, nil, vm.Config{}, nil); err != nil {
			t.Fatalf("process clean block: %v", err)
		}
		if got, want := statedb.IntermediateRoot(rules), cleanState.IntermediateRoot(rules); got != want {
			t.Errorf("state root %x after skipping, want %x from a block without the skipped transactions", got, want)
		}
	})
}

// TestProcessContinueOnUndecodableSender covers the other rejection path: a
// transaction whose sender cannot be recovered never reaches execution, so it
// is skipped before the state is touched.
func TestProcessContinueOnUndecodableSender(t *testing.T) {
	var (
		config = params.MergedTestChainConfig
		signer = types.LatestSigner(config)
		key, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr   = crypto.PubkeyToAddress(key.PublicKey)
		to     = common.Address{0xaa}
	)
	valid, err := types.SignTx(types.NewTransaction(0, to, big.NewInt(1), params.TxGas, big.NewInt(875000000), nil), signer, key)
	if err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	// Signed for a different chain, so sender recovery fails for this signer.
	otherChain := types.LatestSigner(&params.ChainConfig{ChainID: big.NewInt(1337), HomesteadBlock: new(big.Int), EIP155Block: new(big.Int)})
	foreign, err := types.SignTx(types.NewTransaction(1, to, big.NewInt(2), params.TxGas, big.NewInt(875000000), nil), otherChain, key)
	if err != nil {
		t.Fatalf("sign tx: %v", err)
	}
	gspec := &Genesis{
		Config: config,
		Alloc: types.GenesisAlloc{
			addr: types.Account{Balance: big.NewInt(1000000000000000000)},
		},
	}
	engine := beacon.New(ethash.NewFaker())
	block := GenerateBadBlock(gspec.ToBlock(), engine, types.Transactions{valid, foreign}, config, false)

	bc, err := NewBlockChain(rawdb.NewMemoryDatabase(), gspec, engine, nil)
	if err != nil {
		t.Fatalf("new blockchain: %v", err)
	}
	defer bc.Stop()

	statedb, err := bc.State()
	if err != nil {
		t.Fatalf("state: %v", err)
	}
	res, err := NewStateProcessor(bc).Process(context.Background(), block, statedb, nil, nil, vm.Config{ContinueOnInvalidTx: true}, nil)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if len(res.Rejected) != 1 || res.Rejected[0].Index != 1 {
		t.Fatalf("rejected: %+v, want exactly the transaction at index 1", res.Rejected)
	}
	if len(res.Receipts) != 1 {
		t.Fatalf("receipts: got %d, want 1", len(res.Receipts))
	}
	if got, want := res.GasUsed, params.TxGas; got != want {
		t.Errorf("gas used: got %d, want %d", got, want)
	}
}
