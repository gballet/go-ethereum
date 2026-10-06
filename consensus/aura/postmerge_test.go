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

package aura_test

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/consensus/aura"
	"github.com/ethereum/go-ethereum/consensus/aura/contracts"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/core/vm/program"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"
)

var (
	validator          = common.HexToAddress("0x1000000000000000000000000000000000000001")
	rewardContract     = common.HexToAddress("0x2000000000000000000000000000000000000001")
	rewardBeneficiary  = common.HexToAddress("0x2000000000000000000000000000000000000002")
	withdrawalContract = common.HexToAddress("0x3000000000000000000000000000000000000001")
	feeCollector       = common.HexToAddress("0x1559000000000000000000000000000000000000")
	registrar          = common.HexToAddress("0x6000000000000000000000000000000000000000")
	certifier          = common.HexToAddress("0x6000000000000000000000000000000000000001")
	balancerVault      = common.HexToAddress("0x7000000000000000000000000000000000000001")
	depositContract    = common.HexToAddress("0x8000000000000000000000000000000000000001")

	blockReward = big.NewInt(7 * params.GWei)

	originalVaultCode = []byte{byte(vm.STOP)}
	balancerCode      = []byte{byte(vm.PUSH0), byte(vm.STOP)}
	rewrittenCode     = []byte{byte(vm.PUSH0), byte(vm.PUSH0), byte(vm.STOP)}
)

// rewardContractCode answers every reward() call with a single reward of
// blockReward to rewardBeneficiary, ABI-encoded as (address[], uint256[]).
func rewardContractCode() []byte {
	var out []byte
	for _, word := range []*big.Int{
		big.NewInt(0x40), big.NewInt(0x80), // offsets of the two arrays
		big.NewInt(1), new(big.Int).SetBytes(rewardBeneficiary.Bytes()),
		big.NewInt(1), blockReward,
	} {
		out = append(out, common.BigToHash(word).Bytes()...)
	}
	return program.New().ReturnData(out).Bytes()
}

// withdrawalContractCode records the hash of its calldata in slot 0, its
// caller in slot 1 and counts its invocations in slot 2.
func withdrawalContractCode() []byte {
	return program.New().
		Op(vm.CALLDATASIZE).Push0().Push0().Op(vm.CALLDATACOPY).
		Op(vm.CALLDATASIZE).Push0().Op(vm.KECCAK256).Push0().Op(vm.SSTORE).
		Op(vm.CALLER).Push(1).Op(vm.SSTORE).
		Push(2).Op(vm.SLOAD).Push(1).Op(vm.ADD).Push(2).Op(vm.SSTORE).
		Op(vm.STOP).Bytes()
}

// certifierCode implements certified(address), returning true only for the
// given account.
func certifierCode(certified common.Address) []byte {
	return program.New().
		Push(4).Op(vm.CALLDATALOAD).Push(certified).Op(vm.EQ).
		Push0().Op(vm.MSTORE).Return(0, 32).Bytes()
}

// TestAuRaPostMerge builds a post-merge chain run by the AuRa engine through
// the chain maker, and imports it into a separate node. It checks the Gnosis
// specific state transitions that remain after the merge:
//
//   - block rewards are paid by calling the block reward contract,
//   - withdrawals are handed to the withdrawal contract instead of minted,
//   - the base fee and blob fee go to the EIP-1559 fee collector,
//   - zero-priced transactions from certified senders are free,
//   - the balancer hardfork rewrites a contract at its activation block only,
//   - rewriteBytecode replaces code at the configured block.
func TestAuRaPostMerge(t *testing.T) {
	var (
		serviceKey, _ = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		serviceAddr   = crypto.PubkeyToAddress(serviceKey.PublicKey)
		userKey, _    = crypto.HexToECDSA("8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a")
		userAddr      = crypto.PubkeyToAddress(userKey.PublicKey)
		recipient     = common.Address{0xaa}

		zero         = uint64(0)
		balancerTime = uint64(20) // block 2, as the chain maker spaces blocks by 10s
		stepDuration = uint64(5)
	)
	config := &params.ChainConfig{
		ChainID:                 big.NewInt(100),
		HomesteadBlock:          common.Big0,
		EIP150Block:             common.Big0,
		EIP155Block:             common.Big0,
		EIP158Block:             common.Big0,
		ByzantiumBlock:          common.Big0,
		ConstantinopleBlock:     common.Big0,
		PetersburgBlock:         common.Big0,
		IstanbulBlock:           common.Big0,
		BerlinBlock:             common.Big0,
		LondonBlock:             common.Big0,
		TerminalTotalDifficulty: common.Big0,
		ShanghaiTime:            &zero,
		CancunTime:              &zero,
		PragueTime:              &zero,
		BalancerTime:            &balancerTime,
		DepositContractAddress:  depositContract,
		BlobScheduleConfig:      params.GnosisChainConfig.BlobScheduleConfig,
		MinBlobGasPrice:         params.GnosisChainConfig.MinBlobGasPrice,
		MaxBlobsPerTransaction:  params.GnosisChainConfig.MaxBlobsPerTransaction,
		Aura: &params.AuRaConfig{
			StepDuration:                  &stepDuration,
			Validators:                    &params.ValidatorSetJson{List: []common.Address{validator}},
			BlockRewardContractAddress:    &rewardContract,
			BlockRewardContractTransition: &zero,
			WithdrawalContractAddress:     &withdrawalContract,
			Eip1559FeeCollector:           &feeCollector,
			Registrar:                     &registrar,
			BalancerRewriteAddress:        &balancerVault,
			BalancerRewriteCode:           balancerCode,
			RewriteBytecode: map[uint64]map[common.Address]hexutil.Bytes{
				3: {balancerVault: rewrittenCode},
			},
		},
	}
	alloc := core.SystemContractAllocs()
	alloc[rewardContract] = types.Account{Code: rewardContractCode(), Balance: common.Big0}
	alloc[withdrawalContract] = types.Account{Code: withdrawalContractCode(), Balance: common.Big0}
	alloc[registrar] = types.Account{Code: program.New().ReturnData(common.LeftPadBytes(certifier.Bytes(), 32)).Bytes(), Balance: common.Big0}
	alloc[certifier] = types.Account{Code: certifierCode(serviceAddr), Balance: common.Big0}
	alloc[balancerVault] = types.Account{Code: originalVaultCode, Balance: common.Big0}
	alloc[serviceAddr] = types.Account{Balance: big.NewInt(params.Ether)}
	alloc[userAddr] = types.Account{Balance: big.NewInt(params.Ether)}

	genesis := &core.Genesis{
		Config:     config,
		Alloc:      alloc,
		Difficulty: common.Big0,
		BaseFee:    big.NewInt(params.InitialBaseFee),
	}
	withdrawals := []*types.Withdrawal{
		{Validator: 1, Address: common.Address{0xa1}, Amount: 5},
		{Validator: 2, Address: common.Address{0xa2}, Amount: 9},
	}
	signer := types.LatestSigner(config)

	// The block producer and the importing node run independent engines, so
	// each derives the certifier and epoch data on its own.
	producer, err := aura.NewAuRa(config.Aura, rawdb.NewMemoryDatabase())
	require.NoError(t, err)
	defer producer.Close()

	db, blocks, _ := core.GenerateChainWithGenesis(genesis, beacon.New(producer), 4, func(i int, b *core.BlockGen) {
		b.SetCoinbase(validator)
		switch i {
		case 0:
			// A zero-priced transaction from a certified sender, below the
			// base fee, and the withdrawals.
			b.AddTx(types.MustSignNewTx(serviceKey, signer, &types.LegacyTx{
				Nonce: 0, GasPrice: common.Big0, Gas: params.TxGas, To: &recipient, Value: common.Big1,
			}))
			for _, w := range withdrawals {
				b.AddWithdrawal(w)
			}
		case 1:
			// Regular fee-paying transactions, one of which carries a blob.
			b.AddTx(types.MustSignNewTx(userKey, signer, &types.DynamicFeeTx{
				ChainID: config.ChainID, Nonce: 0, GasTipCap: big.NewInt(params.GWei), GasFeeCap: big.NewInt(10 * params.GWei),
				Gas: params.TxGas, To: &recipient, Value: common.Big1,
			}))
			b.AddTx(types.MustSignNewTx(userKey, signer, &types.BlobTx{
				ChainID: uint256.MustFromBig(config.ChainID), Nonce: 1, GasTipCap: uint256.NewInt(params.GWei), GasFeeCap: uint256.NewInt(10 * params.GWei),
				Gas: params.TxGas, To: recipient, Value: uint256.NewInt(1),
				BlobFeeCap: uint256.NewInt(10 * params.GWei), BlobHashes: []common.Hash{{0x01}},
			}))
		}
	})

	importer, err := aura.NewAuRa(config.Aura, db)
	require.NoError(t, err)
	defer importer.Close()

	bc, err := core.NewBlockChain(db, genesis, beacon.New(importer), nil)
	require.NoError(t, err)
	defer bc.Stop()

	n, err := bc.InsertChain(blocks)
	require.NoError(t, err)
	require.Equal(t, len(blocks), n)

	withdrawalCall, err := abi.JSON(bytes.NewReader(contracts.Withdrawal))
	require.NoError(t, err)

	var fees uint256.Int // fee collector balance expected so far
	for i, block := range blocks {
		number := block.NumberU64()
		statedb, err := bc.StateAt(block.Header())
		require.NoError(t, err)
		receipts := bc.GetReceiptsByHash(block.Hash())

		// Every block pays the reward computed by the reward contract.
		reward := new(uint256.Int).Mul(uint256.MustFromBig(blockReward), uint256.NewInt(number))
		require.Equal(t, reward, statedb.GetBalance(rewardBeneficiary), "block %d: reward beneficiary balance", number)

		// Every block calls the withdrawal contract from the system address,
		// with or without withdrawals.
		require.Equal(t, common.BigToHash(new(big.Int).SetUint64(number)), statedb.GetState(withdrawalContract, common.BigToHash(common.Big2)), "block %d: withdrawal contract calls", number)
		require.Equal(t, common.BytesToHash(params.SystemAddress.Bytes()), statedb.GetState(withdrawalContract, common.BigToHash(common.Big1)), "block %d: withdrawal contract caller", number)

		// The base fee and the blob fee go to the fee collector.
		for _, r := range receipts {
			fee := new(uint256.Int).Mul(uint256.NewInt(r.GasUsed), uint256.MustFromBig(block.BaseFee()))
			if r.BlobGasUsed > 0 {
				fee.Add(fee, new(uint256.Int).Mul(uint256.NewInt(r.BlobGasUsed), uint256.MustFromBig(r.BlobGasPrice)))
			}
			if i == 0 {
				fee.Clear() // the service transaction is free
			}
			fees.Add(&fees, fee)
		}
		require.Equal(t, &fees, statedb.GetBalance(feeCollector), "block %d: fee collector balance", number)

		switch number {
		case 1:
			// Withdrawals are passed to the contract, not credited directly.
			input, err := withdrawalCall.Pack("executeSystemWithdrawals", big.NewInt(4), []uint64{5, 9}, []common.Address{{0xa1}, {0xa2}})
			require.NoError(t, err)
			require.Equal(t, crypto.Keccak256Hash(input), statedb.GetState(withdrawalContract, common.Hash{}))
			for _, w := range withdrawals {
				require.True(t, statedb.GetBalance(w.Address).IsZero(), "withdrawal to %x was credited", w.Address)
			}
			// The service transaction went through below the base fee
			// without paying anything.
			require.Len(t, block.Transactions(), 1)
			require.Positive(t, block.BaseFee().Sign())
			require.Equal(t, uint256.NewInt(params.Ether-1), statedb.GetBalance(serviceAddr))
			require.True(t, statedb.GetBalance(validator).IsZero(), "validator was tipped by a free transaction")
			require.Equal(t, originalVaultCode, statedb.GetCode(balancerVault))
		case 2:
			// First balancer block: the vault is rewritten. The validator
			// only collects the priority fees.
			require.Equal(t, balancerCode, statedb.GetCode(balancerVault))
			tips := uint256.NewInt(2 * params.TxGas * params.GWei)
			require.Equal(t, tips, statedb.GetBalance(validator))
			require.Equal(t, uint64(params.BlobTxBlobGasPerBlob), receipts[1].BlobGasUsed)
			require.Equal(t, big.NewInt(params.GWei), receipts[1].BlobGasPrice, "blob gas price below the Gnosis minimum")
		case 3:
			require.Equal(t, rewrittenCode, statedb.GetCode(balancerVault))
		case 4:
			// The balancer rewrite only happens at the fork boundary.
			require.Equal(t, rewrittenCode, statedb.GetCode(balancerVault))
		}
	}

	// A zero-priced transaction from an uncertified sender is still rejected.
	head := bc.CurrentBlock()
	statedb, err := bc.StateAt(head)
	require.NoError(t, err)
	evm := vm.NewEVM(core.NewEVMBlockContext(head, bc, nil), statedb, config, vm.Config{})
	tx := types.MustSignNewTx(userKey, signer, &types.LegacyTx{
		Nonce: 2, GasPrice: common.Big0, Gas: params.TxGas, To: &recipient,
	})
	_, _, err = core.ApplyTransaction(t.Context(), evm, core.NewGasPool(head.GasLimit), statedb, head, tx, bc.Engine())
	require.ErrorIs(t, err, core.ErrFeeCapTooLow)
}
