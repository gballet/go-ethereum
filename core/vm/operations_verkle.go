// Copyright 2024 The go-ethereum Authors
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

package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

func gasSStore4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas := evm.StateDB.Witness().TouchAddressOnWriteAndComputeGas(contract.Address().Bytes(), common.Hash(stack.peek().Bytes32()))
	if gas == 0 {
		gas = params.WarmStorageReadCostEIP2929
	}
	return gas, nil
}

func gasSLoad4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas := evm.StateDB.Witness().TouchAddressOnReadAndComputeGas(contract.Address().Bytes(), common.Hash(stack.peek().Bytes32()))
	if gas == 0 {
		gas = params.WarmStorageReadCostEIP2929
	}
	return gas, nil
}

func gasBalance4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	return evm.StateDB.Witness().TouchBalance(address[:], false), nil
}

func gasExtCodeSize4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	return evm.StateDB.Witness().TouchCodeSize(address[:], false), nil
}

func gasExtCodeHash4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	return evm.StateDB.Witness().TouchCodeHash(address[:], false), nil
}

func makeCallVariantGasEIP4762(oldCalculator gasFunc) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if err != nil {
			return 0, err
		}
		wgas, err := evm.StateDB.Witness().TouchCodeSize(contract.Address().Bytes(), false), nil
		if err != nil {
			return 0, err
		}
		gas += wgas
		wgas, err = evm.StateDB.Witness().TouchCodeHash(contract.Address().Bytes(), false), nil
		if err != nil {
			return 0, err
		}
		return wgas + gas, nil
	}
}

var (
	gasCallEIP4762         = makeCallVariantGasEIP4762(gasCall)
	gasCallCodeEIP4762     = makeCallVariantGasEIP4762(gasCallCode)
	gasStaticCallEIP4762   = makeCallVariantGasEIP4762(gasStaticCall)
	gasDelegateCallEIP4762 = makeCallVariantGasEIP4762(gasDelegateCall)
)

func gasSelfdestructEIP4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	beneficiaryAddr := common.Address(stack.peek().Bytes20())
	contractAddr := contract.Address()
	// If the beneficiary isn't the contract, we need to touch the beneficiary's balance.
	// If the beneficiary is the contract itself, there're two possibilities:
	// 1. The contract was created in the same transaction: the balance is already touched (no need to touch again)
	// 2. The contract wasn't created in the same transaction: there's no net change in balance,
	//    and SELFDESTRUCT will perform no action on the account header. (we touch since we did SubBalance+AddBalance above)
	if contractAddr != beneficiaryAddr || evm.StateDB.WasCreatedInCurrentTx(contractAddr) {
		statelessGas := evm.Accesses.TouchBalance(beneficiaryAddr[:], false)
		if !contract.UseGas(statelessGas) {
			contract.Gas = 0
			return 0, ErrOutOfGas
		}
		return statelessGas, nil
	}
	return 0, nil
}
