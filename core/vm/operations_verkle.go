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
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/params"
)

func gasSStore4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas := evm.Accesses.TouchSlotAndChargeGas(contract.Address().Bytes(), common.Hash(stack.peek().Bytes32()), true)
	if gas == 0 {
		gas = params.WarmStorageReadCostEIP2929
	}
	return gas, nil
}

func gasSLoad4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas := evm.Accesses.TouchSlotAndChargeGas(contract.Address().Bytes(), common.Hash(stack.peek().Bytes32()), false)
	if gas == 0 {
		gas = params.WarmStorageReadCostEIP2929
	}
	return gas, nil
}

func gasBalance4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	gas := evm.Accesses.TouchBasicData(address[:], false)
	if gas == 0 {
		gas = params.WarmStorageReadCostEIP2929
	}
	return gas, nil
}

func gasExtCodeSize4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	if _, isPrecompile := evm.precompile(address); isPrecompile {
		return 0, nil
	}
	wgas := evm.Accesses.TouchBasicData(address[:], false)
	if wgas == 0 {
		wgas = params.WarmStorageReadCostEIP2929
	}
	return wgas, nil
}

func gasExtCodeHash4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	if _, isPrecompile := evm.precompile(address); isPrecompile || evm.isSystemContract(address) {
		return 0, nil
	}
	codehashgas := evm.Accesses.TouchCodeHash(address[:], false)
	if codehashgas == 0 {
		codehashgas = params.WarmStorageReadCostEIP2929
	}
	return codehashgas, nil
}

func makeCallVariantGasEIP4762(oldCalculator gasFunc) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
		if err != nil {
			return 0, err
		}
		target := common.Address(stack.Back(1).Bytes20())
		if _, isPrecompile := evm.precompile(target); isPrecompile {
			return gas, nil
		}
		// The charging for the value transfer is done BEFORE subtracting
		// the 1/64th gas, as this is considered part of the CALL instruction.
		// (so before we get to this point)
		// But the message call is part of the subcall, for which only 63/64th
		// of the gas should be available.
		wgas := evm.Accesses.TouchAndChargeMessageCall(target.Bytes())
		if wgas == 0 {
			wgas = params.WarmStorageReadCostEIP2929
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

	statelessGas := evm.Accesses.TouchBasicData(contractAddr[:], false)
	balanceIsZero := evm.StateDB.GetBalance(contractAddr).Sign() == 0

	if _, isPrecompile := evm.precompile(beneficiaryAddr); isPrecompile && balanceIsZero {
		return statelessGas, nil
	}

	if contractAddr != beneficiaryAddr {
		statelessGas += evm.Accesses.TouchBasicData(beneficiaryAddr[:], false)
	}
	// Charge write costs if it transfers value
	if !balanceIsZero {
		statelessGas += evm.Accesses.TouchBasicData(contractAddr[:], true)
		if contractAddr != beneficiaryAddr {
			if evm.StateDB.Exist(beneficiaryAddr) {
				statelessGas += evm.Accesses.TouchBasicData(beneficiaryAddr[:], true)
			} else {
				statelessGas += evm.Accesses.TouchFullAccount(beneficiaryAddr[:], true)
			}
		}
	}
	return statelessGas, nil
}

func gasExtCodeCopyEIP4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	// memory expansion first (dynamic part of pre-2929 implementation)
	gas, err := gasExtCodeCopy(evm, contract, stack, mem, memorySize)
	if err != nil {
		return 0, err
	}
	addr := common.Address(stack.peek().Bytes20())

	if _, isPrecompile := evm.precompile(addr); isPrecompile {
		return gas, nil
	}
	wgas := evm.Accesses.TouchBasicData(addr[:], false)
	if wgas == 0 {
		wgas = params.WarmStorageReadCostEIP2929
	}
	var overflow bool
	// We charge (cold-warm), since 'warm' is already charged as constantGas
	if gas, overflow = math.SafeAdd(gas, wgas); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}
