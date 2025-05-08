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
	return evm.Accesses.SlotGas(contract.Address().Bytes(), common.Hash(stack.peek().Bytes32()), true), nil
}

func gasSLoad4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	return evm.Accesses.SlotGas(contract.Address().Bytes(), common.Hash(stack.peek().Bytes32()), false), nil
}

func gasBalance4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	return evm.Accesses.BasicDataGas(address[:], false, true), nil
}

func gasExtCodeSize4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	isSystemContract := evm.isSystemContract(address)
	_, isPrecompile := evm.precompile(address)
	if isPrecompile || isSystemContract {
		return params.WarmStorageReadCostEIP2929, nil
	}
	return evm.Accesses.BasicDataGas(address[:], false, true), nil
}

func gasExtCodeHash4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	address := stack.peek().Bytes20()
	if _, isPrecompile := evm.precompile(address); isPrecompile || evm.isSystemContract(address) {
		return params.WarmStorageReadCostEIP2929, nil
	}
	return evm.Accesses.CodeHashGas(address[:], false, true), nil
}

func makeCallVariantGasEIP4762(oldCalculator gasFunc, withTransferCosts bool) gasFunc {
	return func(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
		var (
			target           = common.Address(stack.Back(1).Bytes20())
			witnessGas       uint64
			_, isPrecompile  = evm.precompile(target)
			isSystemContract = evm.isSystemContract(target)
		)

		// If value is transferred, it is charged before 1/64th
		// is subtracted from the available gas pool.
		if withTransferCosts && !stack.Back(2).IsZero() {
			wantedValueTransferWitnessGas := evm.Accesses.ValueTransferGas(contract.Address().Bytes(), target[:])
			if wantedValueTransferWitnessGas > contract.Gas {
				return 0, ErrOutOfGas
			}
			evm.Accesses.TouchValueTransfer(contract.Address().Bytes(), target[:])
			witnessGas = wantedValueTransferWitnessGas
		} else if isPrecompile || isSystemContract {
			witnessGas = params.WarmStorageReadCostEIP2929
		} else {
			// The charging for the value transfer is done BEFORE subtracting
			// the 1/64th gas, as this is considered part of the CALL instruction.
			// (so before we get to this point)
			// But the message call is part of the subcall, for which only 63/64th
			// of the gas should be available.
			wantedMessageCallWitnessGas := evm.Accesses.MessageCallGas(target.Bytes())
			var overflow bool
			if witnessGas, overflow = math.SafeAdd(witnessGas, wantedMessageCallWitnessGas); overflow {
				return 0, ErrGasUintOverflow
			}
			if witnessGas > contract.Gas {
				return 0, ErrOutOfGas
			}
			evm.Accesses.TouchMessageCall(target.Bytes())
		}

		contract.Gas -= witnessGas
		// if the operation fails, adds witness gas to the gas before returning the error
		gas, err := oldCalculator(evm, contract, stack, mem, memorySize)
		contract.Gas += witnessGas // restore witness gas so that it can be charged at the callsite
		var overflow bool
		if gas, overflow = math.SafeAdd(gas, witnessGas); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, err
	}
}

var (
	gasCallEIP4762         = makeCallVariantGasEIP4762(gasCall, true)
	gasCallCodeEIP4762     = makeCallVariantGasEIP4762(gasCallCode, false)
	gasStaticCallEIP4762   = makeCallVariantGasEIP4762(gasStaticCall, false)
	gasDelegateCallEIP4762 = makeCallVariantGasEIP4762(gasDelegateCall, false)
)

func gasSelfdestructEIP4762(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	beneficiaryAddr := common.Address(stack.peek().Bytes20())
	contractAddr := contract.Address()

	statelessGas := evm.Accesses.BasicDataGas(contractAddr[:], false, false)
	if statelessGas > contract.Gas {
		return 0, ErrOutOfGas
	}
	evm.Accesses.TouchBasicData(contractAddr[:], false)

	balanceIsZero := evm.StateDB.GetBalance(contractAddr).Sign() == 0
	_, isPrecompile := evm.precompile(beneficiaryAddr)
	isSystemContract := evm.isSystemContract(beneficiaryAddr)

	if (isPrecompile || isSystemContract) && balanceIsZero {
		return statelessGas, nil
	}

	if contractAddr != beneficiaryAddr {
		wanted := evm.Accesses.BasicDataGas(beneficiaryAddr[:], false, false)
		if wanted > contract.Gas-statelessGas {
			return statelessGas + wanted, nil
		}
		statelessGas += wanted
		evm.Accesses.TouchBasicData(beneficiaryAddr[:], false)
	}
	// Charge write costs if it transfers value
	if !balanceIsZero {
		wanted := evm.Accesses.BasicDataGas(contractAddr[:], true, false)
		if wanted > contract.Gas-statelessGas {
			return 0, ErrOutOfGas
		}
		statelessGas += wanted
		evm.Accesses.TouchBasicData(contractAddr[:], true)

		if contractAddr != beneficiaryAddr {
			if evm.StateDB.Exist(beneficiaryAddr) {
				wanted = evm.Accesses.BasicDataGas(beneficiaryAddr[:], true, false)
			} else {
				wanted = evm.Accesses.FullAccountGas(beneficiaryAddr[:], true)
			}
			if wanted > contract.Gas-statelessGas {
				return 0, ErrOutOfGas
			}
			statelessGas += wanted
			if evm.StateDB.Exist(beneficiaryAddr) {
				evm.Accesses.TouchBasicData(beneficiaryAddr[:], true)
			} else {
				evm.Accesses.TouchFullAccount(beneficiaryAddr[:], true)
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

	isSystemContract := evm.isSystemContract(addr)
	_, isPrecompile := evm.precompile(addr)
	if isPrecompile || isSystemContract {
		var overflow bool
		if gas, overflow = math.SafeAdd(gas, params.WarmStorageReadCostEIP2929); overflow {
			return 0, ErrGasUintOverflow
		}
		return gas, nil
	}
	wgas := evm.Accesses.BasicDataGas(addr[:], false, true)
	var overflow bool
	if gas, overflow = math.SafeAdd(gas, wgas); overflow {
		return 0, ErrGasUintOverflow
	}
	evm.Accesses.TouchBasicData(addr[:], false)
	return gas, nil
}
