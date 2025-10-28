// Copyright 2025 The go-ethereum Authors
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
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

// TestExecutePrecompile tests the EXECUTE precompile
func TestExecutePrecompile(t *testing.T) {
	testCases := []struct {
		name        string
		input       func() []byte
		expectedGas uint64
		expectError bool
	}{
		{
			name: "minimal valid input with no hashes",
			input: func() []byte {
				input := make([]byte, 256)
				// Chain ID = 1
				copy(input[31:32], []byte{0x01})
				// Pre-state hash = 0x1234...
				copy(input[32:34], []byte{0x12, 0x34})
				// Block gas limit = 30000000
				gasLimit := big.NewInt(30000000)
				copy(input[64:96], common.LeftPadBytes(gasLimit.Bytes(), 32))
				// Array length = 0
				// Coinbase = 0x0123456789abcdef...
				copy(input[128:148], common.HexToAddress("0x0123456789abcdef0123456789abcdef01234567").Bytes())
				// Block number = 1000
				blockNum := big.NewInt(1000)
				copy(input[160:192], common.LeftPadBytes(blockNum.Bytes(), 32))
				// Block fee per gas = 1000000000 (1 gwei)
				feePerGas := big.NewInt(1000000000)
				copy(input[192:224], common.LeftPadBytes(feePerGas.Bytes(), 32))
				// Timestamp = 1700000000
				timestamp := big.NewInt(1700000000)
				copy(input[224:256], common.LeftPadBytes(timestamp.Bytes(), 32))
				return input
			},
			expectedGas: params.ExecuteBaseGas,
			expectError: false,
		},
		{
			name: "valid input with 3 hashes",
			input: func() []byte {
				input := make([]byte, 256+3*32)
				// Chain ID = 1
				copy(input[31:32], []byte{0x01})
				// Pre-state hash = 0x1234...
				copy(input[32:34], []byte{0x12, 0x34})
				// Block gas limit = 30000000
				gasLimit := big.NewInt(30000000)
				copy(input[64:96], common.LeftPadBytes(gasLimit.Bytes(), 32))
				// Array length = 3
				arrayLen := big.NewInt(3)
				copy(input[96:128], common.LeftPadBytes(arrayLen.Bytes(), 32))
				// Coinbase
				copy(input[128:148], common.HexToAddress("0x0123456789abcdef0123456789abcdef01234567").Bytes())
				// Block number = 1000
				blockNum := big.NewInt(1000)
				copy(input[160:192], common.LeftPadBytes(blockNum.Bytes(), 32))
				// Block fee per gas = 1000000000
				feePerGas := big.NewInt(1000000000)
				copy(input[192:224], common.LeftPadBytes(feePerGas.Bytes(), 32))
				// Timestamp = 1700000000
				timestamp := big.NewInt(1700000000)
				copy(input[224:256], common.LeftPadBytes(timestamp.Bytes(), 32))
				// Add 3 hashes
				for i := 0; i < 3; i++ {
					copy(input[256+i*32:256+(i+1)*32], bytes.Repeat([]byte{byte(i + 1)}, 32))
				}
				return input
			},
			expectedGas: params.ExecuteBaseGas + 3*params.ExecutePerHashGas,
			expectError: false,
		},
		{
			name: "input too short",
			input: func() []byte {
				return make([]byte, 255) // One byte short
			},
			expectedGas: params.ExecuteBaseGas,
			expectError: true,
		},
		{
			name: "array length exceeds max",
			input: func() []byte {
				input := make([]byte, 256)
				// Set array length to max + 1
				arrayLen := big.NewInt(int64(params.ExecuteMaxHashes + 1))
				copy(input[96:128], common.LeftPadBytes(arrayLen.Bytes(), 32))
				return input
			},
			expectedGas: params.ExecuteBaseGas + params.ExecuteMaxHashes*params.ExecutePerHashGas,
			expectError: true,
		},
		{
			name: "array length specified but input too short for hashes",
			input: func() []byte {
				input := make([]byte, 256)
				// Set array length to 5 but don't provide the hashes
				arrayLen := big.NewInt(5)
				copy(input[96:128], common.LeftPadBytes(arrayLen.Bytes(), 32))
				return input
			},
			expectedGas: params.ExecuteBaseGas + 5*params.ExecutePerHashGas,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			executePrecompile := &execute{}
			input := tc.input()

			// Test gas calculation
			gas := executePrecompile.RequiredGas(input)
			if gas != tc.expectedGas {
				t.Errorf("gas mismatch: expected %d, got %d", tc.expectedGas, gas)
			}

			// Test execution
			output, err := executePrecompile.Run(input)
			if tc.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tc.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.expectError && len(output) != 0 {
				t.Errorf("expected empty output but got %d bytes", len(output))
			}
		})
	}
}

// TestExecutePrecompileGasEdgeCases tests edge cases for gas calculation
func TestExecutePrecompileGasEdgeCases(t *testing.T) {
	executePrecompile := &execute{}

	testCases := []struct {
		name        string
		arrayLen    uint64
		expectedGas uint64
	}{
		{
			name:        "zero hashes",
			arrayLen:    0,
			expectedGas: params.ExecuteBaseGas,
		},
		{
			name:        "one hash",
			arrayLen:    1,
			expectedGas: params.ExecuteBaseGas + params.ExecutePerHashGas,
		},
		{
			name:        "max hashes",
			arrayLen:    params.ExecuteMaxHashes,
			expectedGas: params.ExecuteBaseGas + params.ExecuteMaxHashes*params.ExecutePerHashGas,
		},
		{
			name:        "over max hashes",
			arrayLen:    params.ExecuteMaxHashes + 100,
			expectedGas: params.ExecuteBaseGas + params.ExecuteMaxHashes*params.ExecutePerHashGas,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := make([]byte, 256)
			arrayLen := big.NewInt(int64(tc.arrayLen))
			copy(input[96:128], common.LeftPadBytes(arrayLen.Bytes(), 32))

			gas := executePrecompile.RequiredGas(input)
			if gas != tc.expectedGas {
				t.Errorf("gas mismatch: expected %d, got %d", tc.expectedGas, gas)
			}
		})
	}
}

// TestNativeRollupForkActivation tests that the EXECUTE precompile is only available
// after the Native Rollup fork is activated
func TestNativeRollupForkActivation(t *testing.T) {
	// Test that EXECUTE is not available before Native Rollup
	rulesPreNativeRollup := params.Rules{
		IsOsaka:        true,
		IsNativeRollup: false,
	}
	precompiles := activePrecompiledContracts(rulesPreNativeRollup)
	executeAddr := common.BytesToAddress([]byte{0x1, 0x01})
	if _, exists := precompiles[executeAddr]; exists {
		t.Error("EXECUTE precompile should not be available before Native Rollup fork")
	}

	// Test that EXECUTE is available after Native Rollup
	rulesPostNativeRollup := params.Rules{
		IsOsaka:        true,
		IsNativeRollup: true,
	}
	precompiles = activePrecompiledContracts(rulesPostNativeRollup)
	if _, exists := precompiles[executeAddr]; !exists {
		t.Error("EXECUTE precompile should be available after Native Rollup fork")
	}
}

// TestExecutePrecompileName tests the Name() method
func TestExecutePrecompileName(t *testing.T) {
	executePrecompile := &execute{}
	if name := executePrecompile.Name(); name != "EXECUTE" {
		t.Errorf("unexpected name: expected EXECUTE, got %s", name)
	}
}