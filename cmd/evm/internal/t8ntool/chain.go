// Copyright 2026 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package t8ntool

import (
	"fmt"
	stdmath "math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/types/bal"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// t8nChain exposes a t8n environment as a core.ChainContext.
type t8nChain struct {
	config *params.ChainConfig
	engine consensus.Engine
	header *types.Header
	hashes map[math.HexOrDecimal64]common.Hash

	hashError error
}

func (c *t8nChain) Config() *params.ChainConfig  { return c.config }
func (c *t8nChain) Engine() consensus.Engine     { return c.engine }
func (c *t8nChain) CurrentHeader() *types.Header { return c.header }

func (c *t8nChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	return &types.Header{Number: new(big.Int).SetUint64(number)}
}

func (c *t8nChain) GetHeaderByNumber(number uint64) *types.Header  { return nil }
func (c *t8nChain) GetHeaderByHash(hash common.Hash) *types.Header { return nil }

func (c *t8nChain) BlockHashFn(ref *types.Header) func(n uint64) common.Hash {
	return func(n uint64) common.Hash {
		if c.hashes == nil {
			c.hashError = fmt.Errorf("getHash(%d) invoked, no blockhashes provided", n)
			return common.Hash{}
		}
		h, ok := c.hashes[math.HexOrDecimal64(n)]
		if !ok {
			c.hashError = fmt.Errorf("getHash(%d) invoked, blockhash for that block not provided", n)
		}
		return h
	}
}

// t8nEngine applies the block rewards and the withdrawals for t8n.
type t8nEngine struct {
	consensus.Engine

	statedb     *state.StateDB
	rules       params.Rules
	reward      int64
	coinbase    common.Address
	ommers      []ommer
	isEIP4762   bool
	isAmsterdam bool
}

func newT8nEngine(statedb *state.StateDB, rules params.Rules, reward int64, env *stEnv, isEIP4762, isAmsterdam bool) *t8nEngine {
	return &t8nEngine{
		Engine:      ethash.NewFaker(),
		statedb:     statedb,
		rules:       rules,
		reward:      reward,
		coinbase:    env.Coinbase,
		ommers:      env.Ommers,
		isEIP4762:   isEIP4762,
		isAmsterdam: isAmsterdam,
	}
}

func (e *t8nEngine) Finalize(chain consensus.ChainHeaderReader, header *types.Header, statedb vm.StateDB, body *types.Body, blockAccessIndex uint32, blockAccessList *bal.ConstructionBlockAccessList) {
	e.statedb.IntermediateRoot(e.rules)

	// Add mining reward? (-1 means rewards are disabled)
	if e.reward >= 0 {
		var (
			blockReward = big.NewInt(e.reward)
			minerReward = new(big.Int).Set(blockReward)
			perOmmer    = new(big.Int).Rsh(blockReward, 5)
		)
		for _, ommer := range e.ommers {
			// Add 1/32th for each ommer included
			minerReward.Add(minerReward, perOmmer)
			// Add (8-delta)/8
			reward := big.NewInt(8)
			reward.Sub(reward, new(big.Int).SetUint64(ommer.Delta))
			reward.Mul(reward, blockReward)
			reward.Rsh(reward, 3)
			e.statedb.AddBalance(ommer.Address, uint256.MustFromBig(reward), tracing.BalanceIncreaseRewardMineUncle)
		}
		e.statedb.AddBalance(e.coinbase, uint256.MustFromBig(minerReward), tracing.BalanceIncreaseRewardMineBlock)
	}
	// Apply withdrawals
	for _, w := range body.Withdrawals {
		amount := new(big.Int).Mul(new(big.Int).SetUint64(w.Amount), big.NewInt(params.GWei))
		prev := e.statedb.AddBalance(w.Address, uint256.MustFromBig(amount), tracing.BalanceIncreaseWithdrawal)

		if e.isEIP4762 {
			e.statedb.AccessEvents().AddAccount(w.Address, true, stdmath.MaxUint64)
		}
		if e.isAmsterdam {
			if w.Amount == 0 {
				blockAccessList.AccountRead(w.Address)
			} else {
				blockAccessList.BalanceChange(blockAccessIndex, w.Address, new(uint256.Int).Add(&prev, uint256.MustFromBig(amount)))
			}
		}
	}
}
