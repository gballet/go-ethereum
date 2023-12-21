package aura

import (
	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

type GasLimitOverride struct {
	cache *lru.Cache[common.Hash, *uint256.Int]
}

func NewGasLimitOverride() *GasLimitOverride {
	// The number of recent block hashes for which the gas limit override is memoized.
	const GasLimitOverrideCacheCapacity = 10

	cache, err := lru.New[common.Hash, *uint256.Int](GasLimitOverrideCacheCapacity)
	if err != nil {
		panic("error creating prefetching cache for blocks")
	}
	return &GasLimitOverride{cache: cache}
}

func (pb *GasLimitOverride) Pop(hash common.Hash) *uint256.Int {
	if val, ok := pb.cache.Get(hash); ok && val != nil {
		pb.cache.Remove(hash)
		return val
	}
	return nil
}

func (pb *GasLimitOverride) Add(hash common.Hash, b *uint256.Int) {
	if b == nil {
		return
	}
	pb.cache.ContainsOrAdd(hash, b)
}

func (c *AuRa) HasGasLimitContract() bool {
	return len(c.cfg.BlockGasLimitContractTransitions) != 0
}

func (c *AuRa) GetBlockGasLimitFromContract(_ *params.ChainConfig) uint64 {
	// var blockLimitContract
	addr, ok := c.cfg.BlockGasLimitContractTransitions[0]
	if !ok {
		return 0
	}
	gasLimit := callBlockGasLimitAbi(addr, c.Syscall)
	return gasLimit.Uint64()
}

func (c *AuRa) verifyGasLimitOverride(config *params.ChainConfig, chain consensus.ChainHeaderReader, header *types.Header, statedb *state.StateDB) {
	// TODO(gballet): take care of that when we reach the merge
	//IsPoSHeader check is necessary as merge.go calls Initialize on AuRa indiscriminately
	gasLimitOverride := c.HasGasLimitContract() && !c.isPos
	if gasLimitOverride {
		_ /*blockGasLimit */ = c.GetBlockGasLimitFromContract(config)

		// if blockGasLimit > 0 {
		// 	if header.GasLimit != blockGasLimit {
		// 		panic(fmt.Sprintf("Block gas limit doesn't match BlockGasLimitContract with AuRa: %d != %d at block %d, merged=%v", header.GasLimit, blockGasLimit, header.Number, c.isPos))
		// 	}
		// }
	}
}
