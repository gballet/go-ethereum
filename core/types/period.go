package types

import (
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-verkle"
)

var (
	PeriodLength = uint64(15_778_800) // measured in seconds, about 6 months
	Period0      = verkle.StatePeriod(0)
	Period1      = verkle.StatePeriod(1)
	Period2      = verkle.StatePeriod(2)
)

func GetStatePeriod(config *params.ChainConfig, curTime uint64) verkle.StatePeriod {
	if config == nil || config.StateExpiryTime == nil {
		return Period0
	}

	forkTime := *config.StateExpiryTime
	if curTime < forkTime {
		return Period0
	}

	periodLen := PeriodLength
	if config.StateExpiryPeriod != nil {
		periodLen = *config.StateExpiryPeriod
	}

	return verkle.StatePeriod((curTime - forkTime) / periodLen)
}