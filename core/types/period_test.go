package types

import (
	"testing"

	"github.com/ethereum/go-ethereum/params"
)

func u64(v uint64) *uint64 { return &v }

func TestGetStatePeriod(t *testing.T) {
	tests := []struct {
		name           string
		config         *params.ChainConfig
		curTime        uint64
		expectedPeriod uint64
	}{
		{
			name:           "nil config returns period 0",
			config:         nil,
			curTime:        16_000_000,
			expectedPeriod: 0,
		},
		{
			name: "nil StateExpiryTime returns period 0",
			config: &params.ChainConfig{
				StateExpiryTime: nil,
			},
			curTime:        16_000_000,
			expectedPeriod: 0,
		},
		{
			name: "current time before fork time returns period 0",
			config: &params.ChainConfig{
				StateExpiryTime: u64(16_000_000),
			},
			curTime:        15_000_000,
			expectedPeriod: 0,
		},
		{
			name: "current time equal to fork time returns period 0",
			config: &params.ChainConfig{
				StateExpiryTime: u64(16_000_000),
			},
			curTime:        16_000_000,
			expectedPeriod: 0,
		},
		{
			name: "current time after fork time returns correct period",
			config: &params.ChainConfig{
				StateExpiryTime: u64(16_000_000),
			},
			curTime:        16_000_000 + PeriodLength,
			expectedPeriod: 1,
		},
		{
			name: "multiple periods after fork time",
			config: &params.ChainConfig{
				StateExpiryTime: u64(16_000_000),
			},
			curTime:        16_000_000 + (PeriodLength * 3),
			expectedPeriod: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetStatePeriod(tt.config, tt.curTime)
			if uint64(got) != tt.expectedPeriod {
				t.Errorf("GetStatePeriod() = %v, want %v", got, tt.expectedPeriod)
			}
		})
	}
}
