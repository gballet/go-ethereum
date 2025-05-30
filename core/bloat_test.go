package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

func TestBloatNet(t *testing.T) {
	var (
		key, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		address     = crypto.PubkeyToAddress(key.PublicKey)
		chainConfig = &params.ChainConfig{
			ChainID:                 big.NewInt(1),
			HomesteadBlock:          big.NewInt(0),
			DAOForkBlock:            nil,
			DAOForkSupport:          false,
			EIP150Block:             big.NewInt(0),
			EIP155Block:             big.NewInt(0),
			EIP158Block:             big.NewInt(0),
			ByzantiumBlock:          big.NewInt(0),
			ConstantinopleBlock:     big.NewInt(0),
			PetersburgBlock:         big.NewInt(0),
			IstanbulBlock:           big.NewInt(0),
			MuirGlacierBlock:        big.NewInt(0),
			BerlinBlock:             big.NewInt(0),
			LondonBlock:             big.NewInt(0),
			ArrowGlacierBlock:       big.NewInt(0),
			GrayGlacierBlock:        big.NewInt(0),
			MergeNetsplitBlock:      big.NewInt(0),
			ShanghaiTime:            u64(0),
			CancunTime:              u64(0),
			PragueTime:              u64(0),
			OsakaTime:               nil,
			VerkleTime:              nil,
			BloatTime:               u64(0),
			TerminalTotalDifficulty: big.NewInt(131072),
			Ethash:                  new(params.EthashConfig),
			BlobScheduleConfig: &params.BlobScheduleConfig{
				Cancun: params.DefaultCancunBlobConfig,
				Prague: params.DefaultPragueBlobConfig,
			},
		}
		genesis = &Genesis{
			Config: chainConfig,
			Alloc:  types.GenesisAlloc{address: {Balance: big.NewInt(1000000000000000000)}},
		}
	)

	// Set the limit to 1GB since this is an in-ram db and it will OOM if there
	// is a bug.
	params.GrowthTarget = 1 * 1024 * 1024 * 1024

	// Generate chain.
	db, blocks, _ := GenerateChainWithGenesis(genesis, beacon.New(ethash.NewFaker()), 11, func(i int, g *BlockGen) {
		// Empty blocks
	})

	// Initialize BlockChain.
	chain, err := NewBlockChain(db, nil, genesis, nil, beacon.New(ethash.NewFaker()), vm.Config{}, nil)
	if err != nil {
		t.Fatalf("unable to initialize chain: %v", err)
	}
	if _, err := chain.InsertChain(blocks); err != nil {
		t.Fatalf("error inserting chain: %v", err)
	}

	dbit := db.NewIterator(nil, nil)
	bloat := 0
	for dbit.Next() {
		bloat += len(dbit.Value()) // Read the value to ensure it is not nil
	}
	if bloat < params.GrowthTarget {
		t.Fatalf("bloat is less than target: got %d, want at least %d", bloat, params.GrowthTarget)
	}
}
