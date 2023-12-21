package params

import (
	"embed"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

//go:embed chainspecs
var chainspecs embed.FS

func readChainSpec(filename string) *ChainConfig {
	f, err := chainspecs.Open(filename)
	if err != nil {
		panic(fmt.Sprintf("Could not open chainspec for %s: %v", filename, err))
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	spec := &ChainConfig{}
	err = decoder.Decode(&spec)
	if err != nil {
		panic(fmt.Sprintf("Could not parse chainspec for %s: %v", filename, err))
	}
	return spec
}

var (
	GnosisGenesisHash = common.HexToHash("0x4f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756")
	ChiadoGenesisHash = common.HexToHash("0xada44fd8d2ecab8b08f256af07ad3e777f17fb434f8f8e678b312f576212ba9a")

	GnosisChainConfig = readChainSpec("chainspecs/gnosis.json")
	ChiadoChainConfig = readChainSpec("chainspecs/chiado.json")
)
