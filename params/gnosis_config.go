package params

import (
	"embed"
	"encoding/json"
	"fmt"
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
	spec := &chain.Config{}
	err = decoder.Decode(&spec)
	if err != nil {
		panic(fmt.Sprintf("Could not parse chainspec for %s: %v", filename, err))
	}
	return spec
}

var (
	GnosisChainConfig = readChainSpec("chainspecs/gnosis.json")
	ChiadoChainConfig = readChainSpec("chainspecs/chiado.json")
)
