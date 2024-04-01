package witnesstracing

import (
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	edatabase "github.com/jsign/verkle-explorer/database"
)

var txHash string
var codeChunkGas uint64
var executedBytes uint64
var executedInstructions int
var totalGasUsed uint64
var events []edatabase.WitnessEvent

func ResetWitnessTracer(hash string) {
	txHash = hash
	codeChunkGas = 0
	executedBytes = 0
	executedInstructions = 0
	totalGasUsed = 0
	events = nil
}

func SetTotalGasUsed(gas uint64) {
	totalGasUsed = gas
}

func RecordWitnessEvent(gas uint64, eventName string, params ...interface{}) {
	var strParams strings.Builder
	strParams.WriteString("[")
	for i, p := range params {
		switch v := p.(type) {
		case []byte:
			strParams.WriteString("0x")
			strParams.WriteString(hex.EncodeToString(v))
		case common.Hash:
			strParams.WriteString(v.Hex())
		default:
			strParams.WriteString(fmt.Sprintf("%v", v))
		}
		if i < len(params)-1 {
			strParams.WriteString(", ")
		}
	}
	strParams.WriteString("]")

	events = append(events, edatabase.WitnessEvent{
		Name:   eventName,
		Gas:    gas,
		Params: strParams.String(),
	})
}

func RecordCodeChunkCost(cost uint64) {
	codeChunkGas += cost
}

func RecordExecutedInstruction(bytes uint64) {
	executedInstructions++
	executedBytes += bytes
}

func init() {
	ExplDB = ExplorerDatabase{dmap: make(map[string]*edatabase.TxExec)}
}

var ExplDB ExplorerDatabase

type ExplorerDatabase struct {
	lock sync.RWMutex

	data []*edatabase.TxExec
	dmap map[string]*edatabase.TxExec
}

func (ed *ExplorerDatabase) SaveRecord() {
	ed.lock.Lock()
	defer ed.lock.Unlock()

	record := edatabase.TxExec{
		Hash: txHash,

		TotalGas:     totalGasUsed,
		CodeChunkGas: codeChunkGas,

		ExecutedInstructions: executedInstructions,
		ExecutedBytes:        executedBytes,

		Events: events,
	}
	i := sort.Search(len(ed.data), func(i int) bool {
		return len(ed.data[i].Events) <= len(record.Events)
	})
	ed.data = slices.Insert(ed.data, i, &record)

	ed.dmap[txHash] = &record
}

func (ed *ExplorerDatabase) GetTxExec(hash string) (edatabase.TxExec, error) {
	ed.lock.RLock()
	defer ed.lock.RUnlock()

	txInfo, ok := ed.dmap[hash]
	if !ok {
		return edatabase.TxExec{}, edatabase.ErrTxNotFound
	}
	return *txInfo, nil
}

func (ed *ExplorerDatabase) GetTopTxs(count int) ([]*edatabase.TxExec, error) {
	ed.lock.RLock()
	defer ed.lock.RUnlock()

	var txs []*edatabase.TxExec
	for i := range ed.data {
		if i >= count {
			break
		}
		txs = append(txs, ed.data[i])
	}
	return txs, nil
}
