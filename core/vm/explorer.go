package vm

import (
	edatabase "github.com/jsign/verkle-explorer/database"
)

var txHash string
var codeChunkGas uint64
var executedBytes uint64
var executedInstructions int
var totalGasUsed uint64

func ResetWitnessTracer(hash string) {
	txHash = hash
	codeChunkGas = 0
	executedBytes = 0
	executedInstructions = 0
	totalGasUsed = 0
}

func SetTotalGasUsed(gas uint64) {
	totalGasUsed = gas
}

func recordCodeChunkCost(cost uint64) {
	codeChunkGas += cost
}

func recordExecutedInstruction(bytes uint64) {
	executedInstructions++
	executedBytes += bytes
}

func init() {
	ExplDB = ExplorerDatabase{data: make(map[string]edatabase.TxExec)}
}

var ExplDB ExplorerDatabase

func SaveRecord() {
	ExplDB.data[txHash] = edatabase.TxExec{
		Hash: txHash,

		TotalGas:     totalGasUsed,
		CodeChunkGas: codeChunkGas,

		ExecutedInstructions: executedInstructions,
		ExecutedBytes:        executedBytes,
	}
}

type ExplorerDatabase struct {
	data map[string]edatabase.TxExec
}

func (ed *ExplorerDatabase) GetTxExec(hash string) (edatabase.TxExec, error) {
	txInfo, ok := ed.data[hash]
	if !ok {
		return edatabase.TxExec{}, edatabase.ErrTxNotFound
	}
	return txInfo, nil
}
