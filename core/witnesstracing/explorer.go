package witnesstracing

import (
	"encoding/hex"
	"fmt"
	"strings"

	"database/sql"

	"github.com/ethereum/go-ethereum/common"
	edatabase "github.com/jsign/verkle-explorer/database"
	_ "github.com/mattn/go-sqlite3"
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
	db, err := sql.Open("sqlite3", "kaustinen5.db?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=10000")
	if err != nil {
		panic(err)
	}
	if _, err := db.Exec(`
     	CREATE TABLE IF NOT EXISTS tx_exec (
			hash TEXT PRIMARY KEY, 
			total_gas INTEGER, 
			code_chunk_gas INTEGER, 
			executed_instructions INTEGER, 
			executed_bytes INTEGER
		) STRICT`); err != nil {
		panic(err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS tx_events (
			hash TEXT, 
			name TEXT, 
			gas INTEGER, 
			params TEXT,

			FOREIGN KEY(hash) REFERENCES tx_exec(hash)
		) STRICT`); err != nil {
		panic(err)
	}
	ExplDB = ExplorerDatabase{db: db}
}

var ExplDB ExplorerDatabase

type ExplorerDatabase struct {
	db *sql.DB
}

func (ed *ExplorerDatabase) SaveRecord() {
	if _, err := ed.db.Exec("INSERT OR IGNORE INTO tx_exec (hash, total_gas, code_chunk_gas, executed_instructions, executed_bytes) VALUES (?, ?, ?, ?, ?)", txHash, totalGasUsed, codeChunkGas, executedInstructions, executedBytes); err != nil {
		panic(err)
	}
	for _, event := range events {
		if _, err := ed.db.Exec("INSERT OR IGNORE INTO tx_events (hash, name, gas, params) VALUES (?, ?, ?, ?)", txHash, event.Name, event.Gas, event.Params); err != nil {
			panic(err)
		}
	}

}

func (ed *ExplorerDatabase) GetTxExec(hash string) (edatabase.TxExec, error) {
	row := ed.db.QueryRow("SELECT * FROM tx_exec WHERE hash = ?", hash)
	var edTxExec edatabase.TxExec
	err := row.Scan(&edTxExec.Hash, &edTxExec.TotalGas, &edTxExec.CodeChunkGas, &edTxExec.ExecutedInstructions, &edTxExec.ExecutedBytes)
	if err == sql.ErrNoRows {
		return edatabase.TxExec{}, edatabase.ErrTxNotFound
	}
	rows, err := ed.db.Query("SELECT * FROM tx_events WHERE hash = ?", hash)
	if err != nil {
		return edatabase.TxExec{}, fmt.Errorf("failed to get tx events: %w", err)
	}
	for rows.Next() {
		var dummy string
		var event edatabase.WitnessEvent
		if err := rows.Scan(&dummy, &event.Name, &event.Gas, &event.Params); err != nil {
			return edatabase.TxExec{}, fmt.Errorf("failed to scan tx event: %w", err)
		}
		edTxExec.Events = append(edTxExec.Events, event)
	}
	return edTxExec, nil
}

func (ed *ExplorerDatabase) GetTopTxs(count int) ([]edatabase.TxExec, error) {
	rows, err := ed.db.Query("SELECT * FROM tx_exec ORDER BY total_gas DESC LIMIT ?", count)
	if err != nil {
		return nil, fmt.Errorf("failed to get top txs: %w", err)
	}
	defer rows.Close()

	var txs []edatabase.TxExec
	for rows.Next() {
		var edTxExec edatabase.TxExec
		if err := rows.Scan(&edTxExec.Hash, &edTxExec.TotalGas, &edTxExec.CodeChunkGas, &edTxExec.ExecutedInstructions, &edTxExec.ExecutedBytes); err != nil {
			return nil, fmt.Errorf("failed to scan tx: %w", err)
		}
		txs = append(txs, edTxExec)
	}

	return txs, nil
}
