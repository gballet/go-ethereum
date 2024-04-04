package witnesstracing

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"database/sql"

	"github.com/ethereum/go-ethereum/common"
	edatabase "github.com/jsign/verkle-explorer/database"
	_ "github.com/mattn/go-sqlite3"
)

var txHash string
var txBlockNumber uint64
var txFrom string
var txTo string
var txValue *big.Int
var codeChunkGas uint64
var chargedCodeChunks int
var executedBytes uint64
var executedInstructions int
var totalGasUsed uint64
var witnessEvents []edatabase.WitnessEvent
var witnessKeyValues []edatabase.WitnessTreeKeyValue

func ResetWitnessTracer(hash string) {
	txHash = hash
	txBlockNumber = 0
	txFrom = ""
	txTo = ""
	txValue = nil
	codeChunkGas = 0
	chargedCodeChunks = 0
	executedBytes = 0
	executedInstructions = 0
	totalGasUsed = 0
	witnessEvents = nil
	witnessKeyValues = nil
}

func SetGeneralInfo(blockNumber uint64, from string, to string, value *big.Int, gas uint64) {
	txBlockNumber = blockNumber
	txFrom = from
	txTo = to
	txValue = value
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

	witnessEvents = append(witnessEvents, edatabase.WitnessEvent{
		Name:   eventName,
		Gas:    gas,
		Params: strParams.String(),
	})
}

func RecordWitnessTreeKeyValue(key []byte, current []byte, newValue []byte) {
	currValue := ""
	if len(current) > 0 {
		currValue = "0x" + hex.EncodeToString(current)
	}

	postValue := ""
	if !bytes.Equal(current, newValue) {
		postValue = "0x" + hex.EncodeToString(newValue)
	}
	witnessKeyValues = append(witnessKeyValues, edatabase.WitnessTreeKeyValue{Key: "0x" + hex.EncodeToString(key), CurrentValue: currValue, PostValue: postValue})
}

func RecordCodeChunkCost(cost uint64) {
	chargedCodeChunks++
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
			block_number INTEGER,
			addr_from TEXT,
			addr_to TEXT,
			value TEXT,
			total_gas INTEGER, 
			code_chunk_gas INTEGER, 
			charged_code_chunks INTEGER,
			executed_instructions INTEGER, 
			executed_bytes INTEGER,
			jsonWitnessEvents BLOB,
			jsonTreeKeyValues BLOB
		) STRICT`); err != nil {
		panic(err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS tx_exec_total_gas ON tx_exec(total_gas DESC)"); err != nil {
		panic(err)
	}
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS tx_exec_charged_code_chunks ON tx_exec(charged_code_chunks DESC)"); err != nil {
		panic(err)
	}
	ExplDB = ExplorerDatabase{db: db}
}

var ExplDB ExplorerDatabase

type ExplorerDatabase struct {
	db *sql.DB
}

func (ed *ExplorerDatabase) SaveRecord() {
	sort.Slice(witnessKeyValues, func(i, j int) bool {
		return witnessKeyValues[i].Key < witnessKeyValues[j].Key
	})

	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(witnessKeyValues); err != nil {
		panic(err)
	}
	jsonWitnessKeyValues := buf.Bytes()

	buf = bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(witnessEvents); err != nil {
		panic(err)
	}
	jsonWitnessEvents := buf.Bytes()

	if _, err := ed.db.Exec("INSERT OR IGNORE INTO tx_exec (hash, block_number, addr_from, addr_to, value, total_gas, code_chunk_gas, charged_code_chunks, executed_instructions, executed_bytes, jsonWitnessEvents, jsonTreeKeyValues) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		txHash, txBlockNumber, txFrom, txTo, txValue.String(), totalGasUsed, codeChunkGas, chargedCodeChunks, executedInstructions, executedBytes, jsonWitnessEvents, jsonWitnessKeyValues); err != nil {
		panic(err)
	}
}

func (ed *ExplorerDatabase) GetTxExec(hash string) (edatabase.TxExec, error) {
	row := ed.db.QueryRow("SELECT * FROM tx_exec WHERE hash = ?", hash)
	var edTxExec edatabase.TxExec
	var jsonTreeKeyValues []byte
	var jsonWitnessEvents []byte
	err := row.Scan(&edTxExec.Hash, &edTxExec.BlockNumber, &edTxExec.From, &edTxExec.To, &edTxExec.Value, &edTxExec.TotalGas, &edTxExec.CodeChunkGas, &edTxExec.ChargedCodeChunks, &edTxExec.ExecutedInstructions, &edTxExec.ExecutedBytes, &jsonWitnessEvents, &jsonTreeKeyValues)
	if err == sql.ErrNoRows {
		return edatabase.TxExec{}, edatabase.ErrTxNotFound
	}
	if err := gob.NewDecoder(bytes.NewReader(jsonWitnessEvents)).Decode(&edTxExec.WitnessEvents); err != nil {
		panic(err)
	}
	if err := gob.NewDecoder(bytes.NewReader(jsonTreeKeyValues)).Decode(&edTxExec.WitnessTreeKeyValues); err != nil {
		panic(err)
	}
	return edTxExec, nil
}

func (ed *ExplorerDatabase) GetHighestGasTxs(count int) ([]edatabase.TxInfo, error) {
	rows, err := ed.db.Query("SELECT * FROM tx_exec ORDER BY total_gas DESC LIMIT ?", count)
	if err != nil {
		return nil, fmt.Errorf("failed to get high gas txs: %w", err)
	}
	defer rows.Close()

	return getTxInfos(rows)
}

func (ed *ExplorerDatabase) GetInefficientCodeAccessTxs(count int) ([]edatabase.TxInfo, error) {
	rows, err := ed.db.Query("SELECT * FROM tx_exec WHERE charged_code_chunks > 0 ORDER BY cast(executed_bytes as real)/cast(charged_code_chunks*31 as real) ASC LIMIT ?", count)
	if err != nil {
		return nil, fmt.Errorf("failed to get inefficient code access txs: %w", err)
	}
	defer rows.Close()

	return getTxInfos(rows)
}

func getTxInfos(rows *sql.Rows) ([]edatabase.TxInfo, error) {
	var txs []edatabase.TxInfo
	for rows.Next() {
		var edTxExec edatabase.TxInfo
		var dummy string
		if err := rows.Scan(&edTxExec.Hash, &edTxExec.BlockNumber, &edTxExec.From, &edTxExec.To, &edTxExec.Value, &edTxExec.TotalGas, &edTxExec.CodeChunkGas, &edTxExec.ChargedCodeChunks, &edTxExec.ExecutedInstructions, &edTxExec.ExecutedBytes, &dummy, &dummy); err != nil {
			return nil, fmt.Errorf("failed to scan tx: %w", err)
		}
		txs = append(txs, edTxExec)
	}
	return txs, nil
}
