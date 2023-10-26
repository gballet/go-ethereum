package kaustinenanalytics2

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var Db *sql.DB

func init() {
	var err error
	Db, err = sql.Open("sqlite3", "kaustinen.db?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		panic(err)
	}

	if _, err := Db.Exec(`
	CREATE TABLE IF NOT EXISTS witness(
		block_number INTEGER NOT NULL,
		gas_used INTEGER NOT NULL,

		ssz_total_size INTEGER NOT NULL,
		ssz_statediff_size INTEGER NOT NULL,
		ssz_verkleproof_size INTEGER NOT NULL,

		statediff_stem_count INTEGER NOT NULL,
		statediff_currentvalue_nonnil_count INTEGER NOT NULL,
		statediff_newvalue_nonnil_count INTEGER NOT NULL,

		PRIMARY KEY(block_number)
	) STRICT
	`); err != nil {
		panic(err)
	}

	if _, err := Db.Exec(`
	CREATE TABLE IF NOT EXISTS tree_stats (
		block_number INTEGER NOT NULL,

		depth1_count INTEGER NOT NULL,
		depth2_count INTEGER NOT NULL,
		depth3_count INTEGER NOT NULL,
		depth4_count INTEGER NOT NULL,
		depth5_count INTEGER NOT NULL,

		leaf_node_count INTEGER NOT NULL,
		internal_node_count INTEGER NOT NULL,

		keyvalue_count INTEGER NOT NULL,

		PRIMARY KEY(block_number)
	) STRICT
	`); err != nil {
		panic(err)
	}

	if _, err := Db.Exec(`
	CREATE TABLE IF NOT EXISTS proof_gens (
		num_keys INTEGER NOT NULL,
		prestate_getelementsforproof_ms INTEGER NOT NULL,
		prestate_numopenings INTEGER NOT NULL,
		create_multiproof_ms INTEGER NOT NULL
	) STRICT
	`); err != nil {
		panic(err)
	}

	if _, err := Db.Exec(`
	CREATE TABLE IF NOT EXISTS proof_verifs (
		num_keys INTEGER NOT NULL,
		prestate_getelementsforproof_ms INTEGER NOT NULL,
		prestate_numopenings INTEGER NOT NULL,
		verify_multiproof_ms INTEGER NOT NULL
	) STRICT
	`); err != nil {
		panic(err)
	}
}
