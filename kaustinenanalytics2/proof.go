package kaustinenanalytics2

import (
	"fmt"

	"github.com/gballet/go-verkle"
)

func ProofGenStats() error {
	if _, err := Db.Exec(`INSERT INTO proof_gens values (?, ?, ?, ?)`,
		verkle.NumKeys,
		verkle.PreStateGetElementsForProofDuration.Milliseconds(),
		verkle.PreStateNumOpenings,
		verkle.ProofGenDuration.Milliseconds()); err != nil {
		return fmt.Errorf("failed to insert proof gen stats: %v", err)
	}
	return nil
}

func ProofVerifStats() error {
	if _, err := Db.Exec(`INSERT INTO proof_verifs values (?, ?, ?, ?)`,
		verkle.NumKeys,
		verkle.PreStateGetElementsForProofDuration.Milliseconds(),
		verkle.PreStateNumOpenings,
		verkle.ProofVerifDuration.Milliseconds()); err != nil {
		return fmt.Errorf("failed to insert proof verif stats: %v", err)
	}
	return nil
}
