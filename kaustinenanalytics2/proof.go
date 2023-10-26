package kaustinenanalytics2

import (
	"fmt"
	"time"

	"github.com/gballet/go-verkle"
)

func ProofGenStats(e2eTime time.Duration) error {
	if _, err := Db.Exec(`INSERT INTO proof_gens values (?, ?, ?, ?, ?)`,
		verkle.NumKeys,
		verkle.PreStateNumOpenings,
		verkle.PreStateGetElementsForProofDuration.Milliseconds(),
		verkle.ProofGenDuration.Milliseconds(),
		e2eTime.Milliseconds()); err != nil {
		return fmt.Errorf("failed to insert proof gen stats: %v", err)
	}
	return nil
}

func ProofVerifStats(e2eTime time.Duration) error {
	if _, err := Db.Exec(`INSERT INTO proof_verifs values (?, ?, ?, ?, ?)`,
		verkle.NumKeys,
		verkle.PreStateNumOpenings,
		verkle.PreStateGetElementsForProofDuration.Milliseconds(),
		verkle.ProofVerifDuration.Milliseconds(),
		e2eTime.Milliseconds()); err != nil {
		return fmt.Errorf("failed to insert proof verif stats: %v", err)
	}
	return nil
}
