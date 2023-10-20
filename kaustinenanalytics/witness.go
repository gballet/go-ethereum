package kaustinenanalytics

import (
	"fmt"

	eth2client "github.com/attestantio/go-eth2-client/spec/verkle"
	"github.com/ethereum/go-ethereum/core/types"
)

func CollectWitnessMetrics(block *types.Block) error {
	witness := block.ExecutionWitness()
	if witness == nil {
		return nil
	}

	sszWitness := eth2client.ExecutionWitness{
		StateDiff: make([]*eth2client.StemStateDiff, len(witness.StateDiff)),
		VerkleProof: &eth2client.VerkleProof{
			OtherStems:            make([][]byte, len(witness.VerkleProof.OtherStems)),
			DepthExtensionPresent: make([]byte, len(witness.VerkleProof.DepthExtensionPresent)),
			CommitmentsByPath:     make([][]byte, len(witness.VerkleProof.CommitmentsByPath)),
			IPAProof:              &eth2client.IPAProof{},
		},
	}

	// SSZ State Diff - God have mercy for your soul.
	for i := range witness.StateDiff {
		sszWitness.StateDiff[i] = &eth2client.StemStateDiff{}
		copy(sszWitness.StateDiff[i].Stem[:], witness.StateDiff[i].Stem[:])
		sszWitness.StateDiff[i].SuffixDiffs = make([]*eth2client.SuffixStateDiff, len(witness.StateDiff[i].SuffixDiffs))
		for j := range witness.StateDiff[i].SuffixDiffs {
			sszWitness.StateDiff[i].SuffixDiffs[j] = &eth2client.SuffixStateDiff{}
			sszWitness.StateDiff[i].SuffixDiffs[j].Suffix = witness.StateDiff[i].SuffixDiffs[j].Suffix
			if witness.StateDiff[i].SuffixDiffs[j].CurrentValue != nil {
				sszWitness.StateDiff[i].SuffixDiffs[j].CurrentValue = make([]byte, len(witness.StateDiff[i].SuffixDiffs[j].CurrentValue))
				copy(sszWitness.StateDiff[i].SuffixDiffs[j].CurrentValue, (*witness.StateDiff[i].SuffixDiffs[j].CurrentValue)[:])
			}
			if witness.StateDiff[i].SuffixDiffs[j].NewValue != nil {
				sszWitness.StateDiff[i].SuffixDiffs[j].NewValue = make([]byte, len(witness.StateDiff[i].SuffixDiffs[j].NewValue))
				copy(sszWitness.StateDiff[i].SuffixDiffs[j].NewValue, (*witness.StateDiff[i].SuffixDiffs[j].NewValue)[:])
			}
		}
	}

	// SSZ Verkle Proof
	for i := range witness.VerkleProof.OtherStems {
		sszWitness.VerkleProof.OtherStems[i] = make([]byte, len(witness.VerkleProof.OtherStems[i]))
		copy(sszWitness.VerkleProof.OtherStems[i], witness.VerkleProof.OtherStems[i][:])
	}
	copy(sszWitness.VerkleProof.DepthExtensionPresent[:], witness.VerkleProof.DepthExtensionPresent[:])
	for i := range witness.VerkleProof.CommitmentsByPath {
		sszWitness.VerkleProof.CommitmentsByPath[i] = make([]byte, len(witness.VerkleProof.CommitmentsByPath[i]))
		copy(sszWitness.VerkleProof.CommitmentsByPath[i], witness.VerkleProof.CommitmentsByPath[i][:])
	}
	sszWitness.VerkleProof.IPAProof.CL = witness.VerkleProof.IPAProof.CL
	sszWitness.VerkleProof.IPAProof.CR = witness.VerkleProof.IPAProof.CR
	sszWitness.VerkleProof.IPAProof.FinalEvaluation = witness.VerkleProof.IPAProof.FinalEvaluation

	sszTotalSize := sszWitness.SizeSSZ()
	sszStateDiffSize := 0
	for ii := 0; ii < len(sszWitness.StateDiff); ii++ {
		sszStateDiffSize += 4
		sszStateDiffSize += sszWitness.StateDiff[ii].SizeSSZ()
	}
	sszVerkleProofSize := sszWitness.VerkleProof.SizeSSZ()

	stemCount := 0
	currentValueNonNilCount := 0
	newValueNonNilCount := 0
	for i := range witness.StateDiff {
		stemCount++
		for j := range witness.StateDiff[i].SuffixDiffs {
			if witness.StateDiff[i].SuffixDiffs[j].CurrentValue != nil {
				currentValueNonNilCount++
			}
			if witness.StateDiff[i].SuffixDiffs[j].NewValue != nil {
				newValueNonNilCount++
			}
		}
	}

	if _, err := db.Exec(`INSERT OR IGNORE INTO witness values (?, ?, ?, ?, ?, ?, ?, ?)`,
		block.NumberU64(),
		block.GasUsed(),
		sszTotalSize,
		sszStateDiffSize,
		sszVerkleProofSize,
		stemCount,
		currentValueNonNilCount,
		newValueNonNilCount); err != nil {
		return fmt.Errorf("failed to insert witness: %v", err)
	}

	return nil
}
