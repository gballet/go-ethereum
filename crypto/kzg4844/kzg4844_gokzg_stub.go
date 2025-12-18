// Copyright 2023 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

//go:build !gokzg

package kzg4844

import "sync"

// gokzgIniter ensures that we initialize the KZG library once before using it.
var gokzgIniter sync.Once

// gokzgInit initializes the KZG library with the provided trusted setup.
func gokzgInit() {
	// Stub: go-eth-kzg not compiled in
}

// gokzgBlobToCommitment creates a small commitment out of a data blob.
func gokzgBlobToCommitment(blob *Blob) (Commitment, error) {
	panic("go-eth-kzg not compiled in, build with -tags gokzg")
}

// gokzgComputeProof computes the KZG proof at the given point for the polynomial
// represented by the blob.
func gokzgComputeProof(blob *Blob, point Point) (Proof, Claim, error) {
	panic("go-eth-kzg not compiled in, build with -tags gokzg")
}

// gokzgVerifyProof verifies the KZG proof that the polynomial represented by the blob
// evaluated at the given point is the claimed value.
func gokzgVerifyProof(commitment Commitment, point Point, claim Claim, proof Proof) error {
	panic("go-eth-kzg not compiled in, build with -tags gokzg")
}

// gokzgComputeBlobProof returns the KZG proof that is used to verify the blob against
// the commitment.
//
// This method does not verify that the commitment is correct with respect to blob.
func gokzgComputeBlobProof(blob *Blob, commitment Commitment) (Proof, error) {
	panic("go-eth-kzg not compiled in, build with -tags gokzg")
}

// gokzgVerifyBlobProof verifies that the blob data corresponds to the provided commitment.
func gokzgVerifyBlobProof(blob *Blob, commitment Commitment, proof Proof) error {
	panic("go-eth-kzg not compiled in, build with -tags gokzg")
}

// gokzgComputeCellProofs returns the KZG cell proofs that are used to verify the blob against
// the commitment.
//
// This method does not verify that the commitment is correct with respect to blob.
func gokzgComputeCellProofs(blob *Blob) ([]Proof, error) {
	panic("go-eth-kzg not compiled in, build with -tags gokzg")
}

// gokzgVerifyCellProofBatch verifies that the blob data corresponds to the provided commitment.
func gokzgVerifyCellProofBatch(blobs []Blob, commitments []Commitment, cellProofs []Proof) error {
	panic("go-eth-kzg not compiled in, build with -tags gokzg")
}
