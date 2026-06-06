/**
 * @file verifier.go
 * @brief Out-of-band verification engine validating succinct proofs for the VALKYRIE system.
 * 
 * License: GNU GPLv3
 */

package verifier

import (
	"crypto/sha256"
	"fmt"

	"github.com/westkevin12/RAMNET/VALKYRIE/pkg/prover"
)

// VerifyProof re-evaluates the commitments, signature, and cryptographic fields to assert proof validity
func VerifyProof(proof *prover.Proof, a, b, c []int32) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("proof object cannot be nil")
	}

	// 1. Re-compute input and output commitments from the raw arrays
	aCommit := prover.ComputeCommitment(a)
	bCommit := prover.ComputeCommitment(b)
	cCommit := prover.ComputeCommitment(c)

	expectedInputCommitment := fmt.Sprintf("%s+%s", aCommit, bCommit)
	if proof.InputCommitment != expectedInputCommitment {
		return false, fmt.Errorf("input commitments mismatch: proof has %s, raw data has %s",
			proof.InputCommitment, expectedInputCommitment)
	}

	if proof.OutputCommitment != cCommit {
		return false, fmt.Errorf("output commitment mismatch: proof has %s, raw data has %s",
			proof.OutputCommitment, cCommit)
	}

	// 2. Validate Trace Hash by re-hashing ProofBytes
	traceHashBytes := sha256.Sum256(proof.ProofBytes)
	expectedTraceHash := fmt.Sprintf("0x%x", traceHashBytes)
	if proof.TraceHash != expectedTraceHash {
		return false, fmt.Errorf("trace hash verification failed: proof has %s, computed %s",
			proof.TraceHash, expectedTraceHash)
	}

	// 3. Verify Mock ZK Cryptographic Proof signature
	sigHasher := sha256.New()
	sigHasher.Write(traceHashBytes[:])
	sigHasher.Write([]byte(proof.TaskId))
	sigHasher.Write([]byte(aCommit))
	sigHasher.Write([]byte(bCommit))
	sigHasher.Write([]byte(cCommit))
	expectedSignature := sigHasher.Sum(nil)

	if len(proof.Signature) != len(expectedSignature) {
		return false, fmt.Errorf("signature verification failed: invalid signature size")
	}

	for i := 0; i < len(expectedSignature); i++ {
		if proof.Signature[i] != expectedSignature[i] {
			return false, fmt.Errorf("signature verification failed: cryptographic signature mismatch")
		}
	}

	return true, nil
}
