package verifier

import (
	"testing"

	"github.com/westkevin12/RAMNET/VALKYRIE/pkg/prover"
)

func TestVerifier(t *testing.T) {
	n := 4
	cells := n * n
	a := make([]int32, cells)
	b := make([]int32, cells)
	cObserved := make([]int32, cells)

	for i := 0; i < cells; i++ {
		a[i] = int32(i + 1)
		b[i] = int32(i - 2)
	}

	for i := 0; i < n; i++ {
		for kv := 0; kv < n; kv++ {
			r := a[i*n+kv]
			for j := 0; j < n; j++ {
				cObserved[i*n+j] += r * b[kv*n+j]
			}
		}
	}

	proof, _, err := prover.GenerateProof(prover.ProofParams{
		TaskId:       "task-0",
		HardwareTier: "digital_exact",
		N:            n,
		AData:        a,
		BData:        b,
		CObserved:    cObserved,
	})
	if err != nil {
		t.Fatalf("Failed to generate proof: %v", err)
	}

	// Verify proof
	valid, err := VerifyProof(proof, a, b, cObserved)
	if err != nil {
		t.Fatalf("Failed to verify valid proof: %v", err)
	}
	if !valid {
		t.Errorf("Expected proof to be valid")
	}

	// Try verifying with mutated inputs
	mutatedA := make([]int32, len(a))
	copy(mutatedA, a)
	mutatedA[0] = 99
	valid, err = VerifyProof(proof, mutatedA, b, cObserved)
	if err == nil {
		t.Errorf("Expected error when verifying with mismatched inputs, but got nil")
	}
	if valid {
		t.Errorf("Expected proof validation to fail for mismatched inputs")
	}

	// Try verifying with mutated signature
	proof.Signature[0] ^= 0xFF
	valid, err = VerifyProof(proof, a, b, cObserved)
	if err == nil {
		t.Errorf("Expected error when signature is mutated, but got nil")
	}
	if valid {
		t.Errorf("Expected proof validation to fail for mutated signature")
	}
}
