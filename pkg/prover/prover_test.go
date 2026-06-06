package prover

import (
	"testing"
)

func TestProverDigitalExact(t *testing.T) {
	n := 4
	cells := n * n
	a := make([]int32, cells)
	b := make([]int32, cells)
	cObserved := make([]int32, cells)

	// Initialize simple deterministic inputs
	for i := 0; i < cells; i++ {
		a[i] = int32(i + 1)
		b[i] = int32(i - 2)
	}

	// Compute correct C
	for i := 0; i < n; i++ {
		for kv := 0; kv < n; kv++ {
			r := a[i*n+kv]
			for j := 0; j < n; j++ {
				cObserved[i*n+j] += r * b[kv*n+j]
			}
		}
	}

	proof, trace, err := GenerateProof(ProofParams{
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

	if proof.HardwareTier != "digital_exact" {
		t.Errorf("Expected tier digital_exact, got %s", proof.HardwareTier)
	}

	if !proof.Verified {
		t.Errorf("Expected proof to be verified")
	}

	if len(trace.Steps) == 0 {
		t.Errorf("Expected steps in execution trace")
	}

	// Make an invalid C
	cObserved[0] = 9999
	_, _, err = GenerateProof(ProofParams{
		TaskId:       "task-0",
		HardwareTier: "digital_exact",
		N:            n,
		AData:        a,
		BData:        b,
		CObserved:    cObserved,
	})
	if err == nil {
		t.Errorf("Expected error when C does not match ideal exactly, but got nil")
	}
}

func TestProverAnalogRange(t *testing.T) {
	n := 4
	cells := n * n
	a := make([]int32, cells)
	b := make([]int32, cells)
	cObserved := make([]int32, cells)

	for i := 0; i < cells; i++ {
		a[i] = int32(i + 1)
		b[i] = int32(i)
	}

	// Compute correct C
	for i := 0; i < n; i++ {
		for kv := 0; kv < n; kv++ {
			r := a[i*n+kv]
			for j := 0; j < n; j++ {
				cObserved[i*n+j] += r * b[kv*n+j]
			}
		}
	}

	// Add minor drift (within tolerance = 1.96 * 0.05 * 100 = 9.8)
	cObserved[0] += 5
	cObserved[1] -= 3

	proof, trace, err := GenerateProof(ProofParams{
		TaskId:       "task-1",
		HardwareTier: "analog_range",
		N:            n,
		AData:        a,
		BData:        b,
		CObserved:    cObserved,
		Sigma:        0.05,
		ZCritical:    1.96,
	})
	if err != nil {
		t.Fatalf("Failed to generate analog proof: %v", err)
	}

	if trace == nil {
		t.Fatalf("Expected execution trace to be generated, got nil")
	}

	if proof.HardwareTier != "analog_range" {
		t.Errorf("Expected tier analog_range, got %s", proof.HardwareTier)
	}

	// Add major drift (out of tolerance)
	cObserved[0] += 20
	_, _, err = GenerateProof(ProofParams{
		TaskId:       "task-1",
		HardwareTier: "analog_range",
		N:            n,
		AData:        a,
		BData:        b,
		CObserved:    cObserved,
		Sigma:        0.05,
		ZCritical:    1.96,
	})
	if err == nil {
		t.Errorf("Expected error when analog drift exceeds allowed range, but got nil")
	}
}
