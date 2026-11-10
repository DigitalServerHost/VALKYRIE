package verifier

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/westkevin12/RAMNET/VALKYRIE/pkg/prover"
)

// forgeryFixture returns honest inputs A and B plus an output C that is NOT A x B.
func forgeryFixture() (n int, a, b, cWrong []int32) {
	n = 4
	cells := n * n
	a = make([]int32, cells)
	b = make([]int32, cells)
	cWrong = make([]int32, cells)
	for i := 0; i < cells; i++ {
		a[i] = int32(i + 1)
		b[i] = int32(i - 2)
	}
	for i := 0; i < n; i++ {
		for kv := 0; kv < n; kv++ {
			r := a[i*n+kv]
			for j := 0; j < n; j++ {
				cWrong[i*n+j] += r * b[kv*n+j]
			}
		}
	}
	// A dishonest worker skips the work and returns garbage.
	for i := range cWrong {
		cWrong[i] += 1000 + int32(i)
	}
	return n, a, b, cWrong
}

// TestVerifierRejectsHandBuiltProofForWrongOutput builds a proof using only the
// exported prover API, the same way GenerateProof does but without its
// correctness check. No secret is needed, so any worker can do this.
func TestVerifierRejectsHandBuiltProofForWrongOutput(t *testing.T) {
	_, a, b, cWrong := forgeryFixture()
	taskID := "task-forged"

	aCommit := prover.ComputeCommitment(a)
	bCommit := prover.ComputeCommitment(b)
	cCommit := prover.ComputeCommitment(cWrong)

	trace := &prover.ExecutionTrace{
		Header: prover.Header{
			TaskId:           taskID,
			LogicHash:        "0x00",
			InputCommitments: []string{aCommit, bCommit},
			HardwareTier:     "digital_exact",
		},
		Footer: prover.Footer{OutputCommitment: cCommit},
	}
	proofBytes, err := trace.SerializeBinary()
	if err != nil {
		t.Fatalf("serialize forged trace: %v", err)
	}
	traceHash := sha256.Sum256(proofBytes)

	sig := sha256.New()
	sig.Write(traceHash[:])
	sig.Write([]byte(taskID))
	sig.Write([]byte(aCommit))
	sig.Write([]byte(bCommit))
	sig.Write([]byte(cCommit))

	forged := &prover.Proof{
		TaskId:           taskID,
		HardwareTier:     "digital_exact",
		InputCommitment:  fmt.Sprintf("%s+%s", aCommit, bCommit),
		OutputCommitment: cCommit,
		TraceHash:        fmt.Sprintf("0x%x", traceHash),
		ProofBytes:       proofBytes,
		Signature:        sig.Sum(nil),
		Verified:         true,
	}

	valid, err := VerifyProof(forged, "digital_exact", a, b, cWrong)
	if valid || err == nil {
		t.Fatalf("VerifyProof accepted a forged proof for C != A x B (valid=%v, err=%v)", valid, err)
	}
}

// TestVerifierRejectsAnalogProofWithInflatedSigma uses the honest GenerateProof
// path. The requester-controlled Sigma is not part of the proof, so a huge
// value lets any output pass the analog range check.
func TestVerifierRejectsAnalogProofWithInflatedSigma(t *testing.T) {
	n, a, b, cWrong := forgeryFixture()

	proof, _, err := prover.GenerateProof(prover.ProofParams{
		TaskId:       "task-sigma",
		HardwareTier: "analog_range",
		N:            n,
		AData:        a,
		BData:        b,
		CObserved:    cWrong,
		Sigma:        1e9,
	})
	if err != nil {
		t.Fatalf("GenerateProof unexpectedly refused (setup assumption changed): %v", err)
	}

	valid, err := VerifyProof(proof, "analog_range", a, b, cWrong)
	if valid || err == nil {
		t.Fatalf("VerifyProof accepted an analog proof whose output is far from A x B (valid=%v, err=%v)", valid, err)
	}
}

// TestVerifierEnforcesAuthorizedTier checks that a proof cannot be verified under
// a tier other than the one the task authorized, even if the proof is otherwise
// valid. This blocks a worker from downgrading a digital_exact task to the looser
// analog_range check.
func TestVerifierEnforcesAuthorizedTier(t *testing.T) {
	n, a, b, _ := forgeryFixture()
	cExact := make([]int32, n*n)
	for i := 0; i < n; i++ {
		for k := 0; k < n; k++ {
			r := a[i*n+k]
			for j := 0; j < n; j++ {
				cExact[i*n+j] += r * b[k*n+j]
			}
		}
	}
	// An honest digital_exact proof for the correct output.
	proof, _, err := prover.GenerateProof(prover.ProofParams{
		TaskId: "task-tier", HardwareTier: "digital_exact", N: n, AData: a, BData: b, CObserved: cExact,
	})
	if err != nil {
		t.Fatalf("GenerateProof: %v", err)
	}

	// Same tier as authorized: accepted.
	if ok, err := VerifyProof(proof, "digital_exact", a, b, cExact); !ok || err != nil {
		t.Fatalf("matching tier: got (%v, %v), want (true, nil)", ok, err)
	}
	// Authorized tier differs from the proof's claim: rejected.
	if ok, err := VerifyProof(proof, "analog_range", a, b, cExact); ok || err == nil {
		t.Fatalf("tier mismatch accepted (ok=%v, err=%v), want rejection", ok, err)
	}
	// Missing authorized tier: rejected.
	if ok, err := VerifyProof(proof, "", a, b, cExact); ok || err == nil {
		t.Fatalf("empty authorized tier accepted (ok=%v, err=%v), want rejection", ok, err)
	}
}
