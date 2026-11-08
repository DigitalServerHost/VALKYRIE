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

	valid, err := VerifyProof(forged, a, b, cWrong)
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

	valid, err := VerifyProof(proof, a, b, cWrong)
	if valid || err == nil {
		t.Fatalf("VerifyProof accepted an analog proof whose output is far from A x B (valid=%v, err=%v)", valid, err)
	}
}
