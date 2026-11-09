package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/westkevin12/RAMNET/VALKYRIE/pkg/prover"
)

func TestCheckVerifyOperandSizes(t *testing.T) {
	if err := checkVerifyOperandSizes(make([]int32, 16), make([]int32, 16), make([]int32, 16)); err != nil {
		t.Fatalf("small operands rejected: %v", err)
	}
	if err := checkVerifyOperandSizes(make([]int32, maxVerifyCells+1), nil, nil); err == nil {
		t.Fatalf("oversized a_data accepted, want rejection")
	}
	if err := checkVerifyOperandSizes(nil, nil, make([]int32, maxVerifyCells+1)); err == nil {
		t.Fatalf("oversized c_data accepted, want rejection")
	}
}

// TestHandleVerifyRejectsOversizedOperands confirms /verify answers 400 for an
// oversized operand instead of entering the commitment/arithmetic path.
func TestHandleVerifyRejectsOversizedOperands(t *testing.T) {
	body, _ := json.Marshal(VerifyRequest{
		Proof: &prover.Proof{},
		AData: make([]int32, maxVerifyCells+1),
	})
	rec := httptest.NewRecorder()
	handleVerify(rec, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestHandleVerifyAcceptsValidProof confirms the bound does not reject a
// legitimately-sized request.
func TestHandleVerifyAcceptsValidProof(t *testing.T) {
	n := 4
	cells := n * n
	a := make([]int32, cells)
	b := make([]int32, cells)
	for i := range a {
		a[i] = int32(i + 1)
		b[i] = int32(i - 2)
	}
	c := make([]int32, cells)
	for i := 0; i < n; i++ {
		for k := 0; k < n; k++ {
			r := a[i*n+k]
			for j := 0; j < n; j++ {
				c[i*n+j] += r * b[k*n+j]
			}
		}
	}
	proof, _, err := prover.GenerateProof(prover.ProofParams{
		TaskId: "t", HardwareTier: "digital_exact", N: n, AData: a, BData: b, CObserved: c,
	})
	if err != nil {
		t.Fatalf("generate proof: %v", err)
	}
	body, _ := json.Marshal(VerifyRequest{Proof: proof, AuthorizedTier: "digital_exact", AData: a, BData: b, CData: c})
	rec := httptest.NewRecorder()
	handleVerify(rec, httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want %d", rec.Code, http.StatusOK)
	}
	var resp VerifyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("valid proof rejected: %s", resp.Reason)
	}
}
