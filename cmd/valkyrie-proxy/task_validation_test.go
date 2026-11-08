package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPrepareTaskDataValidation(t *testing.T) {
	// Matching, explicitly-provided operands are accepted.
	t.Run("valid provided operands", func(t *testing.T) {
		req := &TaskRequest{N: 4, AData: make([]int32, 16), BData: make([]int32, 16)}
		cells, err := prepareTaskData(req)
		if err != nil || cells != 16 {
			t.Fatalf("got cells=%d err=%v, want 16, nil", cells, err)
		}
	})

	// Missing operands are generated to the right size.
	t.Run("defaults generate operands", func(t *testing.T) {
		req := &TaskRequest{N: 8}
		cells, err := prepareTaskData(req)
		if err != nil || cells != 64 || len(req.AData) != 64 || len(req.BData) != 64 {
			t.Fatalf("got cells=%d err=%v lenA=%d lenB=%d, want 64/nil/64/64",
				cells, err, len(req.AData), len(req.BData))
		}
	})

	// N<=0 falls back to the default dimension.
	t.Run("non-positive N defaults", func(t *testing.T) {
		req := &TaskRequest{N: 0}
		cells, err := prepareTaskData(req)
		if err != nil || cells != 64*64 {
			t.Fatalf("got cells=%d err=%v, want %d, nil", cells, err, 64*64)
		}
	})

	rejects := []struct {
		name string
		req  *TaskRequest
	}{
		{"a_data too short", &TaskRequest{N: 64, AData: []int32{1, 2, 3}}},
		{"b_data wrong length", &TaskRequest{N: 4, BData: make([]int32, 9)}},
		{"c_data wrong length", &TaskRequest{N: 4, CData: make([]int32, 10)}},
		{"N over cap", &TaskRequest{N: maxMatrixDim + 1}},
	}
	for _, tc := range rejects {
		t.Run("reject "+tc.name, func(t *testing.T) {
			if _, err := prepareTaskData(tc.req); err == nil {
				t.Fatalf("prepareTaskData(%+v) = nil error, want rejection", tc.req)
			}
		})
	}
}

// TestHandleTaskRejectsMalformedBeforeExecution confirms /task answers 400 for a
// length-mismatched operand instead of running the kernel over a short buffer.
func TestHandleTaskRejectsMalformedBeforeExecution(t *testing.T) {
	body, _ := json.Marshal(TaskRequest{
		HardwareTier: "digital_exact",
		N:            64,
		AData:        []int32{1, 2, 3}, // far shorter than 64*64
	})
	rec := httptest.NewRecorder()
	handleTask(rec, httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(body)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (request should be rejected before kernel execution)",
			rec.Code, http.StatusBadRequest)
	}
}

// TestHandleTaskRejectsOversizedN confirms an unbounded N is rejected cheaply
// rather than driving O(N^2) allocation and O(N^3) compute.
func TestHandleTaskRejectsOversizedN(t *testing.T) {
	body, _ := json.Marshal(TaskRequest{HardwareTier: "digital_exact", N: maxMatrixDim + 1})
	rec := httptest.NewRecorder()
	handleTask(rec, httptest.NewRequest(http.MethodPost, "/task", bytes.NewReader(body)))

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
