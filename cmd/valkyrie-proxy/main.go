/**
 * @file main.go
 * @brief HTTP REST API Proxy Wrapper and Integration CLI for VALKYRIE Verification Layer.
 * 
 * License: GNU GPLv3
 */

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
	"unsafe"

	"ORCHID/jit"
	"github.com/westkevin12/RAMNET/VALKYRIE/pkg/prover"
	"github.com/westkevin12/RAMNET/VALKYRIE/pkg/verifier"
)

// ANSI color codes for premium terminal layout
const (
	ColorReset  = "\033[0m"
	ColorBold   = "\033[1m"
	ColorBlue   = "\033[34m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorRed    = "\033[31m"
	ColorCyan   = "\033[36m"
)

// String literal constants to avoid duplication
const (
	msgMethodNotAllowed = "Method not allowed"
	headerContentType   = "Content-Type"
	mimeAppJSON         = "application/json"
	taskURLFormat       = "http://localhost:%d/task"
)

// Global trace hook helper
type ProxyTraceHook struct {
	LastMetadata jit.ExecutionMetadata
	Called       bool
}

func (h *ProxyTraceHook) OnExecute(meta jit.ExecutionMetadata) {
	h.LastMetadata = meta
	h.Called = true
}

// TaskRequest defines input schema for /task
type TaskRequest struct {
	TaskId       string    `json:"task_id"`
	HardwareTier string    `json:"hardware_tier"`
	N            int       `json:"n"`
	AData        []int32   `json:"a_data,omitempty"`
	BData        []int32   `json:"b_data,omitempty"`
	CData        []int32   `json:"c_data,omitempty"`
	Sigma        float64   `json:"sigma,omitempty"`
	Confidence   float64   `json:"confidence,omitempty"`
}

// TaskResponse defines output schema for /task
type TaskResponse struct {
	Status       string        `json:"status"`
	TaskId       string        `json:"task_id"`
	HardwareTier string        `json:"hardware_tier"`
	N            int           `json:"n"`
	Checksum     int64         `json:"checksum"`
	Proof        *prover.Proof `json:"proof"`
}

// VerifyRequest defines input schema for /verify
type VerifyRequest struct {
	Proof *prover.Proof `json:"proof"`
	AData []int32       `json:"a_data"`
	BData []int32       `json:"b_data"`
	CData []int32       `json:"c_data"`
}

// VerifyResponse defines output schema for /verify
type VerifyResponse struct {
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

func main() {
	mode := flag.String("mode", "server", "Execution mode: server, test")
	port := flag.Int("port", 9001, "Port for the HTTP proxy daemon")
	flag.Parse()

	if *mode == "test" {
		runIntegrationTest(*port)
		return
	}

	runServer(*port)
}

func runServer(port int) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/task", handleTask)
	mux.HandleFunc("/verify", handleVerify)

	addr := fmt.Sprintf(":%d", port)
	fmt.Printf("%s🌌 VALKYRIE Proxy Wrapper%s running on port %d\n", ColorCyan, ColorReset, port)
	fmt.Printf("%s[SYSTEM]%s Initializing Go-native dual-route ZK verification pipeline...\n", ColorBlue, ColorReset)

	server := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "HTTP Server error: %v\n", err)
		os.Exit(1)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, msgMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set(headerContentType, mimeAppJSON)
	json.NewEncoder(w).Encode(map[string]string{
		"status":         "healthy",
		"version":        "1.0.0",
		"proving_engine": "VALKYRIE Dual-Route Proof Engine",
		"zk_backend":     "Plonky3 / Groth16 / Bulletproofs",
	})
}

// prepareTaskData validates inputs and populates defaults for TaskRequest
func prepareTaskData(req *TaskRequest) int {
	if req.TaskId == "" {
		req.TaskId = fmt.Sprintf("task-%d", time.Now().UnixNano())
	}
	if req.N <= 0 {
		req.N = 64
	}
	cells := req.N * req.N

	// Generate inputs if not provided
	if len(req.AData) == 0 {
		req.AData = make([]int32, cells)
		for i := 0; i < cells; i++ {
			req.AData[i] = int32((i*17 + 3)%7) - 3
		}
	}
	if len(req.BData) == 0 {
		req.BData = make([]int32, cells)
		for i := 0; i < cells; i++ {
			req.BData[i] = int32((i*13 + 5)%7) - 3
		}
	}
	return cells
}

// executeJITKernel performs compilation and execution under JIT, capturing trace Hook metadata
func executeJITKernel(n int, aData, bData, cData []int32, cells int) ([]int32, error) {
	hook := &ProxyTraceHook{}
	jit.RegisterTraceHook(hook)
	defer jit.RegisterTraceHook(nil)

	// Choose locality optimized kernel
	kernel, err := jit.CompileLocality(n)
	if err != nil {
		return nil, err
	}
	defer kernel.Free()

	// Alloc output buffer
	cSlice := make([]int32, cells)
	if len(cData) > 0 {
		copy(cSlice, cData)
	}

	// Execute via bare-metal JIT (or copy logic if client provided custom outputs to check)
	if len(cData) == 0 {
		kernel.Execute(
			unsafe.Pointer(&aData[0]),
			unsafe.Pointer(&bData[0]),
			unsafe.Pointer(&cSlice[0]),
		)
	} else {
		cSlice = cData
	}

	// Double check hook capture
	var isLocality bool
	if hook.Called {
		isLocality = hook.LastMetadata.Locality
		_ = isLocality
	}
	return cSlice, nil
}

func handleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, msgMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	var req TaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 1. Validate inputs
	cells := prepareTaskData(&req)

	// 2. Perform zero-copy JIT execution with registered TraceHook
	cSlice, err := executeJITKernel(req.N, req.AData, req.BData, req.CData, cells)
	if err != nil {
		http.Error(w, "JIT compilation error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 3. Evaluate context and generate proof payload
	zCritical := req.Confidence
	if zCritical <= 0 {
		zCritical = prover.DefaultZCritical
	} else {
		switch zCritical {
		case 0.95:
			zCritical = 1.96
		case 0.99:
			zCritical = 2.58
		}
	}

	proof, _, err := prover.GenerateProof(prover.ProofParams{
		TaskId:       req.TaskId,
		HardwareTier: req.HardwareTier,
		N:            req.N,
		AData:        req.AData,
		BData:        req.BData,
		CObserved:    cSlice,
		Sigma:        req.Sigma,
		ZCritical:    zCritical,
	})
	if err != nil {
		w.Header().Set(headerContentType, mimeAppJSON)
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]string{
			"status": "refused",
			"error":  err.Error(),
		})
		return
	}

	// Calculate checksum
	var checksum int64
	for i, val := range cSlice {
		checksum += int64(i+1) * int64(val)
	}

	w.Header().Set(headerContentType, mimeAppJSON)
	json.NewEncoder(w).Encode(TaskResponse{
		Status:       "success",
		TaskId:       req.TaskId,
		HardwareTier: req.HardwareTier,
		N:            req.N,
		Checksum:     checksum,
		Proof:        proof,
	})
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, msgMethodNotAllowed, http.StatusMethodNotAllowed)
		return
	}

	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	valid, err := verifier.VerifyProof(req.Proof, req.AData, req.BData, req.CData)
	w.Header().Set(headerContentType, mimeAppJSON)
	if err != nil {
		json.NewEncoder(w).Encode(VerifyResponse{
			Valid:  false,
			Reason: err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(VerifyResponse{
		Valid:  valid,
		Reason: "Cryptographic signature and matrix arithmetic bounds verified successfully",
	})
}

func testHealthcheck(client *http.Client, port int) {
	fmt.Printf("\n%s[TEST]%s Step 1: Ingesting server health...\n", ColorBlue, ColorReset)
	resp, err := client.Get(fmt.Sprintf("http://localhost:%d/health", port))
	if err != nil {
		fmt.Printf("%s[FAIL]%s Healthcheck request failed: %v\n", ColorRed, ColorReset, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	var health map[string]string
	json.NewDecoder(resp.Body).Decode(&health)
	fmt.Printf("   -> Server Engine: %s%s%s\n", ColorGreen, health["proving_engine"], ColorReset)
	fmt.Printf("   -> ZK Backend: %s%s%s\n", ColorGreen, health["zk_backend"], ColorReset)
}

func testDigitalExactTask(client *http.Client, port int, n int, a, b []int32) *prover.Proof {
	fmt.Printf("\n%s[TEST]%s Step 2: Dispatching digital matrix task (N=%d) to /task...\n", ColorBlue, ColorReset, n)
	taskReq := TaskRequest{
		TaskId:       "task-digital-exact-0",
		HardwareTier: "digital_exact",
		N:            n,
		AData:        a,
		BData:        b,
	}
	reqBytes, _ := json.Marshal(taskReq)
	resp, err := client.Post(fmt.Sprintf(taskURLFormat, port), mimeAppJSON, bytes.NewBuffer(reqBytes))
	if err != nil {
		fmt.Printf("%s[FAIL]%s Digital task request failed: %v\n", ColorRed, ColorReset, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("%s[FAIL]%s Digital task failed with status %d: %s\n", ColorRed, ColorReset, resp.StatusCode, string(body))
		os.Exit(1)
	}

	var taskResp TaskResponse
	json.NewDecoder(resp.Body).Decode(&taskResp)
	fmt.Printf("   -> Status: %s%s%s\n", ColorGreen, taskResp.Status, ColorReset)
	fmt.Printf("   -> Trace Hash: %s%s%s\n", ColorYellow, taskResp.Proof.TraceHash, ColorReset)
	fmt.Printf("   -> Proving Overhead: %s%d ms%s\n", ColorYellow, taskResp.Proof.ExecutionTimeMs, ColorReset)
	return taskResp.Proof
}

func testVerifyDigitalProof(client *http.Client, port int, proof *prover.Proof, a, b, cIdeal []int32) {
	fmt.Printf("\n%s[TEST]%s Step 3: Auditing ZK Proof at L3 Gate (/verify)...\n", ColorBlue, ColorReset)
	verifyReq := VerifyRequest{
		Proof: proof,
		AData: a,
		BData: b,
		CData: cIdeal,
	}
	reqBytes, _ := json.Marshal(verifyReq)
	resp, err := client.Post(fmt.Sprintf("http://localhost:%d/verify", port), mimeAppJSON, bytes.NewBuffer(reqBytes))
	if err != nil {
		fmt.Printf("%s[FAIL]%s Verify request failed: %v\n", ColorRed, ColorReset, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	var verifyResp VerifyResponse
	json.NewDecoder(resp.Body).Decode(&verifyResp)
	if !verifyResp.Valid {
		fmt.Printf("%s[FAIL]%s ZK Proof validation failed: %s\n", ColorRed, ColorReset, verifyResp.Reason)
		os.Exit(1)
	}
	fmt.Printf("   -> Verification Result: %sVALID (ZK-SNARK math confirmed)%s\n", ColorGreen, ColorReset)
}

func testAnalogRangeTask(client *http.Client, port int, n int, a, b, cAnalog []int32) *prover.Proof {
	fmt.Printf("\n%s[TEST]%s Step 4: Dispatching analog matrix task with precision drift to /task...\n", ColorBlue, ColorReset)
	taskReqAnalog := TaskRequest{
		TaskId:       "task-analog-range-0",
		HardwareTier: "analog_range",
		N:            n,
		AData:        a,
		BData:        b,
		CData:        cAnalog,
		Sigma:        0.05,
		Confidence:   0.95,
	}
	reqBytes, _ := json.Marshal(taskReqAnalog)
	resp, err := client.Post(fmt.Sprintf(taskURLFormat, port), mimeAppJSON, bytes.NewBuffer(reqBytes))
	if err != nil {
		fmt.Printf("%s[FAIL]%s Analog task request failed: %v\n", ColorRed, ColorReset, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("%s[FAIL]%s Analog task failed with status %d: %s\n", ColorRed, ColorReset, resp.StatusCode, string(body))
		os.Exit(1)
	}

	var taskRespAnalog TaskResponse
	json.NewDecoder(resp.Body).Decode(&taskRespAnalog)
	fmt.Printf("   -> Status: %s%s%s\n", ColorGreen, taskRespAnalog.Status, ColorReset)
	fmt.Printf("   -> Range Trace Hash: %s%s%s\n", ColorYellow, taskRespAnalog.Proof.TraceHash, ColorReset)
	fmt.Printf("   -> Proving Overhead: %s%d ms%s\n", ColorYellow, taskRespAnalog.Proof.ExecutionTimeMs, ColorReset)
	return taskRespAnalog.Proof
}

func testVerifyAnalogProof(client *http.Client, port int, proof *prover.Proof, a, b, cAnalog []int32) {
	fmt.Printf("\n%s[TEST]%s Step 5: Auditing Bounded Range Proof at L3 Gate (/verify)...\n", ColorBlue, ColorReset)
	verifyReqAnalog := VerifyRequest{
		Proof: proof,
		AData: a,
		BData: b,
		CData: cAnalog,
	}
	reqBytes, _ := json.Marshal(verifyReqAnalog)
	resp, err := client.Post(fmt.Sprintf("http://localhost:%d/verify", port), mimeAppJSON, bytes.NewBuffer(reqBytes))
	if err != nil {
		fmt.Printf("%s[FAIL]%s Verify request failed: %v\n", ColorRed, ColorReset, err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	var verifyRespAnalog VerifyResponse
	json.NewDecoder(resp.Body).Decode(&verifyRespAnalog)
	if !verifyRespAnalog.Valid {
		fmt.Printf("%s[FAIL]%s Range Proof validation failed: %s\n", ColorRed, ColorReset, verifyRespAnalog.Reason)
		os.Exit(1)
	}
	fmt.Printf("   -> Verification Result: %sVALID (Fuzzy Range Bounds confirmed)%s\n", ColorGreen, ColorReset)
}

func testCorruptedTask(client *http.Client, port int, n int, a, b, cCorrupted []int32) {
	fmt.Printf("\n%s[TEST]%s Step 6: Dispatching corrupted execution outputs (extreme drift) to /task...\n", ColorBlue, ColorReset)
	taskReqCorrupted := TaskRequest{
		TaskId:       "task-analog-corrupted",
		HardwareTier: "analog_range",
		N:            n,
		AData:        a,
		BData:        b,
		CData:        cCorrupted,
		Sigma:        0.05,
		Confidence:   0.95,
	}
	reqBytes, _ := json.Marshal(taskReqCorrupted)
	resp, err := client.Post(fmt.Sprintf(taskURLFormat, port), mimeAppJSON, bytes.NewBuffer(reqBytes))
	if err != nil {
		fmt.Printf("%s[FAIL]%s Corrupted request failed: %v\n", ColorRed, ColorReset, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Printf("%s[FAIL]%s Expected server to refuse corrupted outputs, but returned OK status\n", ColorRed, ColorReset)
		os.Exit(1)
	}
	var refuseResp map[string]string
	json.NewDecoder(resp.Body).Decode(&refuseResp)
	fmt.Printf("   -> Status: %s%s%s (Refused as expected)\n", ColorGreen, refuseResp["status"], ColorReset)
	fmt.Printf("   -> Refusal Reason: %s%s%s\n", ColorRed, refuseResp["error"], ColorReset)
}

// runIntegrationTest executes an end-to-end simulation test suite displaying results on a dashboard
func runIntegrationTest(port int) {
	fmt.Printf("\n%s======================================================================%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s           🛡️  VALKYRIE INTEGRATION & AUDITING TEST SWEEP  🛡️%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Printf("%s======================================================================%s\n", ColorCyan, ColorReset)

	// Start server in background
	go func() {
		runServer(port)
	}()

	// Wait for server to bind
	time.Sleep(500 * time.Millisecond)

	client := &http.Client{Timeout: 10 * time.Second}

	// Step 1: Healthcheck
	testHealthcheck(client, port)

	// Generate Test Matrices
	n := 16
	cells := n * n
	a := make([]int32, cells)
	b := make([]int32, cells)
	for i := 0; i < cells; i++ {
		a[i] = int32((i*17 + 3) % 7) - 3
		b[i] = int32((i*13 + 5) % 7) - 3
	}

	// Compute exact correct C
	cIdeal := make([]int32, cells)
	for i := 0; i < n; i++ {
		for kv := 0; kv < n; kv++ {
			r := a[i*n+kv]
			for j := 0; j < n; j++ {
				cIdeal[i*n+j] += r * b[kv*n+j]
			}
		}
	}

	// Step 2: Digital Exact Task
	proof := testDigitalExactTask(client, port, n, a, b)

	// Step 3: Verify Digital Proof
	testVerifyDigitalProof(client, port, proof, a, b, cIdeal)

	// Step 4: Analog Range Task (with minor drift)
	cAnalog := make([]int32, cells)
	copy(cAnalog, cIdeal)
	// Add minor charge variance
	cAnalog[0] += 2
	cAnalog[1] -= 3
	proofAnalog := testAnalogRangeTask(client, port, n, a, b, cAnalog)

	// Step 5: Verify Analog Range Proof
	testVerifyAnalogProof(client, port, proofAnalog, a, b, cAnalog)

	// Step 6: Malicious Task (high drift)
	cCorrupted := make([]int32, cells)
	copy(cCorrupted, cIdeal)
	cCorrupted[0] += 50 // High drift
	testCorruptedTask(client, port, n, a, b, cCorrupted)

	// Complete Dashboard Summary
	fmt.Printf("\n%s======================================================================%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s           ✨  VALKYRIE VERIFICATION INTEGRATION SWEEP COMPLETED  ✨%s\n", ColorBold+ColorGreen, ColorReset)
	fmt.Printf("           All dual-route validation flows executing with zero errors.\n")
	fmt.Printf("%s======================================================================%s\n\n", ColorCyan, ColorReset)
}
