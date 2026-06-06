/**
 * @file prover.go
 * @brief Zero-knowledge and range-inference proof compiler for VALKYRIE verification layer.
 * 
 * License: GNU GPLv3
 */

package prover

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

// Constants for analog range verification
const (
	DefaultDriftSigma = 0.05
	DefaultZCritical  = 1.96 // 95% confidence
)

// Header metadata for execution trace
type Header struct {
	TaskId           string   `json:"task_id"`
	LogicHash        string   `json:"logic_hash"`
	InputCommitments []string `json:"input_commitments"`
	HardwareTier     string   `json:"hardware_tier"`
}

// Step represents a single register transition in the trace vector
type Step struct {
	Step     int       `json:"step"`
	Op       string    `json:"op"`
	Addr     uint64    `json:"addr"`
	Val      []float64 `json:"val"`
	RegIn    int       `json:"reg_in,omitempty"`
	RegAccum int       `json:"reg_accum,omitempty"`
}

// Footer metadata for execution trace
type Footer struct {
	OutputCommitment string `json:"output_commitment"`
}

// ExecutionTrace maps step-by-step state changes of registers and memory
type ExecutionTrace struct {
	Header Header `json:"header"`
	Steps  []Step `json:"steps"`
	Footer Footer `json:"footer"`
}

// Proof is the succinct non-interactive cryptographic proof payload
type Proof struct {
	TaskId           string    `json:"task_id"`
	HardwareTier     string    `json:"hardware_tier"`
	InputCommitment  string    `json:"input_commitment"`
	OutputCommitment string    `json:"output_commitment"`
	TraceHash        string    `json:"trace_hash"`
	ProofBytes       []byte    `json:"proof_bytes"`
	Signature        []byte    `json:"signature"`
	Verified         bool      `json:"verified"`
	Timestamp        time.Time `json:"timestamp"`
	ExecutionTimeMs  int64     `json:"execution_time_ms"`
}

type errWriter struct {
	w   *bytes.Buffer
	err error
}

func (ew *errWriter) write(data any) {
	if ew.err != nil {
		return
	}
	ew.err = binary.Write(ew.w, binary.LittleEndian, data)
}

func (ew *errWriter) writeBytes(data []byte) {
	if ew.err != nil {
		return
	}
	_, ew.err = ew.w.Write(data)
}

// SerializeBinary encodes the trace into a standard binary vector for ZK constraints ingestion
func (et *ExecutionTrace) SerializeBinary() ([]byte, error) {
	buf := new(bytes.Buffer)
	ew := &errWriter{w: buf}

	// Task ID length and bytes
	taskIdBytes := []byte(et.Header.TaskId)
	ew.write(uint32(len(taskIdBytes)))
	ew.writeBytes(taskIdBytes)

	// Logic Hash length and bytes
	logicHashBytes := []byte(et.Header.LogicHash)
	ew.write(uint32(len(logicHashBytes)))
	ew.writeBytes(logicHashBytes)

	// Hardware Tier length and bytes
	tierBytes := []byte(et.Header.HardwareTier)
	ew.write(uint32(len(tierBytes)))
	ew.writeBytes(tierBytes)

	// Steps length
	ew.write(uint32(len(et.Steps)))

	// Steps data
	for _, step := range et.Steps {
		ew.write(uint32(step.Step))
		opBytes := []byte(step.Op)
		ew.write(uint32(len(opBytes)))
		ew.writeBytes(opBytes)
		ew.write(step.Addr)
		ew.write(uint32(len(step.Val)))
		for _, v := range step.Val {
			ew.write(v)
		}
		ew.write(int32(step.RegIn))
		ew.write(int32(step.RegAccum))
	}

	// Output commitment length and bytes
	outCommitBytes := []byte(et.Footer.OutputCommitment)
	ew.write(uint32(len(outCommitBytes)))
	ew.writeBytes(outCommitBytes)

	if ew.err != nil {
		return nil, ew.err
	}
	return buf.Bytes(), nil
}

// ComputeCommitment calculates a cryptographic commitment hash of the input/output array
func ComputeCommitment(data []int32) string {
	hasher := sha256.New()
	buf := make([]byte, 4)
	for _, val := range data {
		binary.LittleEndian.PutUint32(buf, uint32(val))
		hasher.Write(buf)
	}
	return fmt.Sprintf("0x%x", hasher.Sum(nil))
}

// ProofParams holds the parameters for generating a proof.
type ProofParams struct {
	TaskId       string
	HardwareTier string
	N            int
	AData        []int32
	BData        []int32
	CObserved    []int32
	Sigma        float64
	ZCritical    float64
}

// verifyDigitalExact performs digital validation and constructs corresponding trace steps
func verifyDigitalExact(n int, a, b, cObserved, cIdeal []int32) ([]Step, error) {
	cells := n * n
	for i := 0; i < cells; i++ {
		if cObserved[i] != cIdeal[i] {
			return nil, fmt.Errorf("digital verification failed: bit-for-bit parity mismatch at index %d (expected %d, got %d)",
				i, cIdeal[i], cObserved[i])
		}
	}

	// Generate dynamic trace steps simulating digital registers operations (scaled down for sanity)
	var traceSteps []Step
	stepCount := 0
	limit := 10
	if cells < limit {
		limit = cells
	}
	for i := 0; i < limit; i++ {
		traceSteps = append(traceSteps, Step{
			Step: stepCount,
			Op:   "VLOAD",
			Addr: uint64(0x7ffd0000 + i*4),
			Val:  []float64{float64(a[i]), float64(b[i])},
		})
		stepCount++
		traceSteps = append(traceSteps, Step{
			Step:     stepCount,
			Op:       "VMUL_ACC",
			RegIn:    0,
			RegAccum: 1,
			Val:      []float64{float64(cObserved[i])},
		})
		stepCount++
	}
	return traceSteps, nil
}

// verifyAnalogRange performs analog drift checks and constructs corresponding trace steps
func verifyAnalogRange(n int, a, b, cObserved, cIdeal []int32, sigma, zCritical float64) ([]Step, error) {
	cells := n * n
	if sigma <= 0 {
		sigma = DefaultDriftSigma
	}
	if zCritical <= 0 {
		zCritical = DefaultZCritical
	}
	maxAllowedDrift := zCritical * sigma * 100.0 // Scaled for integer domain comparison

	// Range-bounded verification check
	for i := 0; i < cells; i++ {
		diff := math.Abs(float64(cObserved[i] - cIdeal[i]))
		if diff > maxAllowedDrift {
			return nil, fmt.Errorf("analog range verification failed: drift %.2f at index %d exceeds allowed boundary %.2f",
				diff, i, maxAllowedDrift)
		}
	}

	// Generate steps including drift values
	var traceSteps []Step
	stepCount := 0
	limit := 10
	if cells < limit {
		limit = cells
	}
	for i := 0; i < limit; i++ {
		traceSteps = append(traceSteps, Step{
			Step: stepCount,
			Op:   "VALOAD", // Analog load
			Addr: uint64(0x8ffd0000 + i*4),
			Val:  []float64{float64(a[i]), float64(b[i])},
		})
		stepCount++
		drift := float64(cObserved[i] - cIdeal[i])
		traceSteps = append(traceSteps, Step{
			Step:     stepCount,
			Op:       "VAMUL_DRIFT",
			RegIn:    0,
			RegAccum: 1,
			Val:      []float64{float64(cObserved[i]), drift},
		})
		stepCount++
	}
	return traceSteps, nil
}

// GenerateProof evaluates the execution results and synthesizes the ZK or range-bounded proof payload
func GenerateProof(params ProofParams) (*Proof, *ExecutionTrace, error) {
	startTime := time.Now()
	cells := params.N * params.N
	if len(params.AData) != cells || len(params.BData) != cells || len(params.CObserved) != cells {
		return nil, nil, fmt.Errorf("invalid matrix dimensions: expected size %d (%d cells), got a=%d, b=%d, c=%d",
			params.N, cells, len(params.AData), len(params.BData), len(params.CObserved))
	}

	// Compute ideal matrix multiplication result in Go (reference model)
	cIdeal := make([]int32, cells)
	for i := 0; i < params.N; i++ {
		for kv := 0; kv < params.N; kv++ {
			r := params.AData[i*params.N+kv]
			for j := 0; j < params.N; j++ {
				cIdeal[i*params.N+j] += r * params.BData[kv*params.N+j]
			}
		}
	}

	// Perform physical checking based on hardware tier
	var traceSteps []Step
	var err error

	switch params.HardwareTier {
	case "digital_exact":
		traceSteps, err = verifyDigitalExact(params.N, params.AData, params.BData, params.CObserved, cIdeal)
		if err != nil {
			return nil, nil, err
		}
	case "analog_range":
		traceSteps, err = verifyAnalogRange(params.N, params.AData, params.BData, params.CObserved, cIdeal, params.Sigma, params.ZCritical)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("unsupported hardware tier: %s", params.HardwareTier)
	}

	// Compute commitments
	aCommit := ComputeCommitment(params.AData)
	bCommit := ComputeCommitment(params.BData)
	cCommit := ComputeCommitment(params.CObserved)

	// Compute Logic Hash representing program execution properties
	logicHasher := sha256.New()
	logicHasher.Write([]byte(fmt.Sprintf("%s-%d-%s", params.HardwareTier, params.N, cCommit)))
	logicHash := fmt.Sprintf("0x%x", logicHasher.Sum(nil))

	// Construct execution trace
	trace := &ExecutionTrace{
		Header: Header{
			TaskId:           params.TaskId,
			LogicHash:        logicHash,
			InputCommitments: []string{aCommit, bCommit},
			HardwareTier:     params.HardwareTier,
		},
		Steps: traceSteps,
		Footer: Footer{
			OutputCommitment: cCommit,
		},
	}

	// Serialize trace to binary
	binaryBytes, err := trace.SerializeBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize trace: %w", err)
	}

	// Compute Trace Hash (Succinct verification key)
	traceHashBytes := sha256.Sum256(binaryBytes)
	traceHash := fmt.Sprintf("0x%x", traceHashBytes)

	// Compute Mock ZK Cryptographic Proof (SHA256 signature of trace + inputs commitments)
	sigHasher := sha256.New()
	sigHasher.Write(traceHashBytes[:])
	sigHasher.Write([]byte(params.TaskId))
	sigHasher.Write([]byte(aCommit))
	sigHasher.Write([]byte(bCommit))
	sigHasher.Write([]byte(cCommit))
	signature := sigHasher.Sum(nil)

	// Compile proof object
	proof := &Proof{
		TaskId:           params.TaskId,
		HardwareTier:     params.HardwareTier,
		InputCommitment:  fmt.Sprintf("%s+%s", aCommit, bCommit),
		OutputCommitment: cCommit,
		TraceHash:        traceHash,
		ProofBytes:       binaryBytes,
		Signature:        signature,
		Verified:         true,
		Timestamp:        time.Now(),
		ExecutionTimeMs:  time.Since(startTime).Milliseconds(),
	}

	return proof, trace, nil
}
