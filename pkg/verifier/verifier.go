/**
 * @file verifier.go
 * @brief Out-of-band verification engine validating succinct proofs for the VALKYRIE system.
 *
 * License: GNU GPLv3
 */

package verifier

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/westkevin12/RAMNET/VALKYRIE/pkg/prover"
)

// freivaldsRounds is the number of random probes used to check A x B == C.
// Each round rejects an incorrect C with probability >= 1/2 over Z/2^32, so the
// chance of accepting a wrong output is at most 2^-freivaldsRounds.
const freivaldsRounds = 24

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

	// 4. Verify the output itself.
	//
	// Checks 1-3 only prove the proof is internally consistent; none of them ties
	// C to A and B, and the signature uses no secret, so a worker can hand-build a
	// valid-looking proof for any C. The verifier must therefore check C against
	// A x B on its own, using parameters it controls (never values taken from the
	// request or the proof).
	if err := verifyOutput(proof.HardwareTier, a, b, c); err != nil {
		return false, err
	}

	return true, nil
}

// verifyOutput confirms that C is consistent with A x B for the declared tier,
// using verifier-owned parameters only.
func verifyOutput(tier string, a, b, c []int32) error {
	cells := len(c)
	if len(a) != cells || len(b) != cells {
		return fmt.Errorf("output verification failed: array length mismatch len(a)=%d len(b)=%d len(c)=%d",
			len(a), len(b), len(c))
	}
	n, err := matrixDim(cells)
	if err != nil {
		return fmt.Errorf("output verification failed: %w", err)
	}

	switch tier {
	case "digital_exact":
		if err := freivalds(n, a, b, c, freivaldsRounds); err != nil {
			return fmt.Errorf("output verification failed (digital_exact): %w", err)
		}
	case "analog_range":
		if err := checkAnalogRange(n, a, b, c); err != nil {
			return fmt.Errorf("output verification failed (analog_range): %w", err)
		}
	default:
		return fmt.Errorf("output verification failed: unsupported hardware tier %q", tier)
	}
	return nil
}

// matrixDim returns n for a flattened n x n matrix, or an error if cells is not a
// perfect square.
func matrixDim(cells int) (int, error) {
	if cells <= 0 {
		return 0, fmt.Errorf("empty matrix")
	}
	n := int(math.Round(math.Sqrt(float64(cells))))
	if n*n != cells {
		return 0, fmt.Errorf("array length %d is not a perfect square", cells)
	}
	return n, nil
}

// freivalds probabilistically checks A x B == C over Z/2^32, the ring the ORCHID
// kernels actually compute in (int32 arithmetic wraps mod 2^32). For a random
// vector r it checks A(Br) == Cr; for any wrong C a single round passes with
// probability at most 1/2, so rounds independent probes bound the false-accept
// rate by 2^-rounds. Each round is O(n^2), versus O(n^3) to recompute the product.
func freivalds(n int, a, b, c []int32, rounds int) error {
	au := asUint32(a)
	bu := asUint32(b)
	cu := asUint32(c)

	for round := 0; round < rounds; round++ {
		r, err := randomVec(n)
		if err != nil {
			// Fail closed: a verifier that cannot sample randomness must not pass.
			return fmt.Errorf("could not sample verification randomness: %w", err)
		}

		// br = B r
		br := make([]uint32, n)
		for i := 0; i < n; i++ {
			var sum uint32
			row := i * n
			for j := 0; j < n; j++ {
				sum += bu[row+j] * r[j]
			}
			br[i] = sum
		}

		// Check A(Br) == C r row by row.
		for i := 0; i < n; i++ {
			var abr, cr uint32
			row := i * n
			for j := 0; j < n; j++ {
				abr += au[row+j] * br[j]
				cr += cu[row+j] * r[j]
			}
			if abr != cr {
				return fmt.Errorf("C is not the product A x B (mismatch at row %d)", i)
			}
		}
	}
	return nil
}

// checkAnalogRange recomputes the ideal product and confirms every entry of C is
// within the verifier's own drift budget. The tolerance is derived from the
// verifier-owned prover.DefaultDriftSigma / prover.DefaultZCritical policy and is
// never taken from the request, so a worker cannot widen it by inflating Sigma.
func checkAnalogRange(n int, a, b, c []int32) error {
	ideal := idealProduct(n, a, b)
	maxAllowedDrift := prover.DefaultZCritical * prover.DefaultDriftSigma * 100.0
	for i := range c {
		drift := math.Abs(float64(c[i]) - float64(ideal[i]))
		if drift > maxAllowedDrift {
			return fmt.Errorf("drift %.2f at index %d exceeds verifier bound %.2f", drift, i, maxAllowedDrift)
		}
	}
	return nil
}

// idealProduct computes A x B with the same int32 wrapping semantics as the
// ORCHID reference kernel.
func idealProduct(n int, a, b []int32) []int32 {
	ideal := make([]int32, n*n)
	for i := 0; i < n; i++ {
		for kv := 0; kv < n; kv++ {
			r := a[i*n+kv]
			for j := 0; j < n; j++ {
				ideal[i*n+j] += r * b[kv*n+j]
			}
		}
	}
	return ideal
}

func asUint32(v []int32) []uint32 {
	out := make([]uint32, len(v))
	for i, x := range v {
		out[i] = uint32(x)
	}
	return out
}

// randomVec returns n uniform uint32 values drawn from crypto/rand.
func randomVec(n int) ([]uint32, error) {
	buf := make([]byte, n*4)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	out := make([]uint32, n)
	for i := 0; i < n; i++ {
		out[i] = binary.LittleEndian.Uint32(buf[i*4:])
	}
	return out, nil
}
