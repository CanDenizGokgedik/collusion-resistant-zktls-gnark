// mpc.go — simulated 2-party co-SNARK execution using goroutines + channels.
//
// Architecture mirrors the Rust co-snark-prover subprocess model:
//
//   Prover goroutine            Verifier goroutine
//   holds pShare only           holds vShare only
//        │                           │
//        └─── shareMsg ──────────────┘
//                  coordinator receives both
//                  → assembles witness
//                  → runs Groth16.Prove
//
// In a real MPC deployment the coordinator would never see plaintext shares;
// instead each party would contribute to individual MSM operations via the
// Beaver-triple protocol (as in collaborative-zksnark). Here we model the
// communication boundary and timing overhead faithfully while keeping the
// implementation in pure Go without a distributed MSM library.
//
// The two execution modes match the paper's Table II:
//
//   Execute      — centralised  (coordinator sees both shares in plaintext)
//   ExecuteSplit — split-input  (each goroutine sends only its own share;
//                               coordinator combines and proves)
package cosnark

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
)

// ShareMsg is the message each party sends to the coordinator.
type ShareMsg struct {
	PartyID int    // 0 = prover, 1 = verifier
	Share   [32]byte
	Err     error
}

// MpcResult carries the co-SNARK output.
type MpcResult struct {
	ProofBytes []byte
	ProveMs    int64
	CommitMs   int64 // time until both shares arrived (communication latency proxy)
}

// Execute runs the co-SNARK in centralised mode:
// the coordinator receives both shares and proves directly.
func Execute(
	crs *CRS,
	pShare, vShare, randBinding [32]byte,
	pms, clientRandom, serverRandom [32]byte,
) (*MpcResult, error) {
	t0 := time.Now()
	pr, err := Prove(crs, pShare, vShare, randBinding, pms, clientRandom, serverRandom)
	if err != nil {
		return nil, err
	}
	return &MpcResult{
		ProofBytes: pr.ProofBytes,
		ProveMs:    pr.ProveMs,
		CommitMs:   time.Since(t0).Milliseconds(),
	}, nil
}

// ExecuteSplit runs the co-SNARK in split-input mode:
// two goroutines each hold only their own share and send it via a channel.
// The coordinator receives both, assembles the witness, and calls Groth16.Prove.
//
// This matches the Rust mpc_prover.rs two-subprocess model.
func ExecuteSplit(
	crs *CRS,
	pShare, vShare, randBinding [32]byte,
	pms, clientRandom, serverRandom [32]byte,
) (*MpcResult, error) {
	ch := make(chan ShareMsg, 2)

	// Prover goroutine — knows only pShare.
	go func() {
		ch <- ShareMsg{PartyID: 0, Share: pShare}
	}()

	// Verifier goroutine — knows only vShare.
	go func() {
		ch <- ShareMsg{PartyID: 1, Share: vShare}
	}()

	// Coordinator: collect both shares.
	t0 := time.Now()
	received := make(map[int][32]byte, 2)
	for i := 0; i < 2; i++ {
		msg := <-ch
		if msg.Err != nil {
			return nil, fmt.Errorf("party %d error: %w", msg.PartyID, msg.Err)
		}
		received[msg.PartyID] = msg.Share
	}
	commitMs := time.Since(t0).Milliseconds()

	// Assemble witness from received shares.
	p := received[0]
	v := received[1]

	randFe := circuit.PackBytes32(randBinding)
	commit := new(big.Int).Add(circuit.PackBytes32(p), circuit.PackBytes32(v))
	commit.Add(commit, randFe)
	commit.Mod(commit, ecc.BLS12_381.ScalarField())

	var assignment frontend.Circuit
	if crs.Mode == ModeKey {
		assignment = &circuit.TlsKeyCircuit{
			PShare:      circuit.PackBytes32(p),
			VShare:      circuit.PackBytes32(v),
			Commitment:  commit,
			RandBinding: randFe,
		}
	} else {
		a := circuit.NewTlsPrfAssignment(pms, clientRandom, serverRandom, p, v, randBinding)
		a.Commitment = commit
		assignment = a
	}

	wit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		return nil, err
	}

	t1 := time.Now()
	proof, err := groth16.Prove(crs.CS, crs.PK, wit)
	if err != nil {
		return nil, err
	}
	proveMs := time.Since(t1).Milliseconds()

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, err
	}

	return &MpcResult{
		ProofBytes: buf.Bytes(),
		ProveMs:    proveMs,
		CommitMs:   commitMs,
	}, nil
}

// VerifyMpc verifies a proof produced by Execute or ExecuteSplit.
func VerifyMpc(
	crs *CRS,
	result *MpcResult,
	pShare, vShare, randBinding [32]byte,
) error {
	randFe := circuit.PackBytes32(randBinding)
	commit := new(big.Int).Add(circuit.PackBytes32(pShare), circuit.PackBytes32(vShare))
	commit.Add(commit, randFe)
	commit.Mod(commit, ecc.BLS12_381.ScalarField())

	var pubAssignment frontend.Circuit
	if crs.Mode == ModeKey {
		pubAssignment = &circuit.TlsKeyCircuit{
			Commitment:  commit,
			RandBinding: randFe,
		}
	} else {
		pubAssignment = &circuit.TlsPrfCircuit{
			Commitment:  commit,
			RandBinding: randFe,
		}
	}
	return Verify(crs, result.ProofBytes, pubAssignment)
}