// mpc.go — 2-party co-SNARK with additive blinding (paper §III).
//
// In a real co-SNARK (Ozdemir-Boneh USENIX Sec. 2022) each party multiplies
// its witness share directly by CRS points, combining contributions
// homomorphically so the coordinator never sees individual shares.
// Since gnark's public API does not expose distributed MSM, an equivalent
// additive blinding protocol is used here:
//
//   ┌─────────────────────────────────────────────────────────────────────┐
//   │  Additive Blinding Protocol (Mode 1 — K_MAC Split)                 │
//   │                                                                     │
//   │  Prover (P)                 Verifier (V)          Coordinator (C)  │
//   │  knows: pShare              knows: vShare          knows: commit    │
//   │                                                                     │
//   │  r ∈_R Fr                                                           │
//   │  maskedP = pack(pShare)+r   ← r (P→V secure channel) →             │
//   │                             maskedV = pack(vShare)-r                │
//   │                                                                     │
//   │  com_P=H(n_P||maskedP) ──────────────────────────▶ com_P           │
//   │                         com_V=H(n_V||maskedV) ──▶  com_V           │
//   │  (maskedP, n_P) ─────────────────────────────────▶ verify          │
//   │                         (maskedV, n_V) ──────────▶ verify          │
//   │                                                                     │
//   │  C sees: maskedP, maskedV (never sees individual shares)            │
//   │  maskedP + maskedV = pack(pShare) + pack(vShare) → circuit ✓        │
//   └─────────────────────────────────────────────────────────────────────┘
//
// Mode 2 (TLS PRF): requires distributed HMAC to split PRF witnesses;
// currently falls back to central mode (future work).

package cosnark

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
)

// ── Message types ─────────────────────────────────────────────────────────────

// CommitMsg — Phase 1: hash commitment over a masked share.
type CommitMsg struct {
	PartyID int
	Commit  [32]byte // SHA256("cosnark/commit/v1" || nonce || maskedFeBytes)
	Err     error
}

// RevealMsg — Phase 2: masked share field element and nonce reveal.
type RevealMsg struct {
	PartyID  int
	MaskedFe []byte   // big.Int bytes: pack(share) ± r  (mod q) — visible to coordinator
	Nonce    [32]byte // commitment nonce
	Err      error
}

// ShareMsg is retained for backward compatibility (used by bench pipeline).
type ShareMsg = CommitMsg

// MpcResult — co-SNARK output.
type MpcResult struct {
	ProofBytes []byte
	ProveMs    int64
	CommitMs   int64 // commit phase duration
	RevealMs   int64 // reveal + verification phase duration
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// commitToFe computes the commitment: SHA256("cosnark/commit/v1" || nonce || feBytes).
func commitToFe(nonce [32]byte, feBytes []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("cosnark/commit/v1\x00"))
	h.Write(nonce[:])
	h.Write(feBytes)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// randFieldElem generates a random element in the BLS12-381 scalar field.
func randFieldElem() (*big.Int, error) {
	q := ecc.BLS12_381.ScalarField()
	for {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		r := new(big.Int).SetBytes(b)
		r.Mod(r, q)
		if r.Sign() != 0 {
			return r, nil
		}
	}
}

// ── Execute (central mode) ────────────────────────────────────────────────────

// Execute runs the co-SNARK in central mode.
// The coordinator receives both shares directly; used for reference and testing.
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

// ── ExecuteSplit (additive blinding mode) ────────────────────────────────────

// ExecuteSplit runs the 2-party co-SNARK protocol with additive blinding.
//
// The coordinator never sees individual shares; it only sees masked field elements
// and their commitments. The blinding factor r is sent from P to V over a
// coordinator-independent channel.
func ExecuteSplit(
	crs *CRS,
	pShare, vShare, randBinding [32]byte,
	pms, clientRandom, serverRandom [32]byte,
) (*MpcResult, error) {
	// Mode 2 falls back to central mode (distributed HMAC not yet implemented).
	if crs.Mode != ModeKey {
		return Execute(crs, pShare, vShare, randBinding, pms, clientRandom, serverRandom)
	}

	q := ecc.BLS12_381.ScalarField()

	// P↔V secure channel: independent of coordinator (carries blinding factor r).
	blindingCh := make(chan *big.Int, 1)
	// Channels to the coordinator.
	commitCh := make(chan CommitMsg, 2)
	revealCh := make(chan RevealMsg, 2)

	// ── Prover goroutine ─────────────────────────────────────────────────────
	// Knows only pShare. Generates r, sends it to V, computes maskedP.
	go func() {
		// Blinding factor r ∈ Fr
		r, err := randFieldElem()
		if err != nil {
			commitCh <- CommitMsg{PartyID: 0, Err: fmt.Errorf("P: rand field elem: %w", err)}
			blindingCh <- nil
			return
		}
		// maskedP = pack(pShare) + r  (mod q)
		pFe := circuit.PackBytes32(pShare)
		maskedP := new(big.Int).Add(pFe, r)
		maskedP.Mod(maskedP, q)

		// P→V: send r over a coordinator-blind channel.
		blindingCh <- r

		// Commit phase.
		maskedPBytes := maskedP.Bytes()
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			commitCh <- CommitMsg{PartyID: 0, Err: fmt.Errorf("P: nonce: %w", err)}
			return
		}
		com := commitToFe(nonce, maskedPBytes)
		commitCh <- CommitMsg{PartyID: 0, Commit: com}

		// Reveal phase.
		revealCh <- RevealMsg{PartyID: 0, MaskedFe: maskedPBytes, Nonce: nonce}
	}()

	// ── Verifier goroutine ───────────────────────────────────────────────────
	// Knows only vShare. Receives r from P, computes maskedV.
	go func() {
		// Receive r from P (coordinator never sees this channel).
		r := <-blindingCh
		if r == nil {
			commitCh <- CommitMsg{PartyID: 1, Err: errors.New("V: failed to receive blinding factor")}
			return
		}
		// maskedV = pack(vShare) - r  (mod q)
		vFe := circuit.PackBytes32(vShare)
		maskedV := new(big.Int).Sub(vFe, r)
		maskedV.Add(maskedV, q) // prevent negative result
		maskedV.Mod(maskedV, q)

		// Commit phase.
		maskedVBytes := maskedV.Bytes()
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			commitCh <- CommitMsg{PartyID: 1, Err: fmt.Errorf("V: nonce: %w", err)}
			return
		}
		com := commitToFe(nonce, maskedVBytes)
		commitCh <- CommitMsg{PartyID: 1, Commit: com}

		// Reveal phase.
		revealCh <- RevealMsg{PartyID: 1, MaskedFe: maskedVBytes, Nonce: nonce}
	}()

	// ── Coordinator: Phase 1 — Collect commitments ────────────────────────────
	t0 := time.Now()
	commits := make(map[int][32]byte, 2)
	for i := 0; i < 2; i++ {
		msg := <-commitCh
		if msg.Err != nil {
			return nil, fmt.Errorf("cosnark: commit phase party %d: %w", msg.PartyID, msg.Err)
		}
		commits[msg.PartyID] = msg.Commit
	}
	commitMs := time.Since(t0).Milliseconds()

	// ── Coordinator: Phase 2 — Reveal and verify commitments ─────────────────
	t1 := time.Now()
	masked := make(map[int]*big.Int, 2)
	for i := 0; i < 2; i++ {
		msg := <-revealCh
		if msg.Err != nil {
			return nil, fmt.Errorf("cosnark: reveal phase party %d: %w", msg.PartyID, msg.Err)
		}
		// Verify commitment: H(nonce || maskedFe) == stored commit
		expected := commitToFe(msg.Nonce, msg.MaskedFe)
		stored := commits[msg.PartyID]
		if !bytes.Equal(expected[:], stored[:]) {
			return nil, fmt.Errorf(
				"cosnark: party %d commitment mismatch — share may have been tampered",
				msg.PartyID,
			)
		}
		masked[msg.PartyID] = new(big.Int).SetBytes(msg.MaskedFe)
	}
	revealMs := time.Since(t1).Milliseconds()

	// ── Coordinator: Phase 3 — Build witness and prove ───────────────────────
	// Coordinator sees maskedP and maskedV; never sees the real pShare/vShare.
	// maskedP + maskedV = pack(pShare) + pack(vShare) → circuit constraint ✓
	maskedP := masked[0]
	maskedV := masked[1]

	randFe := circuit.PackBytes32(randBinding)
	// commitment = maskedP + maskedV + rand = pack(pShare) + pack(vShare) + rand ✓
	commitFe := new(big.Int).Add(maskedP, maskedV)
	commitFe.Add(commitFe, randFe)
	commitFe.Mod(commitFe, q)

	assignment := &circuit.TlsKeyCircuit{
		PShare:      maskedP,   // masked: coordinator never sees the real pShare
		VShare:      maskedV,   // masked: coordinator never sees the real vShare
		Commitment:  commitFe,
		RandBinding: randFe,
	}

	wit, err := frontend.NewWitness(assignment, q)
	if err != nil {
		return nil, fmt.Errorf("cosnark: witness: %w", err)
	}

	t2 := time.Now()
	proof, err := groth16.Prove(crs.CS, crs.PK, wit)
	if err != nil {
		return nil, fmt.Errorf("cosnark: groth16.Prove: %w", err)
	}
	proveMs := time.Since(t2).Milliseconds()

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, err
	}

	return &MpcResult{
		ProofBytes: buf.Bytes(),
		ProveMs:    proveMs,
		CommitMs:   commitMs,
		RevealMs:   revealMs,
	}, nil
}

// ── VerifyMpc ─────────────────────────────────────────────────────────────────

// VerifyMpc verifies the proof produced by Execute or ExecuteSplit.
//
// Verification uses only the public commitment:
//   commitment = pack(pShare) + pack(vShare) + rand
// This equals maskedP + maskedV + rand (blinding cancels out), so auxiliary
// verifiers can verify without knowing the original shares.
func VerifyMpc(
	crs *CRS,
	result *MpcResult,
	pShare, vShare, randBinding [32]byte,
) error {
	q := ecc.BLS12_381.ScalarField()
	randFe := circuit.PackBytes32(randBinding)
	commitFe := new(big.Int).Add(circuit.PackBytes32(pShare), circuit.PackBytes32(vShare))
	commitFe.Add(commitFe, randFe)
	commitFe.Mod(commitFe, q)

	var pubAssignment frontend.Circuit
	if crs.Mode == ModeKey {
		pubAssignment = &circuit.TlsKeyCircuit{
			Commitment:  commitFe,
			RandBinding: randFe,
		}
	} else {
		pubAssignment = &circuit.TlsPrfCircuit{
			Commitment:  commitFe,
			RandBinding: randFe,
		}
	}
	return Verify(crs, result.ProofBytes, pubAssignment)
}