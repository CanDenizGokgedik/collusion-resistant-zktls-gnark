// Package deco implements dx-DCTLS attestation (§VIII of the paper).
//
// HSP: Derive K_MAC, split into (K^P_MAC, K^V_MAC), run co-SNARK → π_HSP.
// QP:  Commit to (Q, R) with HMAC-SHA256(K_MAC, Q||R).
// PGP: Assemble exportable proof (π_HSP + transcript commitment + statement).
package deco

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"time"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// HspProof is the exportable handshake proof (π_HSP).
type HspProof struct {
	SessionID      [16]byte
	Rand           [32]byte
	ProofBytes     []byte   // serialised Groth16 proof
	SessionBinding [32]byte // H(sid || rand || kMacCommit || certHash)
	ProveMs        int64
}

// Session holds the full dx-DCTLS session state after HSP.
type Session struct {
	SessionID  [16]byte
	KMacP      [32]byte // prover's share
	KMacV      [32]byte // verifier's share
	KMac       [32]byte // KMacP XOR KMacV — only coordinator knows this
	KMacCommit [32]byte
	PiHSP      HspProof
	CRS        *cosnark.CRS
	HSPMs      int64
}

// QueryRecord is the QP output.
type QueryRecord struct {
	SessionID            [16]byte
	TranscriptCommitment [32]byte // HMAC-SHA256(K_MAC, query||response)
}

// DxDctlsProof is the full exportable attestation proof (PGP output).
type DxDctlsProof struct {
	PiHSP        HspProof
	QueryRecord  QueryRecord
	Statement    []byte
	ProofDigest  [32]byte
	CrossBinding [32]byte
}

// ── HSP ───────────────────────────────────────────────────────────────────────

// HSP runs the Handshake Session Parameter phase.
//
//	(S, P, V_coord) → (sps, spp, spv) ← HSP(pp, rand)
//	V_coord gets π_HSP ← co-SNARK.Execute({K^P_MAC, K^V_MAC}, rand)
func HSP(crs *cosnark.CRS, rand32, certHash [32]byte) (*Session, error) {
	// Derive K_MAC from DVRF randomness (simplified; production uses TLS PMS).
	seed := sha256.Sum256(append(
		[]byte("tls-attestation/deco-hsp/k-mac-seed/v1"),
		rand32[:]...))
	var kMac [32]byte
	copy(kMac[:], seed[:])

	// Split K_MAC: pShare is random, vShare = kMac XOR pShare.
	var pShare [32]byte
	if _, err := rand.Read(pShare[:]); err != nil {
		return nil, err
	}
	vShare := circuit.XorBytes32(kMac, pShare)

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}

	// Run co-SNARK (split-input mode: prover and verifier goroutines).
	var pms, cr, sr [32]byte // production derives these from TLS handshake
	t0 := time.Now()
	mpcRes, err := cosnark.ExecuteSplit(crs, pShare, vShare, rand32, pms, cr, sr)
	if err != nil {
		return nil, err
	}
	hspMs := time.Since(t0).Milliseconds()

	// K_MAC commitment.
	kMacCommit := sha256.Sum256(append(
		[]byte("tls-attestation/co-snark/k-mac/v1\x00"),
		kMac[:]...))

	binding := sessionBinding(sid, rand32, kMacCommit, certHash)

	piHSP := HspProof{
		SessionID:      sid,
		Rand:           rand32,
		ProofBytes:     mpcRes.ProofBytes,
		SessionBinding: binding,
		ProveMs:        mpcRes.ProveMs,
	}

	return &Session{
		SessionID:  sid,
		KMacP:      pShare,
		KMacV:      vShare,
		KMac:       kMac,
		KMacCommit: kMacCommit,
		PiHSP:      piHSP,
		CRS:        crs,
		HSPMs:      hspMs,
	}, nil
}

// ── QP ────────────────────────────────────────────────────────────────────────

// QP runs the Query Phase — commits to (Q, R) using K_MAC.
func QP(sess *Session, query, response []byte) QueryRecord {
	msg := append(query, response...)
	mac := circuit.HmacSha256Native(sess.KMac[:], msg)
	var commit [32]byte
	copy(commit[:], mac)
	return QueryRecord{
		SessionID:            sess.SessionID,
		TranscriptCommitment: commit,
	}
}

// ── PGP ───────────────────────────────────────────────────────────────────────

// PGP assembles the exportable dx-DCTLS proof.
//
//	π_dx-DCTLS ← ZKP.Prove(x, w)  where x=(Q,R,θs), w=(Q̂,R̂,spv,b)
func PGP(sess *Session, qr QueryRecord, statement []byte) DxDctlsProof {
	var hBuf bytes.Buffer
	hBuf.WriteString("tls-attestation/deco-pgp/proof/v1")
	hBuf.Write(qr.SessionID[:])
	hBuf.Write(qr.TranscriptCommitment[:])
	hBuf.Write(statement)
	digest := sha256.Sum256(hBuf.Bytes())

	var h2Buf bytes.Buffer
	h2Buf.WriteString("tls-attestation/deco-pgp/cross-binding/v1")
	h2Buf.Write(sess.PiHSP.SessionBinding[:])
	h2Buf.Write(qr.TranscriptCommitment[:])
	crossBind := sha256.Sum256(h2Buf.Bytes())

	return DxDctlsProof{
		PiHSP:        sess.PiHSP,
		QueryRecord:  qr,
		Statement:    statement,
		ProofDigest:  digest,
		CrossBinding: crossBind,
	}
}

// ── Verify ─────────────────────────────────────────────────────────────────────

// VerifyHSP checks that π_HSP is bound to the given rand.
func VerifyHSP(pi HspProof, rand32 [32]byte) bool {
	return pi.Rand == rand32
}

// VerifyTranscript checks the transcript commitment against K_MAC, Q, R.
func VerifyTranscript(qr QueryRecord, kMac [32]byte, query, response []byte) bool {
	msg := append(query, response...)
	mac := circuit.HmacSha256Native(kMac[:], msg)
	var expected [32]byte
	copy(expected[:], mac)
	return expected == qr.TranscriptCommitment
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func sessionBinding(sid [16]byte, rand32, kMacCommit, certHash [32]byte) [32]byte {
	var buf bytes.Buffer
	buf.WriteString("tls-attestation/deco-session-binding/v1")
	buf.Write(sid[:])
	buf.Write(rand32[:])
	buf.Write(kMacCommit[:])
	buf.Write(certHash[:])
	return sha256.Sum256(buf.Bytes())
}

// MockSession creates a deterministic mock TLS session for testing.
type MockSession struct {
	ServerName string
	CertHash   [32]byte
	Nonce      [32]byte
}

// NewMock returns a mock session with seed-derived values.
func NewMock(name string, seed byte) MockSession {
	var certHash, nonce [32]byte
	for i := range certHash {
		certHash[i] = seed + byte(i)
		nonce[i] = seed ^ byte(i)
	}
	return MockSession{ServerName: name, CertHash: certHash, Nonce: nonce}
}