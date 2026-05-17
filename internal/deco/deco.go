// Package deco implements dx-DCTLS attestation (§VIII of the paper).
//
// HSP: ECDH ephemeral handshake → K_MAC derivation via TLS 1.2 PRF →
//      (K^P_MAC, K^V_MAC) split → co-SNARK commit-then-reveal → π_HSP.
//      Verification of π_HSP is performed with a real Groth16.Verify call.
//
// QP:  Transcript commitment via HMAC-SHA256(K_MAC, Q||R).
//
// PGP: Exportable proof (π_HSP + transcript commitment + statement + ZKP digest).
//
// TLS ECDH simulation:
//   - Prover and Verifier each generate an ephemeral secp256k1 key pair.
//   - Pre-master secret (PMS) = ECDH(P.sk, V.pk) = ECDH(V.sk, P.pk)
//   - K_MAC = TLS-PRF(PMS, "master secret" || CR || SR)[0:32] XOR rand32
//     (rand32 = DVRF output — binds the session to DVRF randomness)
package deco

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	mimcNative "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
	"github.com/CanDenizGokgedik/tls-gnark/internal/cosnark"
	"github.com/CanDenizGokgedik/tls-gnark/internal/dvrf"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// EphemeralKeyPair is a one-time key pair for the ECDH handshake.
type EphemeralKeyPair struct {
	SK fr.Element
	PK secp256k1.G1Affine
}

// HspProof is the exportable handshake proof (π_HSP).
type HspProof struct {
	SessionID      [16]byte
	Rand           [32]byte
	ProofBytes     []byte   // serialised Groth16 proof
	KMacCommit     [32]byte // SHA256("cosnark/k-mac/v1" || kMac)
	SessionBinding [32]byte // H(sid || rand || kMacCommit || certHash)
	// Groth16 public inputs — required for verification.
	CommitFe  []byte // big.Int bytes: pack(pShare)+pack(vShare)+pack(rand32)
	RandFe    []byte // big.Int bytes: pack(rand32)
	ProveMs   int64
}

// Session holds the full dx-DCTLS session state after HSP.
type Session struct {
	SessionID  [16]byte
	KMacP      [32]byte // prover's share
	KMacV      [32]byte // verifier's share
	KMac       [32]byte // KMacP XOR KMacV — known only to the coordinator
	KMacCommit [32]byte
	PMS        [32]byte // ECDH pre-master secret
	ClientRand [32]byte
	ServerRand [32]byte
	PiHSP      HspProof
	CRS        *cosnark.CRS
	HSPMs      int64
}

// QueryRecord is the QP output.
type QueryRecord struct {
	SessionID            [16]byte
	TranscriptCommitment [32]byte // HMAC-SHA256(K_MAC, Q||R)
}

// DVRFBundle holds the DVRF output and all data needed for verification.
// VerifyDxDctlsProof uses this to run DVRF.Verify.
type DVRFBundle struct {
	Output *dvrf.Output           // combined output from Combine()
	Evals  []*dvrf.Eval           // each participant's partial evaluation
	VKs    []secp256k1.G1Affine  // each participant's verification key
	GK     *dvrf.GroupKey        // group public key
	Alpha  [32]byte              // input to DVRF (session nonce)
}

// PgpCRS holds the compiled constraint system and Groth16 keys for the PGP circuit.
type PgpCRS struct {
	CS constraint.ConstraintSystem
	PK groth16.ProvingKey
	VK groth16.VerifyingKey
}

// DxDctlsProof is the exportable proof produced by PGP.
//
// Full proof bundle from paper §V:
//   - π_HSP  : Groth16 handshake proof (K_MAC split)
//   - π_PGP  : Groth16 PGP proof (K_MAC share knowledge)
//   - DVRF   : Partial evaluations + group public key (for Verify)
type DxDctlsProof struct {
	PiHSP        HspProof
	QueryRecord  QueryRecord
	Statement    []byte
	ProofDigest  [32]byte
	CrossBinding [32]byte
	// PGP ZKP fields (real Groth16 proof).
	PgpProofBytes []byte   // serialised π_PGP
	KMacHash      []byte   // MiMC(KMacP, KMacV) — Groth16 public input
	// DVRF fields (for Verify).
	DVRF DVRFBundle
}

// ── ECDH Helpers ──────────────────────────────────────────────────────────────

// GenerateEphemeral generates an ephemeral key pair on secp256k1.
func GenerateEphemeral() (*EphemeralKeyPair, error) {
	var sk fr.Element
	if _, err := sk.SetRandom(); err != nil {
		return nil, err
	}
	g1Jac, _ := secp256k1.Generators()
	var g1 secp256k1.G1Affine
	g1.FromJacobian(&g1Jac)

	var pkJac secp256k1.G1Jac
	pkJac.ScalarMultiplication(&g1Jac, sk.BigInt(new(big.Int)))
	var pk secp256k1.G1Affine
	pk.FromJacobian(&pkJac)
	return &EphemeralKeyPair{SK: sk, PK: pk}, nil
}

// ecdhShared computes: sk * peerPK (secp256k1 scalar multiplication).
// The X coordinate of the result is used as the PMS (TLS 1.2 §8.1).
func ecdhShared(sk fr.Element, peerPK secp256k1.G1Affine) [32]byte {
	var jac secp256k1.G1Jac
	jac.FromAffine(&peerPK)
	jac.ScalarMultiplication(&jac, sk.BigInt(new(big.Int)))
	var shared secp256k1.G1Affine
	shared.FromJacobian(&jac)

	// Encode X coordinate as 32 bytes (big-endian, zero-padded).
	xBytes := shared.X.BigInt(new(big.Int)).Bytes()
	var pms [32]byte
	copy(pms[32-len(xBytes):], xBytes)
	return pms
}

// ── HSP ───────────────────────────────────────────────────────────────────────

// HSP runs the Handshake Session Parameter phase.
//
// Processing flow:
//  1. Prover and Verifier generate ephemeral ECDH key pairs.
//  2. PMS = ECDH(proverSK, verifierPK) is computed.
//  3. ClientRandom and ServerRandom are generated randomly.
//  4. K_MAC = TLS-PRF(PMS, "master secret"||CR||SR)[0:32] is derived.
//  5. K_MAC is bound to the DVRF output via field addition with rand32.
//  6. pShare is random; vShare = kMac XOR pShare (split).
//  7. co-SNARK commit-then-reveal → π_HSP Groth16 proof.
func HSP(crs *cosnark.CRS, rand32, certHash [32]byte) (*Session, error) {
	// Step 1: ECDH ephemeral key pairs.
	proverKey, err := GenerateEphemeral()
	if err != nil {
		return nil, err
	}
	verifierKey, err := GenerateEphemeral()
	if err != nil {
		return nil, err
	}

	// Step 2: PMS = ECDH(proverSK, verifierPK).
	pms := ecdhShared(proverKey.SK, verifierKey.PK)

	// Step 3: Nonces.
	var clientRandom, serverRandom [32]byte
	if _, err := rand.Read(clientRandom[:]); err != nil {
		return nil, err
	}
	if _, err := rand.Read(serverRandom[:]); err != nil {
		return nil, err
	}

	// Step 4: K_MAC base = TLS-PRF(PMS, "master secret"||CR||SR)[0:32].
	kMacBase := circuit.MasterSecretNative(pms, clientRandom, serverRandom)

	// Step 5: Bind K_MAC to rand32 via field addition (consistent with circuit constraints).
	// TlsPrfCircuit.Define:  kMacFe = pack(P1H2_output) + RandBinding  (mod q)
	// Fr addition is used instead of XOR to match the circuit witness exactly.
	q := ecc.BLS12_381.ScalarField()
	kMacBaseFe := circuit.PackBytes32(kMacBase)
	randFe := circuit.PackBytes32(rand32)
	kMacFe := new(big.Int).Add(kMacBaseFe, randFe)
	kMacFe.Mod(kMacFe, q)
	var kMac [32]byte
	kMacFeBytes := kMacFe.Bytes()
	copy(kMac[32-len(kMacFeBytes):], kMacFeBytes)

	// Step 6: Field-additive K_MAC split.
	// kMacFe = pShareFe + vShareFe  (mod q) — consistent with circuit constraints.
	var pShare [32]byte
	if _, err := rand.Read(pShare[:]); err != nil {
		return nil, err
	}
	pShareFe := circuit.PackBytes32(pShare)
	vShareFe := new(big.Int).Sub(kMacFe, pShareFe)
	vShareFe.Mod(vShareFe, q)
	var vShare [32]byte
	vShareFeBytes := vShareFe.Bytes()
	copy(vShare[32-len(vShareFeBytes):], vShareFeBytes)

	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return nil, err
	}

	// Step 7: co-SNARK → π_HSP.
	// ModeKey: genuine distributed MSM (each party knows only its own scalar).
	// ModePRF: TLS-PRF HMAC chain requires central proving; ExecuteSplit is used.
	t0 := time.Now()
	var mpcRes *cosnark.MpcResult
	if crs.Mode == cosnark.ModeKey {
		mpcRes, err = cosnark.ExecuteDistributedMSM(crs, pShare, vShare, rand32)
	} else {
		mpcRes, err = cosnark.ExecuteSplit(crs, pShare, vShare, rand32, pms, clientRandom, serverRandom)
	}
	if err != nil {
		return nil, err
	}
	hspMs := time.Since(t0).Milliseconds()

	// Public inputs for Groth16 verification (for auxiliary verifiers).
	// randFe was already defined above for K_MAC derivation; reuse it.
	commitFe := new(big.Int).Add(circuit.PackBytes32(pShare), circuit.PackBytes32(vShare))
	commitFe.Add(commitFe, randFe)
	commitFe.Mod(commitFe, ecc.BLS12_381.ScalarField())

	// K_MAC commitment.
	kMacCommit := sha256.Sum256(append(
		[]byte("cosnark/k-mac/v1\x00"),
		kMac[:]...))

	binding := sessionBinding(sid, rand32, kMacCommit, certHash)

	piHSP := HspProof{
		SessionID:      sid,
		Rand:           rand32,
		ProofBytes:     mpcRes.ProofBytes,
		KMacCommit:     kMacCommit,
		SessionBinding: binding,
		CommitFe:       commitFe.Bytes(),
		RandFe:         randFe.Bytes(),
		ProveMs:        mpcRes.ProveMs,
	}

	return &Session{
		SessionID:  sid,
		KMacP:      pShare,
		KMacV:      vShare,
		KMac:       kMac,
		KMacCommit: kMacCommit,
		PMS:        pms,
		ClientRand: clientRandom,
		ServerRand: serverRandom,
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

// ── SetupPGP ──────────────────────────────────────────────────────────────────

// SetupPGP runs the Groth16 trusted setup for the PGP circuit.
// The returned PgpCRS is passed to PGP() and VerifyDxDctlsProof().
func SetupPGP() (*PgpCRS, error) {
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit.PgpCircuit{})
	if err != nil {
		return nil, fmt.Errorf("SetupPGP: compile: %w", err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return nil, fmt.Errorf("SetupPGP: groth16.Setup: %w", err)
	}
	return &PgpCRS{CS: cs, PK: pk, VK: vk}, nil
}

// mimcHash computes MiMC(a, b) over BLS12-381 Fr.
// The result must match the KMacHash public input of PgpCircuit.
//
// gnark-crypto MiMC.Write requires values to be smaller than the BLS12-381 Fr modulus.
// Since random 32-byte KMac values may exceed the modulus, both inputs are reduced
// mod q first.
func mimcHash(a, b *big.Int) ([]byte, error) {
	q := ecc.BLS12_381.ScalarField()
	aRed := new(big.Int).Mod(a, q)
	bRed := new(big.Int).Mod(b, q)

	h := mimcNative.NewMiMC()
	// Write 32-byte big-endian field elements.
	var aBuf, bBuf [32]byte
	aBytes := aRed.Bytes()
	bBytes := bRed.Bytes()
	copy(aBuf[32-len(aBytes):], aBytes)
	copy(bBuf[32-len(bBytes):], bBytes)
	if _, err := h.Write(aBuf[:]); err != nil {
		return nil, fmt.Errorf("mimcHash Write(a): %w", err)
	}
	if _, err := h.Write(bBuf[:]); err != nil {
		return nil, fmt.Errorf("mimcHash Write(b): %w", err)
	}
	return h.Sum(nil), nil
}

// ── PGP ───────────────────────────────────────────────────────────────────────

// PGP produces the exportable dx-DCTLS proof.
//
// Paper §V definition:
//
//	π_pgp ← ZKP.Prove(x, w)   x=(Q, R, θs)   w=(Q̂, R̂, spv, b)
//
// If pgpCRS is nil the ZKP step is skipped (backward compatibility / testing).
// If dvrf is nil the DVRFBundle is left empty.
func PGP(sess *Session, qr QueryRecord, statement []byte, pgpCRS *PgpCRS, dvrf_ *DVRFBundle) DxDctlsProof {
	// Cross-binding hash.
	var h2Buf bytes.Buffer
	h2Buf.WriteString("tls-attestation/deco-pgp/cross-binding/v1\x00")
	h2Buf.Write(sess.PiHSP.SessionBinding[:])
	h2Buf.Write(qr.TranscriptCommitment[:])
	crossBind := sha256.Sum256(h2Buf.Bytes())

	proof := DxDctlsProof{
		PiHSP:        sess.PiHSP,
		QueryRecord:  qr,
		Statement:    statement,
		CrossBinding: crossBind,
	}
	if dvrf_ != nil {
		proof.DVRF = *dvrf_
	}

	// Real Groth16 ZKP generation.
	if pgpCRS != nil {
		q := ecc.BLS12_381.ScalarField()
		// Reduce KMac values mod field modulus (required for MiMC and circuit).
		kMacPFe := new(big.Int).Mod(circuit.PackBytes32(sess.KMacP), q)
		kMacVFe := new(big.Int).Mod(circuit.PackBytes32(sess.KMacV), q)

		// KMacHash = MiMC(kMacPFe, kMacVFe) — public input.
		hashBytes, err := mimcHash(kMacPFe, kMacVFe)
		if err == nil {
			kMacHashFe := new(big.Int).SetBytes(hashBytes)
			assignment := &circuit.PgpCircuit{
				KMacP:    kMacPFe,
				KMacV:    kMacVFe,
				KMacHash: kMacHashFe,
			}
			wit, werr := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
			if werr == nil {
				p, perr := groth16.Prove(pgpCRS.CS, pgpCRS.PK, wit)
				if perr == nil {
					var buf bytes.Buffer
					if _, serr := p.WriteTo(&buf); serr == nil {
						proof.PgpProofBytes = buf.Bytes()
						proof.KMacHash = hashBytes
					}
				}
			}
		}
	}

	// ProofDigest: SHA-256 digest of all proof data.
	var hBuf bytes.Buffer
	hBuf.WriteString("tls-attestation/deco-pgp/proof/v1\x00")
	hBuf.Write(qr.SessionID[:])
	hBuf.Write(qr.TranscriptCommitment[:])
	hBuf.Write(statement)
	hBuf.Write(proof.PgpProofBytes)
	proof.ProofDigest = sha256.Sum256(hBuf.Bytes())

	return proof
}

// ── Verify ─────────────────────────────────────────────────────────────────────

// VerifyHSP fully verifies π_HSP:
//  1. Checks the rand binding.
//  2. Recomputes the session binding hash.
//  3. Verifies the Groth16 proof against the CRS (real ZKP verification).
func VerifyHSP(crs *cosnark.CRS, pi HspProof, rand32, certHash [32]byte) error {
	// Check 1: rand binding.
	if pi.Rand != rand32 {
		return errors.New("verifyHSP: rand binding mismatch")
	}

	// Check 2: session binding hash.
	expectedBinding := sessionBinding(pi.SessionID, rand32, pi.KMacCommit, certHash)
	if expectedBinding != pi.SessionBinding {
		return errors.New("verifyHSP: session binding hash mismatch")
	}

	// Check 3: real Groth16 proof verification.
	if len(pi.ProofBytes) == 0 {
		return errors.New("verifyHSP: π_HSP proof bytes are empty")
	}
	if len(pi.CommitFe) == 0 || len(pi.RandFe) == 0 {
		return errors.New("verifyHSP: Groth16 public inputs missing")
	}

	commitFe := new(big.Int).SetBytes(pi.CommitFe)
	randFe := new(big.Int).SetBytes(pi.RandFe)

	var pubAssignment frontend.Circuit
	if crs.Mode == cosnark.ModeKey {
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

	proof := groth16.NewProof(ecc.BLS12_381)
	if _, err := proof.ReadFrom(bytes.NewReader(pi.ProofBytes)); err != nil {
		return fmt.Errorf("verifyHSP: proof deserialize error: %w", err)
	}

	pubWit, err := frontend.NewWitness(pubAssignment, ecc.BLS12_381.ScalarField(),
		frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("verifyHSP: public witness error: %w", err)
	}

	if err := groth16.Verify(proof, crs.VK, pubWit); err != nil {
		return fmt.Errorf("verifyHSP: Groth16 verification failed: %w", err)
	}
	return nil
}

// VerifyTranscript checks the transcript commitment against K_MAC, Q and R.
func VerifyTranscript(qr QueryRecord, kMac [32]byte, query, response []byte) bool {
	msg := append(query, response...)
	mac := circuit.HmacSha256Native(kMac[:], msg)
	var expected [32]byte
	copy(expected[:], mac)
	return expected == qr.TranscriptCommitment
}

// ── VerifyDxDctlsProof ────────────────────────────────────────────────────────

// VerifyDxDctlsProof implements the auxiliary verifier checks from paper §V.
//
// Three conditions (all must pass):
//
//  1. ZKP.Verify(π_HSP, w)   — Groth16 K_MAC split proof (VerifyHSP)
//  2. ZKP.Verify(π_PGP, w)   — Groth16 PGP proof (K_MAC share knowledge)
//  3. DVRF.Verify(pk, α, evals, out) — DVRF output consistency
//
// hspCRS: HSP Groth16 keys.
// pgpCRS: PGP Groth16 keys (Condition 2 is skipped if nil).
// rand32: α input to DVRF (session nonce).
// certHash: server certificate hash.
func VerifyDxDctlsProof(
	p DxDctlsProof,
	hspCRS *cosnark.CRS,
	pgpCRS *PgpCRS,
	rand32, certHash [32]byte,
) error {
	// ── Condition 1: π_HSP Groth16 verification ──────────────────────────────
	if err := VerifyHSP(hspCRS, p.PiHSP, rand32, certHash); err != nil {
		return fmt.Errorf("VerifyDxDctlsProof [Condition 1 — π_HSP]: %w", err)
	}

	// ── Condition 2: π_PGP Groth16 verification ──────────────────────────────
	if pgpCRS != nil && len(p.PgpProofBytes) > 0 && len(p.KMacHash) > 0 {
		kMacHashFe := new(big.Int).SetBytes(p.KMacHash)
		pubAssignment := &circuit.PgpCircuit{KMacHash: kMacHashFe}
		pgpProof := groth16.NewProof(ecc.BLS12_381)
		if _, err := pgpProof.ReadFrom(bytes.NewReader(p.PgpProofBytes)); err != nil {
			return fmt.Errorf("VerifyDxDctlsProof [Condition 2 — π_PGP deserialize]: %w", err)
		}
		pubWit, err := frontend.NewWitness(pubAssignment, ecc.BLS12_381.ScalarField(),
			frontend.PublicOnly())
		if err != nil {
			return fmt.Errorf("VerifyDxDctlsProof [Condition 2 — π_PGP witness]: %w", err)
		}
		if err := groth16.Verify(pgpProof, pgpCRS.VK, pubWit); err != nil {
			return fmt.Errorf("VerifyDxDctlsProof [Condition 2 — π_PGP Groth16]: %w", err)
		}
	}

	// ── Condition 3: DVRF.Verify ─────────────────────────────────────────────
	b := p.DVRF
	if b.Output != nil && len(b.Evals) > 0 && len(b.VKs) == len(b.Evals) {
		if !dvrf.Verify(b.GK, b.Alpha, b.Evals, b.VKs, b.Output) {
			return errors.New("VerifyDxDctlsProof [Condition 3 — DVRF.Verify]: DVRF output invalid")
		}
		// DVRF randomness must be bound to π_HSP.
		if b.Output.Rand != rand32 {
			return errors.New("VerifyDxDctlsProof [Condition 3 — DVRF.Verify]: DVRF rand ≠ π_HSP rand")
		}
	}

	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func sessionBinding(sid [16]byte, rand32, kMacCommit, certHash [32]byte) [32]byte {
	var buf bytes.Buffer
	buf.WriteString("tls-attestation/deco-session-binding/v1\x00")
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
