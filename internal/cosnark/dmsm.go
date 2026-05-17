// dmsm.go — Genuine Distributed MSM for Groth16 on BLS12-381.
//
// Concrete implementation of the Ozdemir-Boneh co-SNARK architecture on gnark.
// The coordinator NEVER sees the individual private scalars (pShare, vShare).
//
// Critical design note — Filtered Array:
//   gnark's pk.G1.A/B arrays are "filtered" arrays: wires with InfinityA[i]=true
//   are dropped and the remaining points are stored in a compact array.
//   Raw wire index ≠ filtered array index. filteredIdx() handles this mapping.
//
// Wire layout (TlsKeyCircuit, 5 wires):
//   w[0]=1(constant)  w[1]=Commitment  w[2]=RandBinding  w[3]=PShare  w[4]=VShare
//
// InfinityA flags (coefficient zero in the A polynomial = infinity):
//   w[0]=true (not part of any constraint)  w[1..4]=false
//   → pk.G1.A[0]=Commit, [1]=RandBind, [2]=PShare, [3]=VShare
//
// InfinityB flags (B polynomial has only w[0]=constant):
//   w[0]=false  w[1..4]=true
//   → pk.G1.B[0] = constant,  PShare and VShare contribute zero
//
// h=0 proof:
//   Constraint: Commit - PShare - VShare - RandBind = 0
//   When satisfied: solution.A[0]=0, solution.B[0]=1, solution.C[0]=0
//   computeH([0,…],[1,0,…],[0,…]) = IFFT_coset(0*b - 0) = 0 → h=[0,…]
package cosnark

import (
	"bytes"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	groth16bls "github.com/consensys/gnark/backend/groth16/bls12-381"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
)

// ── Filtered index computation ────────────────────────────────────────────────

// filteredIdx returns the position in the infinity-point-filtered array.
// For a given raw wire index i: how many non-infinity wires precede i?
// Returns -1 if the wire itself is infinity.
func filteredIdx(infinityFlags []bool, wireIdx int) int {
	if wireIdx >= len(infinityFlags) || infinityFlags[wireIdx] {
		return -1
	}
	j := 0
	for i := 0; i < wireIdx; i++ {
		if i < len(infinityFlags) && !infinityFlags[i] {
			j++
		}
	}
	return j
}

// ── Party contribution type ───────────────────────────────────────────────────

// PartyContrib holds a party's MSM contributions as group elements.
// The coordinator receives this struct — it never sees the underlying scalar.
type PartyContrib struct {
	PartyID   int
	KContrib  curve.G1Jac // G1.K[kIdx] * share
	AContrib  curve.G1Jac // G1.A[filteredIdxA] * share
	AIsZero   bool        // no contribution when A is infinity
	B1Contrib curve.G1Jac // G1.B[filteredIdxB] * share  (bs1 cross-term)
	B1IsZero  bool
	B2Contrib curve.G2Jac // G2.B[filteredIdxB] * share  (Bs G2)
	B2IsZero  bool
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func shareToFr381(share [32]byte) fr381.Element {
	b := circuit.PackBytes32(share)
	var fe fr381.Element
	fe.SetBigInt(b)
	return fe
}

func g1ScalarMul(pt *curve.G1Affine, s *big.Int) curve.G1Jac {
	var j curve.G1Jac
	j.FromAffine(pt)
	j.ScalarMultiplication(&j, s)
	return j
}

func g2ScalarMul(pt *curve.G2Affine, s *big.Int) curve.G2Jac {
	var j curve.G2Jac
	j.FromAffine(pt)
	j.ScalarMultiplication(&j, s)
	return j
}

// ── computePartyContrib ───────────────────────────────────────────────────────

// computePartyContrib computes all MSM contributions for one party.
// wireIdx: raw (unfiltered) wire index.
// kIdx:    position in the G1.K array for private wires (0=PShare, 1=VShare).
func computePartyContrib(
	partyID int,
	share [32]byte,
	wireIdx, kIdx int,
	pk *groth16bls.ProvingKey,
) *PartyContrib {
	fe := shareToFr381(share)
	var scl big.Int
	fe.BigInt(&scl)

	c := &PartyContrib{PartyID: partyID}

	// K contribution (always present; K array contains only private wires).
	if kIdx < len(pk.G1.K) {
		c.KContrib = g1ScalarMul(&pk.G1.K[kIdx], &scl)
	}

	// A contribution — use filtered index.
	idxA := filteredIdx(pk.InfinityA, wireIdx)
	if idxA < 0 || idxA >= len(pk.G1.A) {
		c.AIsZero = true
	} else {
		c.AContrib = g1ScalarMul(&pk.G1.A[idxA], &scl)
	}

	// B contributions (G1 and G2) — same InfinityB flag.
	idxB := filteredIdx(pk.InfinityB, wireIdx)
	if idxB < 0 || idxB >= len(pk.G1.B) {
		c.B1IsZero = true
	} else {
		c.B1Contrib = g1ScalarMul(&pk.G1.B[idxB], &scl)
	}
	if idxB < 0 || idxB >= len(pk.G2.B) {
		c.B2IsZero = true
	} else {
		c.B2Contrib = g2ScalarMul(&pk.G2.B[idxB], &scl)
	}

	return c
}

// ── ExecuteDistributedMSM ─────────────────────────────────────────────────────

// ExecuteDistributedMSM produces a genuine distributed Groth16 proof for TlsKeyCircuit.
//
// Each party contributes its G1/G2 group elements to the coordinator knowing
// only its own private scalar. The coordinator never sees pShare or vShare.
func ExecuteDistributedMSM(
	crs *CRS,
	pShare, vShare, randBinding [32]byte,
) (*MpcResult, error) {
	if crs.Mode != ModeKey {
		return Execute(crs, pShare, vShare, randBinding, [32]byte{}, [32]byte{}, [32]byte{})
	}

	concretePK, ok := crs.PK.(*groth16bls.ProvingKey)
	if !ok {
		return nil, fmt.Errorf("dmsm: ProvingKey is not a concrete type")
	}

	// Public wire values (known to the coordinator).
	q := ecc.BLS12_381.ScalarField()
	randFe := circuit.PackBytes32(randBinding)
	commitFe := new(big.Int).Add(circuit.PackBytes32(pShare), circuit.PackBytes32(vShare))
	commitFe.Add(commitFe, randFe)
	commitFe.Mod(commitFe, q)

	// BLS12-381 fr elements: w[0]=1, w[1]=Commitment, w[2]=RandBinding
	var pubScalars [3]fr381.Element
	pubScalars[0].SetOne()
	pubScalars[1].SetBigInt(commitFe)
	pubScalars[2].SetBigInt(randFe)

	// ── Phase 1: Party contributions (parallel goroutines) ───────────────────
	t0 := time.Now()
	contribCh := make(chan *PartyContrib, 2)

	go func() {
		// P: raw wire 3 (PShare), K array index 0
		contribCh <- computePartyContrib(0, pShare, 3, 0, concretePK)
	}()
	go func() {
		// V: raw wire 4 (VShare), K array index 1
		contribCh <- computePartyContrib(1, vShare, 4, 1, concretePK)
	}()

	contribs := make(map[int]*PartyContrib, 2)
	for i := 0; i < 2; i++ {
		c := <-contribCh
		contribs[c.PartyID] = c
	}
	commitMs := time.Since(t0).Milliseconds()

	// ── Phase 2: Coordinator assembles the proof ──────────────────────────────
	t1 := time.Now()

	// Zero-knowledge random blinding.
	var _r, _s, _kr fr381.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	_kr.Mul(&_r, &_s).Neg(&_kr)
	var rBig, sBig big.Int
	_r.BigInt(&rBig)
	_s.BigInt(&sBig)

	deltas := curve.BatchScalarMultiplicationG1(
		&concretePK.G1.Delta,
		[]fr381.Element{_r, _s, _kr},
	)

	// ── ar = Σ_{pub} G1.A[filteredIdx(i)] · w_pub[i]  +  A_P  +  A_V  +  α  +  r·Δ ──
	var ar curve.G1Jac
	for i := 0; i < 3; i++ {
		idxA := filteredIdx(concretePK.InfinityA, i)
		if idxA < 0 || idxA >= len(concretePK.G1.A) {
			continue
		}
		var s big.Int
		pubScalars[i].BigInt(&s)
		jac := g1ScalarMul(&concretePK.G1.A[idxA], &s)
		ar.AddAssign(&jac)
	}
	if !contribs[0].AIsZero {
		ar.AddAssign(&contribs[0].AContrib)
	}
	if !contribs[1].AIsZero {
		ar.AddAssign(&contribs[1].AContrib)
	}
	var alphaJac curve.G1Jac
	alphaJac.FromAffine(&concretePK.G1.Alpha)
	ar.AddAssign(&alphaJac)
	var d0 curve.G1Jac
	d0.FromAffine(&deltas[0])
	ar.AddAssign(&d0)

	// ── bs1 = Σ_{pub} G1.B[filteredIdx(i)] · w_pub[i]  +  B1_P  +  B1_V  +  β_G1  +  s·Δ ──
	var bs1 curve.G1Jac
	for i := 0; i < 3; i++ {
		idxB := filteredIdx(concretePK.InfinityB, i)
		if idxB < 0 || idxB >= len(concretePK.G1.B) {
			continue
		}
		var s big.Int
		pubScalars[i].BigInt(&s)
		jac := g1ScalarMul(&concretePK.G1.B[idxB], &s)
		bs1.AddAssign(&jac)
	}
	if !contribs[0].B1IsZero {
		bs1.AddAssign(&contribs[0].B1Contrib)
	}
	if !contribs[1].B1IsZero {
		bs1.AddAssign(&contribs[1].B1Contrib)
	}
	var betaG1Jac curve.G1Jac
	betaG1Jac.FromAffine(&concretePK.G1.Beta)
	bs1.AddAssign(&betaG1Jac)
	var d1 curve.G1Jac
	d1.FromAffine(&deltas[1])
	bs1.AddAssign(&d1)

	// ── Krs = K_P + K_V  +  kr·Δ_G1  +  r·bs1  +  s·ar ──────────────────────
	// h=0 → no Z contribution (single satisfied linear constraint).
	var krs curve.G1Jac
	krs.AddAssign(&contribs[0].KContrib)
	krs.AddAssign(&contribs[1].KContrib)
	var d2 curve.G1Jac
	d2.FromAffine(&deltas[2])
	krs.AddAssign(&d2)
	var rBs1 curve.G1Jac
	rBs1.ScalarMultiplication(&bs1, &rBig)
	krs.AddAssign(&rBs1)
	var sAr curve.G1Jac
	sAr.ScalarMultiplication(&ar, &sBig)
	krs.AddAssign(&sAr)

	// ── Bs = Σ_{pub} G2.B[filteredIdx(i)] · w_pub[i]  +  B2_P  +  B2_V  +  β_G2  +  s·Δ_G2 ──
	var Bs curve.G2Jac
	for i := 0; i < 3; i++ {
		idxB := filteredIdx(concretePK.InfinityB, i)
		if idxB < 0 || idxB >= len(concretePK.G2.B) {
			continue
		}
		var s big.Int
		pubScalars[i].BigInt(&s)
		jac := g2ScalarMul(&concretePK.G2.B[idxB], &s)
		Bs.AddAssign(&jac)
	}
	if !contribs[0].B2IsZero {
		Bs.AddAssign(&contribs[0].B2Contrib)
	}
	if !contribs[1].B2IsZero {
		Bs.AddAssign(&contribs[1].B2Contrib)
	}
	var betaG2Jac curve.G2Jac
	betaG2Jac.FromAffine(&concretePK.G2.Beta)
	Bs.AddAssign(&betaG2Jac)
	var deltaG2 curve.G2Jac
	deltaG2.FromAffine(&concretePK.G2.Delta)
	deltaG2.ScalarMultiplication(&deltaG2, &sBig)
	Bs.AddAssign(&deltaG2)

	proveMs := time.Since(t1).Milliseconds()

	// ── Proof assembly ────────────────────────────────────────────────────────
	var arAff curve.G1Affine
	arAff.FromJacobian(&ar)
	var krsAff curve.G1Affine
	krsAff.FromJacobian(&krs)
	var BsAff curve.G2Affine
	BsAff.FromJacobian(&Bs)

	concreteProof := &groth16bls.Proof{
		Ar:            arAff,
		Krs:           krsAff,
		Bs:            BsAff,
		Commitments:   []curve.G1Affine{},
		CommitmentPok: curve.G1Affine{},
	}

	var buf bytes.Buffer
	if _, err := concreteProof.WriteTo(&buf); err != nil {
		return nil, fmt.Errorf("dmsm: proof serialize: %w", err)
	}

	return &MpcResult{
		ProofBytes: buf.Bytes(),
		ProveMs:    proveMs,
		CommitMs:   commitMs,
	}, nil
}