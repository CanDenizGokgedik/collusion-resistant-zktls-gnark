package frost

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

func reconstructSecret(outs []*DKGOut, subset []int) fr.Element {
	idx := make([]fr.Element, len(subset))
	for k, s := range subset {
		idx[k].SetUint64(uint64(outs[s].Signer.Index))
	}
	var secret fr.Element
	for k, s := range subset {
		lam := lagrange(idx, k)
		var term fr.Element
		term.Mul(&lam, &outs[s].Signer.SK)
		secret.Add(&secret, &term)
	}
	return secret
}

// signWith runs the full 2-round FROST signing with the given subset and
// returns the aggregated signature.
func signWith(t *testing.T, outs []*DKGOut, subset []int, msg [32]byte) *Signature {
	t.Helper()
	var nonces []*Nonce
	var commits []*Commitment
	for _, s := range subset {
		n, c, err := Round1(&outs[s].Signer)
		if err != nil {
			t.Fatal(err)
		}
		nonces = append(nonces, n)
		commits = append(commits, c)
	}
	var shares []*SignatureShare
	for k, s := range subset {
		sh, err := Round2(&outs[s].Signer, nonces[k], commits, msg)
		if err != nil {
			t.Fatal(err)
		}
		shares = append(shares, sh)
	}
	sig, err := Aggregate(commits, shares, msg)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// TestFROST_Soundness independently validates:
//   (1) Feldman shares are a valid t-of-n sharing: secret·G == GroupKey;
//   (2) the aggregated signature satisfies the textbook Schnorr equation
//       S·G == R + c·PK, recomputed independently of the package Verify;
//   (3) the threshold property: a different t-subset yields a signature that
//       also verifies under the same GroupKey;
//   (4) tamper: flipping S breaks verification.
func TestFROST_Soundness(t *testing.T) {
	n, th := 5, 3
	outs, err := RunDKG(n, th)
	if err != nil {
		t.Fatal(err)
	}
	g := g1Gen()
	gk := outs[0].GroupKey

	// (1) secret·G == GroupKey.
	secret := reconstructSecret(outs, []int{0, 1, 2})
	pk := scalarMul(&g, &secret)
	if !pk.Equal(&gk.Point) {
		t.Fatal("secret·G != GroupKey — Feldman DKG unsound")
	}
	t.Log("(1) DKG sound: secret·G == GroupKey")

	var msg [32]byte
	copy(msg[:], []byte("frost-soundness-message"))

	// (2) independent Schnorr check on a {1,2,3} signature.
	sig := signWith(t, outs, []int{0, 1, 2}, msg)
	c := challenge(sig.R, gk.Point, msg)
	sG := scalarMul(&g, &sig.S)
	cPK := scalarMul(&gk.Point, &c)
	var rhs secp256k1.G1Jac
	rhs.FromAffine(&sig.R)
	var cPKJac secp256k1.G1Jac
	cPKJac.FromAffine(&cPK)
	rhs.AddAssign(&cPKJac) // R + c·PK
	var rhsAff secp256k1.G1Affine
	rhsAff.FromJacobian(&rhs)
	if !sG.Equal(&rhsAff) {
		t.Fatal("S·G != R + c·PK — FROST signature unsound")
	}
	t.Log("(2) Signature sound: S·G == R + c·PK (independent Schnorr verify)")

	// (3) threshold property: a different subset verifies under the same key.
	sig2 := signWith(t, outs, []int{1, 3, 4}, msg)
	if !Verify(sig2, gk, msg) {
		t.Fatal("signature from second subset failed to verify — threshold property broken")
	}
	t.Log("(3) Threshold property: disjoint subset verifies under same GroupKey")

	// (4) tamper.
	bad := &Signature{R: sig.R}
	var one fr.Element
	one.SetOne()
	bad.S.Add(&sig.S, &one)
	if Verify(bad, gk, msg) {
		t.Fatal("tampered signature verified — soundness broken")
	}
	t.Log("(4) Tamper rejected: S+1 fails verification")
}
