package dvrf

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	fr "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
)

// reconstructSecret recovers f(0) = Σ λ_i·sk_i over a chosen subset of DKG outputs.
func reconstructSecret(outs []*DKGOut, subset []int) fr.Element {
	idx := make([]fr.Element, len(subset))
	for k, s := range subset {
		idx[k].SetUint64(uint64(outs[s].Participant.Index))
	}
	var secret fr.Element
	for k, s := range subset {
		lam := lagrange(idx, k)
		var term fr.Element
		term.Mul(&lam, &outs[s].Participant.SK)
		secret.Add(&secret, &term)
	}
	return secret
}

// TestDVRF_Soundness independently validates (without relying on the package's
// own Verify) that:
//   (1) the Feldman shares are a valid t-of-n sharing of a single secret:
//       secret·G == GroupKey, and the same secret is recovered from any subset;
//   (2) Combine produces the canonical DVRF value secret·H(α):
//       CombinedGamma == secret·H(α).
func TestDVRF_Soundness(t *testing.T) {
	n, th := 5, 3
	outs, err := RunDKG(n, th)
	if err != nil {
		t.Fatal(err)
	}
	g := g1Generator()

	// (1) secret·G == GroupKey, consistent across two disjoint-ish subsets.
	secretA := reconstructSecret(outs, []int{0, 1, 2})
	secretB := reconstructSecret(outs, []int{2, 3, 4})
	if !secretA.Equal(&secretB) {
		t.Fatal("reconstructed secret differs across subsets — invalid Shamir sharing")
	}
	pkA := scalarMulAff(&g, &secretA)
	if !pkA.Equal(&outs[0].GroupKey.Point) {
		t.Fatal("secret·G != GroupKey — Feldman DKG unsound")
	}
	t.Log("(1) DKG sound: secret·G == GroupKey, consistent across subsets")

	// (2) CombinedGamma == secret·H(α).
	var alpha [32]byte
	copy(alpha[:], []byte("dvrf-soundness-alpha"))
	H := hashToG1(alpha)

	var evals []*Eval
	for _, s := range []int{0, 1, 2} {
		ev, err := PartialEval(&outs[s].Participant, alpha)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyPartialEval(ev, outs[s].Participant.VK, alpha) {
			t.Fatalf("DLEQ verify failed for participant %d", outs[s].Participant.Index)
		}
		evals = append(evals, ev)
	}
	out, err := Combine(evals, alpha)
	if err != nil {
		t.Fatal(err)
	}
	expected := scalarMulAff(&H, &secretA) // secret·H(α)
	if !out.CombinedGamma.Equal(&expected) {
		t.Fatal("CombinedGamma != secret·H(α) — Lagrange combine unsound")
	}
	t.Log("(2) Combine sound: CombinedGamma == secret·H(α)")

	// (3) Tamper: corrupting a partial's gamma must fail DLEQ verification.
	bad, _ := PartialEval(&outs[0].Participant, alpha)
	var two fr.Element
	two.SetUint64(2)
	var badGammaJac secp256k1.G1Jac
	badGammaJac.ScalarMultiplication(affToJac(&bad.Gamma), two.BigInt(new(big.Int)))
	bad.Gamma.FromJacobian(&badGammaJac)
	if VerifyPartialEval(bad, outs[0].Participant.VK, alpha) {
		t.Fatal("tampered gamma passed DLEQ verification — soundness broken")
	}
	t.Log("(3) Tamper rejected: corrupted gamma fails DLEQ")
}
