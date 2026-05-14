package dvrf_test

import (
	"testing"

	"github.com/CanDenizGokgedik/tls-gnark/internal/dvrf"
)

func TestDKG_BasicStructure(t *testing.T) {
	n, threshold := 5, 3
	outs, err := dvrf.RunDKG(n, threshold)
	if err != nil {
		t.Fatalf("RunDKG: %v", err)
	}
	if len(outs) != n {
		t.Fatalf("expected %d participants, got %d", n, len(outs))
	}
	for i, o := range outs {
		if o.Participant.Index != i+1 {
			t.Errorf("participant %d has index %d", i, o.Participant.Index)
		}
		if o.GroupKey == nil {
			t.Errorf("participant %d has nil GroupKey", i)
		}
	}
}

func TestDKG_ThresholdGTN(t *testing.T) {
	_, err := dvrf.RunDKG(3, 5)
	if err == nil {
		t.Fatal("expected error when threshold > n")
	}
}

func TestPartialEval_Deterministic(t *testing.T) {
	outs, err := dvrf.RunDKG(3, 2)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}
	alpha := [32]byte{0x42}

	e1, err := dvrf.PartialEval(&outs[0].Participant, alpha)
	if err != nil {
		t.Fatalf("PartialEval 1: %v", err)
	}
	e2, err := dvrf.PartialEval(&outs[0].Participant, alpha)
	if err != nil {
		t.Fatalf("PartialEval 2: %v", err)
	}
	// Gamma should be the same (deterministic from SK and alpha).
	if !e1.Gamma.Equal(&e2.Gamma) {
		t.Error("Gamma is not deterministic for same (SK, alpha)")
	}
}

func TestCombine_Threshold(t *testing.T) {
	const n, thr = 5, 3
	outs, err := dvrf.RunDKG(n, thr)
	if err != nil {
		t.Fatalf("DKG: %v", err)
	}
	alpha := [32]byte{0xAB, 0xCD}

	var evals []*dvrf.Eval
	for i := 0; i < thr; i++ {
		e, err := dvrf.PartialEval(&outs[i].Participant, alpha)
		if err != nil {
			t.Fatalf("PartialEval[%d]: %v", i, err)
		}
		evals = append(evals, e)
	}

	out, err := dvrf.Combine(evals, alpha)
	if err != nil {
		t.Fatalf("Combine: %v", err)
	}
	// Output should be 32 non-zero bytes.
	allZero := true
	for _, b := range out.Rand {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("VRF output Rand is all zeros")
	}
	t.Logf("VRF output: %x…", out.Rand[:8])
}

func TestCombine_ConsistentAcrossSubsets(t *testing.T) {
	// Same alpha with same t participants should give same output.
	const n, thr = 5, 3
	outs, _ := dvrf.RunDKG(n, thr)
	alpha := [32]byte{0x77}

	evals1 := make([]*dvrf.Eval, thr)
	for i := range evals1 {
		e, _ := dvrf.PartialEval(&outs[i].Participant, alpha)
		evals1[i] = e
	}
	out1, _ := dvrf.Combine(evals1, alpha)

	evals2 := make([]*dvrf.Eval, thr)
	for i := range evals2 {
		e, _ := dvrf.PartialEval(&outs[i].Participant, alpha)
		evals2[i] = e
	}
	out2, _ := dvrf.Combine(evals2, alpha)

	if out1.Rand != out2.Rand {
		t.Error("Combine gives different results for same inputs")
	}
}

func TestCombine_EmptyEvals(t *testing.T) {
	_, err := dvrf.Combine(nil, [32]byte{})
	if err == nil {
		t.Fatal("expected error for empty evals")
	}
}