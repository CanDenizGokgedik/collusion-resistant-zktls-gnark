package circuit

import (
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

const tPrev = 128 // bytes absorbed into s_i (multiple of 64)
const tSuf = 16   // disclosed suffix length
const tTotal = tPrev + tSuf

type siTestCircuit struct {
	Si     [8]frontend.Variable `gnark:",public"`
	Suffix [tSuf]uints.U8       `gnark:",secret"`
	Expect [32]uints.U8         `gnark:",public"`
}

func (c *siTestCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	var si [8]uints.U32
	for i := 0; i < 8; i++ {
		si[i] = uapi.ValueOf(c.Si[i])
	}
	out := sha256ContinueInner(uapi, si, c.Suffix[:], tPrev, tTotal)
	for i := 0; i < 32; i++ {
		api.AssertIsEqual(out[i].Val, c.Expect[i].Val)
	}
	return nil
}

func TestSha256Continue(t *testing.T) {
	full := make([]byte, tTotal)
	for i := range full {
		full[i] = byte(i*7 + 3)
	}
	prefix := full[:tPrev]
	suffix := full[tPrev:]
	si := SiStateNative(prefix)
	expect := sha256.Sum256(full)

	a := &siTestCircuit{}
	for i := 0; i < 8; i++ {
		a.Si[i] = frontend.Variable(uint64(si[i]))
	}
	for i := 0; i < tSuf; i++ {
		a.Suffix[i] = uints.U8{Val: frontend.Variable(int(suffix[i]))}
	}
	for i := 0; i < 32; i++ {
		a.Expect[i] = uints.U8{Val: frontend.Variable(int(expect[i]))}
	}
	test.NewAssert(t).SolvingSucceeded(&siTestCircuit{}, a, test.WithCurves(ecc.BLS12_381))
}
