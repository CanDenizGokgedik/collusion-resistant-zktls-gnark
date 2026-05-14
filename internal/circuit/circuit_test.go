package circuit_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/CanDenizGokgedik/tls-gnark/internal/circuit"
)

// ── Native helpers ────────────────────────────────────────────────────────────

func TestHmacSha256Native(t *testing.T) {
	key := [32]byte{0x0b, 0x0b, 0x0b}
	msg := []byte("Hi There")
	out := circuit.HmacSha256Native(key[:], msg)
	if len(out) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(out))
	}
	// HMAC-SHA256 of "Hi There" with key 0x0b*20 (RFC 4231 test vector #1)
	// Note: our key is only 3 bytes of 0x0b, so this just checks no-crash + length.
}

func TestTlsPrfNative_Deterministic(t *testing.T) {
	var secret [32]byte
	secret[0] = 0x01
	label := []byte("master secret")
	seed := make([]byte, 64)
	out1 := circuit.TlsPrfNative(secret[:], label, seed, 48)
	out2 := circuit.TlsPrfNative(secret[:], label, seed, 48)
	for i := range out1 {
		if out1[i] != out2[i] {
			t.Fatal("TlsPrfNative is not deterministic")
		}
	}
}

func TestXorBytes32(t *testing.T) {
	var a, b [32]byte
	for i := range a {
		a[i] = byte(i)
		b[i] = byte(i + 1)
	}
	c := circuit.XorBytes32(a, b)
	for i := range c {
		if c[i] != a[i]^b[i] {
			t.Fatalf("XorBytes32 wrong at index %d", i)
		}
	}
	// XOR with self = zero
	z := circuit.XorBytes32(a, a)
	for i, v := range z {
		if v != 0 {
			t.Fatalf("a XOR a != 0 at index %d", i)
		}
	}
}

func TestPackBytes32(t *testing.T) {
	var b [32]byte
	b[31] = 1 // big-endian 1
	fe := circuit.PackBytes32(b)
	if fe.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("PackBytes32([...1]) expected 1, got %s", fe.String())
	}
}

func TestMasterSecretNative_Length(t *testing.T) {
	var pms, cr, sr [32]byte
	pms[0] = 0xAB
	cr[0] = 0xCD
	sr[0] = 0xEF
	ms := circuit.MasterSecretNative(pms, cr, sr)
	// Just verify it's 32 bytes and non-zero.
	allZero := true
	for _, v := range ms {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("MasterSecretNative returned all zeros")
	}
}

// ── Mode 1 circuit ────────────────────────────────────────────────────────────

func TestTlsKeyCircuit_Groth16(t *testing.T) {
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit.TlsKeyCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	t.Logf("Mode 1 R1CS constraints: %d", cs.GetNbConstraints())

	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	// Commitment = pack(pShare) + pack(vShare) + pack(rand)  (field addition).
	// The circuit checks this directly: k_mac_var = p_var + v_var; computed = k_mac_var + rand.
	// Shares can be arbitrary — no XOR-disjoint constraint needed.
	var pShare, vShare, rand32 [32]byte
	pShare[0] = 0xDE
	pShare[1] = 0xAD
	vShare[0] = 0xBE
	vShare[1] = 0xEF

	pShareFe := circuit.PackBytes32(pShare)
	vShareFe := circuit.PackBytes32(vShare)
	randFe := circuit.PackBytes32(rand32)
	commit := new(big.Int).Add(pShareFe, vShareFe)
	commit.Add(commit, randFe)
	commit.Mod(commit, ecc.BLS12_381.ScalarField())

	assignment := &circuit.TlsKeyCircuit{
		PShare:      pShareFe,
		VShare:      vShareFe,
		Commitment:  commit,
		RandBinding: randFe,
	}
	wit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	proof, err := groth16.Prove(cs, pk, wit)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	pubWit, err := wit.Public()
	if err != nil {
		t.Fatalf("public witness: %v", err)
	}
	if err := groth16.Verify(proof, vk, pubWit); err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("Mode 1 Groth16 prove+verify: OK")
}

func TestTlsKeyCircuit_WrongCommitment(t *testing.T) {
	cs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &circuit.TlsKeyCircuit{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	pk, _, err := groth16.Setup(cs)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	var pShare, vShare [32]byte
	pShare[0] = 0x01
	vShare[0] = 0x02

	// Use wrong commitment (off by 1).
	kMac := circuit.XorBytes32(pShare, vShare)
	kMacFe := circuit.PackBytes32(kMac)
	badCommit := new(big.Int).Add(kMacFe, big.NewInt(1))
	badCommit.Mod(badCommit, ecc.BLS12_381.ScalarField())

	assignment := &circuit.TlsKeyCircuit{
		PShare:      circuit.PackBytes32(pShare),
		VShare:      circuit.PackBytes32(vShare),
		Commitment:  badCommit,
		RandBinding: big.NewInt(0),
	}
	wit, err := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	_, err = groth16.Prove(cs, pk, wit)
	if err == nil {
		t.Fatal("expected prove to fail with wrong commitment, but it succeeded")
	}
	t.Logf("Correctly rejected wrong commitment: %v", err)
}

func TestPrepareHMACKeys(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	ikey, okey := circuit.PrepareHMACKeys(key)
	for i := 0; i < 32; i++ {
		if ikey[i] != key[i]^0x36 {
			t.Fatalf("ikey[%d] wrong: got %02x want %02x", i, ikey[i], key[i]^0x36)
		}
		if okey[i] != key[i]^0x5c {
			t.Fatalf("okey[%d] wrong: got %02x want %02x", i, okey[i], key[i]^0x5c)
		}
	}
	// Bytes 32-63 should be pure ipad/opad.
	for i := 32; i < 64; i++ {
		if ikey[i] != 0x36 {
			t.Fatalf("ikey[%d] padding wrong: %02x", i, ikey[i])
		}
		if okey[i] != 0x5c {
			t.Fatalf("okey[%d] padding wrong: %02x", i, okey[i])
		}
	}
}