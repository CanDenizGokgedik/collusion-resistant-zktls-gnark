// sha2deco.go — SHA-256 continuation from a committed mid-state (DECO s_i trick).
//
// Lets the inner HMAC hash be CONTINUED from an intermediate chaining state s_i
// (committed/public) over only the disclosed suffix, instead of hashing the
// whole transcript. previousLen (bytes already absorbed into s_i) MUST be a
// multiple of 64. Mirrors jsnark's SHA256DECOGadget.
package circuit

import (
	"crypto/sha256"
	"encoding"
	"encoding/binary"

	"github.com/consensys/gnark/std/math/uints"
	permsha2 "github.com/consensys/gnark/std/permutation/sha2"
)

// SiStateNative returns the SHA-256 chaining state after absorbing prefix.
// len(prefix) MUST be a multiple of 64 (a clean block boundary).
func SiStateNative(prefix []byte) [8]uint32 {
	h := sha256.New()
	h.Write(prefix)
	m, _ := h.(encoding.BinaryMarshaler).MarshalBinary()
	// Format: magic(4) || h0..h7 (8×4 BE) || buf(64) || len(8). buf empty here.
	var st [8]uint32
	for i := 0; i < 8; i++ {
		st[i] = binary.BigEndian.Uint32(m[4+4*i : 8+4*i])
	}
	return st
}

// sha256ContinueInner continues SHA-256 from siState over suffix, appending the
// standard MD padding for a message of totalInnerBytes total length (= the full
// HMAC inner input: ikey(64) + plaintext). previousLen and suffix length are
// compile-time constants; siState and suffix are runtime values.
func sha256ContinueInner(uapi *uints.BinaryField[uints.U32], siState [8]uints.U32, suffix []uints.U8, previousLen, totalInnerBytes int) []uints.U8 {
	// Build suffix || 0x80 || 0x00... || be64(8*totalInnerBytes) so that
	// previousLen + len(stream) is a multiple of 64.
	stream := make([]uints.U8, 0, 64)
	stream = append(stream, suffix...)
	stream = append(stream, uints.NewU8(0x80))
	// pad zeros until (previousLen + len(stream) + 8) % 64 == 0
	for (previousLen+len(stream)+8)%64 != 0 {
		stream = append(stream, uints.NewU8(0x00))
	}
	var lenbuf [8]byte
	binary.BigEndian.PutUint64(lenbuf[:], uint64(8*totalInnerBytes))
	for _, bb := range lenbuf {
		stream = append(stream, uints.NewU8(bb))
	}
	// stream length must be a multiple of 64.
	state := siState
	var blk [64]uints.U8
	for i := 0; i < len(stream)/64; i++ {
		copy(blk[:], stream[i*64:(i+1)*64])
		state = permsha2.Permute(uapi, state, blk)
	}
	var out []uints.U8
	for i := range state {
		out = append(out, uapi.UnpackMSB(state[i])...)
	}
	return out
}
