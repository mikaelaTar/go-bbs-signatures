// Implements the BBS+ signature as defined in <https://eprint.iacr.org/2016/663.pdf>
// in Section 4.3. Also included is ability to do zero-knowledge proofs as described
// in Section 4.4 and 4.5.
//
// The BBS+ signature is a pairing-based ECC signature
// that signs multiple messages instead of just one.
// The signature and messages can be used to create signature proofs of knowledge
// in zero-knowledge proofs in which the signature is not revealed and messages
// can be selectively disclosed––some are revealed and some remain hidden.
//
// The signature also supports separating the signer and signature holder
// where the holder creates commitments to messages which are hidden from the signer
// and a signature blinding factor which is retained. The holder sends the commitment
// to the signer who completes the signing process and sends the blinded signature back.
// The holder can then un-blind the signature finishing a 2-PC computation
//
// BBS+ signatures can be used for TPM DAA attestations or Verifiable Credentials.

package bbs

import (
	"golang.org/x/crypto/blake2b"
	"github.com/mikelodder7/bls12-381"
	"hash"
	"math/big"
)

const (
	// Number of bytes in scalar compressed form
	FrCompressedSize = 32
	// Number of bytes in scalar uncompressed form
	FrUncompressedSize = 48
	// Number of bytes in G1 X coordinate
	G1CompressedSize = 48
	// Number of bytes in G1 X and Y coordinates
	G1UncompressedSize = 96
	// Number of bytes in G2 X (a, b) coordinate
	G2CompressedSize = 96
	// Number of bytes in G2 X(a, b) and Y(a, b) coordinates
	G2UncompressedSize = 192
)

var (
	g1 = bls12381.NewG1()
	g2 = bls12381.NewG2()
	dstG1 = []byte("BLS12381G1_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0")
	dstG2 = []byte("BLS12381G2_XMD:BLAKE2B_SSWU_RO_BBS+_SIGNATURES:1_0_0")
	newBlake2b = func() hash.Hash {
		h, _ := blake2b.New512(nil)
		return h
	}
	fr, _ = new (big.Int).SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)
)

func hashToG1(data []byte) *bls12381.PointG1 {
	p1, _ := g1.HashToCurve(newBlake2b, data, dstG1)
	return p1
}

func hashToG2(data []byte) *bls12381.PointG2 {
	p2, _ := g2.HashToCurve(newBlake2b, data, dstG2)
	return p2
}

// Matches https://github.com/algorand/pairing-plus/blob/master/src/bls12_381/fr.rs#L26
func hashToFr(data []byte) *big.Int {
	h, _ := blake2b.New384(nil)
	_, _ = h.Write(data)
	okm := h.Sum(nil)
	elm := new (big.Int).SetBytes(okm[:24])
	elm.Mul(elm, f2192())
	elm.Mod(elm, fr)
	elm.Add(elm, new (big.Int).SetBytes(okm[24:]))
	elm.Mod(elm, fr)
	return elm
}

func f2192() *big.Int {
	limbs := []*big.Int {
		new (big.Int).SetUint64(0x1e179025ca247088),
		new (big.Int).SetUint64(0x2b34e63940ccbd72),
		new (big.Int).SetUint64(0xc5a30cb243fcc152),
		new (big.Int).SetUint64(0x59476ebc41b4528f),
	}
	result := new (big.Int)
	for _, m := range limbs {
		result.Lsh(result, 64)
		result.Or(result, m)
	}
	return result
}

