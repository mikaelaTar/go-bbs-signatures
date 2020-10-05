package bbs

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"

	bls12381 "github.com/mikelodder7/bls12-381"
)

type ProofChallenge struct {
	value *big.Int
}

func (p ProofChallenge) ToBytes() []byte {
	return p.ToBytes()
}

func (p *ProofChallenge) FromBytes(data []byte) error {
	if len(data) > FrUncompressedSize {
		return fmt.Errorf("invalid length specified")
	}
	p.value.SetBytes(data)
	p.value.Mod(p.value, fr)
	return nil
}

func (p ProofChallenge) Equal(rhs ProofChallenge) bool {
	lG1 := &bls12381.G1{}
	lG1Bytes := p.value.Bytes()
	lG1Point, err := lG1.FromBytes(lG1Bytes)
	if err != nil {
		return false
	}
	l := g1.ToCompressed(lG1Point)

	rG1 := &bls12381.G1{}
	rG1Bytes := rhs.value.Bytes()
	rG1Point, err := rG1.FromBytes(rG1Bytes)
	if err != nil {
		return false
	}
	r := g1.ToCompressed(rG1Point)

	return subtle.ConstantTimeCompare(l, r) == 0
}

func (p *ProofChallenge) Hash(data []byte) {
	p.value = hashToFr(data)
}

func (p *ProofChallenge) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	p.Hash(data)
}
