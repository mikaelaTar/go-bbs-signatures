package bbs

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
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
	l := g1.ToCompressed(p.value)
	r := g1.ToCompressed(rhs.value)
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
