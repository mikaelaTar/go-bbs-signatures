package bbs

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
)

type ProofNonce struct {
	value *big.Int
}

func (p ProofNonce) Bytes() []byte {
	return p.value.Bytes()
}

func (p *ProofNonce) SetBytes(data []byte) error {
	if len(data) > FrUncompressedSize {
		return fmt.Errorf("invalid length specified")
	}
	p.value.SetBytes(data)
	p.value.Mod(p.value, fr)
	return nil
}

func (p ProofNonce) Equal(rhs ProofNonce) bool {
	l := p.value.Bytes()
	r := rhs.value.Bytes()
	return subtle.ConstantTimeCompare(l, r) == 0
}

func (p *ProofNonce) Hash(data []byte) {
	p.value = hashToFr(data)
}

func (p *ProofNonce) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	p.Hash(data)
}
