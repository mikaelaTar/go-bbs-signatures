package bbs

import (
	"crypto/rand"
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

func (p *ProofChallenge) Hash(data []byte) {
	p.value = hashToFr(data)
}

func (p *ProofChallenge) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	p.Hash(data)
}
