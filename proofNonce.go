package bbs

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type ProofNonce struct {
	value *big.Int
}

func (p ProofNonce) ToBytes() []byte {
	return p.ToBytes()
}

func (p *ProofNonce) FromBytes(data []byte) error {
	if len(data) > FrUncompressedSize {
		return fmt.Errorf("invalid length specified")
	}
	p.value.SetBytes(data)
	p.value.Mod(p.value, fr)
	return nil
}

func (p *ProofNonce) Hash(data []byte) {
	p.value = hashToFr(data)
}

func (p *ProofNonce) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	p.Hash(data)
}
