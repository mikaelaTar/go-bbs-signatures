package bbs

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type SignatureBlinding struct {
	value *big.Int
}

func (m SignatureBlinding) ToBytes() []byte {
	return m.ToBytes()
}

func (m *SignatureBlinding) FromBytes(data []byte) error {
	if len(data) > FrUncompressedSize {
		return fmt.Errorf("invalid length specified")
	}
	m.value.SetBytes(data)
	m.value.Mod(m.value, fr)
	return nil
}

func (m *SignatureBlinding) Hash(data []byte) {
	m.value = hashToFr(data)
}

func (m *SignatureBlinding) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	m.Hash(data)
}