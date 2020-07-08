package bbs

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

type SignatureMessage struct {
	value *big.Int
}

func (m SignatureMessage) ToBytes() []byte {
	return m.ToBytes()
}

func (m *SignatureMessage) FromBytes(data []byte) error {
	if len(data) > FrUncompressedSize {
		return fmt.Errorf("invalid length specified")
	}
	m.value.SetBytes(data)
	m.value.Mod(m.value, fr)
	return nil
}

func (m *SignatureMessage) Hash(data []byte) {
	m.value = hashToFr(data)
}

func (m *SignatureMessage) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	m.Hash(data)
}