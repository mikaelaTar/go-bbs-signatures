package bbs

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
)

type SignatureMessage struct {
	value *big.Int
}

func (m SignatureMessage) Bytes() []byte {
	return m.value.Bytes()
}

func (m *SignatureMessage) SetBytes(data []byte) error {
	if len(data) > FrUncompressedSize {
		return fmt.Errorf("invalid length specified")
	}
	m.value.SetBytes(data)
	m.value.Mod(m.value, fr)
	return nil
}

func (m SignatureMessage) Equal(rhs SignatureMessage) bool {
	l := m.value.Bytes()
	r := rhs.value.Bytes()
	return subtle.ConstantTimeCompare(l, r) == 0
}

func (m *SignatureMessage) Hash(data []byte) {
	m.value = hashToFr(data)
}

func (m *SignatureMessage) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	m.Hash(data)
}