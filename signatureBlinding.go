package bbs

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"
)

type SignatureBlinding struct {
	value *big.Int
}

func (m SignatureBlinding) Bytes() []byte {
	return m.value.Bytes()
}

func (m *SignatureBlinding) SetBytes(data []byte) error {
	if len(data) > FrUncompressedSize {
		return fmt.Errorf("invalid length specified")
	}
	m.value.SetBytes(data)
	m.value.Mod(m.value, fr)
	return nil
}

func (m SignatureBlinding) Equal(rhs SignatureBlinding) bool {
	l := m.value.Bytes()
	r := rhs.value.Bytes()
	return subtle.ConstantTimeCompare(l, r) == 0
}

func (m *SignatureBlinding) Hash(data []byte) {
	m.value = hashToFr(data)
}

func (m *SignatureBlinding) Random() {
	data := make([]byte, FrCompressedSize)
	_, _ = rand.Read(data)
	m.Hash(data)
}