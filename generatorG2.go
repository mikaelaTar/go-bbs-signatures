package bbs

import (
	"crypto/subtle"
	"crypto/rand"
	"github.com/mikelodder7/bls12-381"
)

// The type for creating commitments to messages that are hidden during issuance.
type GeneratorG2 struct {
	value *bls12381.PointG2
}

func (c GeneratorG2) ToCompressed() []byte {
	return g2.ToCompressed(c.value)
}

func (c *GeneratorG2) FromCompressed(data []byte) error {
	value, err := g2.FromCompressed(data)
	if err != nil {
		return err
	}
	c.value = value
	return nil
}

func (c GeneratorG2) ToUncompressed() []byte {
	return g2.ToUncompressed(c.value)
}

func (c *GeneratorG2) FromUncompressed(data []byte) error {
	value, err := g2.FromUncompressed(data)
	if err != nil {
		return err
	}
	c.value = value
	return nil
}

func (c GeneratorG2) Equal(rhs GeneratorG2) bool {
	l := g2.ToCompressed(c.value)
	r := g2.ToCompressed(rhs.value)
	return subtle.ConstantTimeCompare(l, r) == 0
}

func (c *GeneratorG2) Hash(data []byte) {
	c.value = hashToG2(data)
}

func (c *GeneratorG2) Random() {
	data := make([]byte, G2CompressedSize)
	_, _ = rand.Read(data)
	c.Hash(data)
}
