package bbs

import (
	"crypto/subtle"
	"crypto/rand"
	"github.com/mikelodder7/bls12-381"
)

// The type for creating commitments to messages that are hidden during issuance.
type GeneratorG1 struct {
	value *bls12381.PointG1
}

func (c GeneratorG1) ToCompressed() []byte {
	return g1.ToCompressed(c.value)
}

func (c *GeneratorG1) FromCompressed(data []byte) error {
	value, err := g1.FromCompressed(data)
	if err != nil {
		return err
	}
	c.value = value
	return nil
}

func (c GeneratorG1) ToUncompressed() []byte {
	return g1.ToUncompressed(c.value)
}

func (c *GeneratorG1) FromUncompressed(data []byte) error {
	value, err := g1.FromUncompressed(data)
	if err != nil {
		return err
	}
	c.value = value
	return nil
}

func (c GeneratorG1) Equal(rhs GeneratorG1) bool {
	l := g1.ToCompressed(c.value)
	r := g1.ToCompressed(rhs.value)
	return subtle.ConstantTimeCompare(l, r) == 0
}

func (c *GeneratorG1) Hash(data []byte) {
	c.value = hashToG1(data)
}

func (c *GeneratorG1) Random() {
	data := make([]byte, G1CompressedSize)
	_, _ = rand.Read(data)
	c.Hash(data)
}
