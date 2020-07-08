package bbs

import (
	"crypto/subtle"
	"github.com/mikelodder7/bls12-381"
)

// The type for creating commitments to messages that are hidden during issuance.
type Commitment struct {
	value *bls12381.PointG1
}

func (c Commitment) ToCompressed() []byte {
	return g1.ToCompressed(c.value)
}

func (c *Commitment) FromCompressed(data []byte) error {
	value, err := g1.FromCompressed(data)
	if err != nil {
		return err
	}
	c.value = value
	return nil
}

func (c Commitment) ToUncompressed() []byte {
	return g1.ToUncompressed(c.value)
}

func (c *Commitment) FromUncompressed(data []byte) error {
	value, err := g1.FromUncompressed(data)
	if err != nil {
		return err
	}
	c.value = value
	return nil
}

func (c Commitment) Equal(rhs Commitment) bool {
	l := g1.ToCompressed(c.value)
	r := g1.ToCompressed(rhs.value)
	return subtle.ConstantTimeCompare(l, r) == 0
}

func (c *Commitment) Hash(data []byte) {
	c.value = hashToG1(data)
}

