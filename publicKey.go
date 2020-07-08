package bbs

import (
	"encoding/binary"
	"fmt"
)

type PublicKey struct {
	h0 *GeneratorG1
	h []*GeneratorG1
	w *GeneratorG2
}

func (p PublicKey) MessageCount() int {
	return len(p.h)
}

func (p PublicKey) Bytes(compressed bool) []byte {
	hLen := len(p.h)
	hBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(hBytes, uint32(hLen))

	output := []byte{}
	if compressed {
		output = append(output, p.w.ToCompressed()...)
		output = append(output, p.h0.ToCompressed()...)
		output = append(hBytes)
		for _, b := range p.h {
			output = append(output, b.ToCompressed()...)
		}
	} else {
		output = append(output, p.w.ToUncompressed()...)
		output = append(output, p.h0.ToUncompressed()...)
		output = append(hBytes)
		for _, b := range p.h {
			output = append(output, b.ToUncompressed()...)
		}
	}
	return output
}

func (p *PublicKey) SetBytes(data []byte, compressed bool) error {
	if (len(data) - 4) % G1CompressedSize != 0 {
		return fmt.Errorf("invalid bytes for public key")
	}
	w := new(GeneratorG2)
	h0 := new (GeneratorG1)
	var h []*GeneratorG1
	if compressed {
		err := w.FromCompressed(data[:G2CompressedSize])
		if err != nil {
			return err
		}
		offset := G2CompressedSize
		end := G2CompressedSize + G1CompressedSize
		err = h0.FromCompressed(data[offset:end])
		if err != nil {
			return err
		}
		offset = end
		end += 4
		count := int(binary.BigEndian.Uint32(data[offset:end]))
		h = make([]*GeneratorG1, count)
		for i := 0; i < count; i++ {
			offset = end
			end += G1CompressedSize
			newH := new (GeneratorG1)
			err = newH.FromCompressed(data[offset:end])
			if err != nil {
				return err
			}
			h[i] = newH
		}
	} else {
		err := w.FromUncompressed(data[:G2UncompressedSize])
		if err != nil {
			return err
		}
		offset := G2UncompressedSize
		end := G2UncompressedSize + G1UncompressedSize
		err = h0.FromUncompressed(data[offset:end])
		if err != nil {
			return err
		}
		offset = end
		end += 4
		count := int(binary.BigEndian.Uint32(data[offset:end]))
		h = make([]*GeneratorG1, count)
		for i := 0; i < count; i++ {
			offset = end
			end += G1UncompressedSize
			newH := new (GeneratorG1)
			err = newH.FromUncompressed(data[offset:end])
			if err != nil {
				return err
			}
			h[i] = newH
		}
	}

	p.h0 = h0
	p.h = h
	p.w = w
	return nil
}
