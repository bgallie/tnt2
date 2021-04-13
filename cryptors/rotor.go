// Package cryptors - define the rotor type and it's methods
package cryptors

import (
	"bytes"
	"fmt"
	"math/big"
)

// Rotor - the type of the TNT2 rotor
type Rotor struct {
	Size    int
	Start   int
	Step    int
	Current int
	Rotor   []byte
}

// New - creates a new Rotor with the given size, start, step and rotor data.
func NewRotor(size, start, step int, rotor []byte) *Rotor {
	var r Rotor
	r.Start, r.Current = start, start
	r.Size = size
	r.Step = step
	r.Rotor = rotor
	r.sliceRotor()
	return &r
}

// Update - updates the given Rotor with a new size, start and step.
func (r *Rotor) Update(size, start, step int) {
	r.Start, r.Current = start, start
	r.Size = size
	r.Step = step
	r.sliceRotor()
}

// sliceRotor - appends the first 256 bits of the rotor to the end of the rotor.
func (r *Rotor) sliceRotor() {
	var i, j uint
	j = uint(r.Size)
	for i = 0; i < 256; i++ {
		if GetBit(r.Rotor, i) {
			SetBit(r.Rotor, j)
		} else {
			ClrBit(r.Rotor, j)
		}
		j++
	}
}

// SetIndex - set the current rotor position based on the given index
func (r *Rotor) SetIndex(idx *big.Int) {
	// Special case if idx == 0
	if idx.Sign() == 0 {
		r.Current = r.Start
	} else {
		p := new(big.Int)
		q := new(big.Int)
		rem := new(big.Int)
		p = p.Mul(idx, new(big.Int).SetInt64(int64(r.Step)))
		p = p.Add(p, new(big.Int).SetInt64(int64(r.Start)))
		q, rem = q.DivMod(p, new(big.Int).SetInt64(int64(r.Size)), rem)
		r.Current = int(rem.Int64())
	}
}

// Index - Rotor does no track the index.
func (r *Rotor) Index() *big.Int {
	return nil
}

// ApplyF - encrypts the given block of data
func (r *Rotor) ApplyF(blk *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	var res [CypherBlockBytes]byte
	ress := res[:]
	rotor := r.Rotor
	idx := r.Current

	for cnt := 0; cnt < CypherBlockSize; cnt++ {
		if GetBit(rotor, uint(idx)) {
			SetBit(ress, uint(cnt))
		}

		idx++
	}

	r.Current = (r.Current + r.Step) % r.Size
	return AddBlock(blk, &res)
}

// ApplyG - decrypts the given block of data
func (r *Rotor) ApplyG(blk *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	var res [CypherBlockBytes]byte
	ress := res[:]
	rotor := r.Rotor[:]
	idx := r.Current

	for cnt := 0; cnt < CypherBlockSize; cnt++ {
		if GetBit(rotor, uint(idx)) {
			SetBit(ress, uint(cnt))
		}

		idx++
	}

	r.Current = (r.Current + r.Step) % r.Size
	return SubBlock(blk, &res)
}

// String - converts a Rotor to a string representation of the Rotor.
func (r *Rotor) String() string {
	var output bytes.Buffer
	rotorLen := len(r.Rotor)
	output.WriteString(fmt.Sprintf("rotor.New(%d, %d, %d, []byte{\n",
		r.Size, r.Start, r.Step))
	for i := 0; i < rotorLen; i += 16 {
		output.WriteString("\t")
		if i+16 < rotorLen {
			for _, k := range r.Rotor[i : i+16] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
		} else {
			l := len(r.Rotor[i:])
			for _, k := range r.Rotor[i : i+l-1] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
			output.WriteString(fmt.Sprintf("%d})", r.Rotor[i+l-1]))
		}
		output.WriteString("\n")
	}

	return output.String()
}