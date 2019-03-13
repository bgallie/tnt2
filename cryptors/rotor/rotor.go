// rotor
package rotor

import (
	"bytes"
	"fmt"
	"math/big"

	"mug.org/defiant/tnt2/cryptors"
	"mug.org/defiant/tnt2/cryptors/bitops"
)

type Rotor struct {
	start   int
	size    int
	step    int
	current int
	rotor   *[cryptors.RotorSizeBytes]byte
}

func New(start, size, step int, rotor *[cryptors.RotorSizeBytes]byte) *Rotor {
	var r Rotor
	r.start, r.current = start, start
	r.size = size
	r.step = step
	r.rotor = rotor
	var i, j uint
	for i = 0; i < 256; i += 1 {
		j = uint(r.size) + i
		if bitops.GetBit(r.rotor[0:], i) {
			bitops.SetBit(r.rotor[0:], j)
		} else {
			bitops.ClrBit(r.rotor[0:], j)
		}
	}
	return &r
}

func (r *Rotor) Update(start, size, step int, rotor *[cryptors.RotorSizeBytes]byte) {
	r.start, r.current = start, start
	r.size = size
	r.step = step
	r.rotor = rotor
	var i, j uint
	for i = 0; i < 256; i += 1 {
		j = uint(r.size) + i
		if bitops.GetBit(r.rotor[0:], i) {
			bitops.SetBit(r.rotor[0:], j)
		} else {
			bitops.ClrBit(r.rotor[0:], j)
		}
	}
}

func (rotor *Rotor) SetIndex(idx *big.Int) {
	// Special case if idx == 0
	if idx.Sign() == 0 {
		rotor.current = rotor.start
	} else {
		p := new(big.Int)
		q := new(big.Int)
		r := new(big.Int)
		p = p.Mul(idx, new(big.Int).SetInt64(int64(rotor.step)))
		p = p.Add(p, new(big.Int).SetInt64(int64(rotor.start)))
		q, r = q.DivMod(p, new(big.Int).SetInt64(int64(rotor.size)), r)
		rotor.current = int(r.Int64())
	}
}

func (rotor *Rotor) GetIndex() *big.Int {
	return nil
}

func (r *Rotor) Apply_F(blk *[cryptors.CypherBlockBytes]byte) *[cryptors.CypherBlockBytes]byte {
	var res [cryptors.CypherBlockBytes]byte
	ress := res[:]
	rotor := r.rotor[:]
	idx := r.current

	for cnt := 0; cnt < cryptors.CypherBlockSize; cnt++ {
		if bitops.GetBit(rotor, uint(idx)) {
			bitops.SetBit(ress, uint(cnt))
		}

		idx++
	}

	r.current = (r.current + r.step) % r.size
	return cryptors.AddBlock(blk, &res)
}

func (r *Rotor) Apply_G(blk *[cryptors.CypherBlockBytes]byte) *[cryptors.CypherBlockBytes]byte {
	var res [cryptors.CypherBlockBytes]byte
	ress := res[:]
	rotor := r.rotor[:]
	idx := r.current

	for cnt := 0; cnt < cryptors.CypherBlockSize; cnt++ {
		if bitops.GetBit(rotor, uint(idx)) {
			bitops.SetBit(ress, uint(cnt))
		}

		idx++
	}

	r.current = (r.current + r.step) % r.size
	return cryptors.SubBlock(blk, &res)
}

func (rotor *Rotor) String() string {
	var output bytes.Buffer
	output.WriteString(fmt.Sprintf("\tSetSize(%d)\n", rotor.size))
	output.WriteString(fmt.Sprintf("\tSetStart(%d)\n", rotor.start))
	output.WriteString(fmt.Sprintf("\tSetStep(%d)\n", rotor.step))
	output.WriteString(fmt.Sprintln("\tSetRotor([...]byte{"))
	for i := 0; i < 1056; i += 16 {
		output.WriteString("\t\t")
		if i != 1040 {
			for _, k := range rotor.rotor[i : i+16] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
		} else {
			for _, k := range rotor.rotor[i : i+15] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
			output.WriteString(fmt.Sprintf("%d})", rotor.rotor[i+15]))
		}
		output.WriteString("\n")
	}

	return output.String()
}
