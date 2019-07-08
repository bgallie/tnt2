// rotor
package rotor

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/bgallie/tnt2/cryptors"
	"github.com/bgallie/tnt2/cryptors/bitops"
)

type Rotor struct {
	Start   int
	Size    int
	Step    int
	Current int
	Rotor   []byte
}

func New(size, start, step int, rotor []byte) *Rotor {
	var r Rotor
	r.Start, r.Current = start, start
	r.Size = size
	r.Step = step
	r.Rotor = rotor
	var i, j uint
	for i = 0; i < 256; i += 1 {
		j = uint(r.Size) + i
		if bitops.GetBit(r.Rotor, i) {
			bitops.SetBit(r.Rotor, j)
		} else {
			bitops.ClrBit(r.Rotor, j)
		}
	}
	return &r
}

func (r *Rotor) Update(size, start, step int, rotor []byte) {
	r.Start, r.Current = start, start
	r.Size = size
	r.Step = step
	r.Rotor = rotor
	var i, j uint
	for i = 0; i < 256; i += 1 {
		j = uint(r.Size) + i
		if bitops.GetBit(r.Rotor, i) {
			bitops.SetBit(r.Rotor, j)
		} else {
			bitops.ClrBit(r.Rotor, j)
		}
	}
}

func (rotor *Rotor) SetIndex(idx *big.Int) {
	// Special case if idx == 0
	if idx.Sign() == 0 {
		rotor.Current = rotor.Start
	} else {
		p := new(big.Int)
		q := new(big.Int)
		r := new(big.Int)
		p = p.Mul(idx, new(big.Int).SetInt64(int64(rotor.Step)))
		p = p.Add(p, new(big.Int).SetInt64(int64(rotor.Start)))
		q, r = q.DivMod(p, new(big.Int).SetInt64(int64(rotor.Size)), r)
		rotor.Current = int(r.Int64())
	}
}

func (rotor *Rotor) Index() *big.Int {
	return nil
}

// func (rotor *Rotor) Size() int {
// 	return rotor.Size
// }

// func (rotor *Rotor) Rotor() []byte {
// 	return rotor.Rotor
// }

func (r *Rotor) Apply_F(blk *[cryptors.CypherBlockBytes]byte) *[cryptors.CypherBlockBytes]byte {
	var res [cryptors.CypherBlockBytes]byte
	ress := res[:]
	rotor := r.Rotor
	idx := r.Current

	for cnt := 0; cnt < cryptors.CypherBlockSize; cnt++ {
		if bitops.GetBit(rotor, uint(idx)) {
			bitops.SetBit(ress, uint(cnt))
		}

		idx++
	}

	r.Current = (r.Current + r.Step) % r.Size
	return cryptors.AddBlock(blk, &res)
}

func (r *Rotor) Apply_G(blk *[cryptors.CypherBlockBytes]byte) *[cryptors.CypherBlockBytes]byte {
	var res [cryptors.CypherBlockBytes]byte
	ress := res[:]
	rotor := r.Rotor[:]
	idx := r.Current

	for cnt := 0; cnt < cryptors.CypherBlockSize; cnt++ {
		if bitops.GetBit(rotor, uint(idx)) {
			bitops.SetBit(ress, uint(cnt))
		}

		idx++
	}

	r.Current = (r.Current + r.Step) % r.Size
	return cryptors.SubBlock(blk, &res)
}

func (rotor *Rotor) String() string {
	var output bytes.Buffer
	rotorLen := len(rotor.Rotor)
	output.WriteString(fmt.Sprintf("rotor.New(%d, %d, %d,[]byte{\n",
		rotor.Size, rotor.Start, rotor.Step))
	for i := 0; i < rotorLen; i += 16 {
		output.WriteString("\t")
		if i != rotorLen-16 {
			for _, k := range rotor.Rotor[i : i+16] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
		} else {
			for _, k := range rotor.Rotor[i : i+15] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
			output.WriteString(fmt.Sprintf("%d})", rotor.Rotor[i+15]))
		}
		output.WriteString("\n")
	}

	return output.String()
}
