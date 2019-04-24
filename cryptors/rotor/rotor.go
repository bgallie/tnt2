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
	start   int
	size    int
	step    int
	current int
	rotor   []byte
}

func New(size, start, step int, rotor []byte) *Rotor {
	var r Rotor
	r.start, r.current = start, start
	r.size = size
	r.step = step
	r.rotor = rotor
	var i, j uint
	for i = 0; i < 256; i += 1 {
		j = uint(r.size) + i
		if bitops.GetBit(r.rotor, i) {
			bitops.SetBit(r.rotor, j)
		} else {
			bitops.ClrBit(r.rotor, j)
		}
	}
	return &r
}

func (r *Rotor) Update(size, start, step int, rotor []byte) {
	r.start, r.current = start, start
	r.size = size
	r.step = step
	r.rotor = rotor
	var i, j uint
	for i = 0; i < 256; i += 1 {
		j = uint(r.size) + i
		if bitops.GetBit(r.rotor, i) {
			bitops.SetBit(r.rotor, j)
		} else {
			bitops.ClrBit(r.rotor, j)
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

func (rotor *Rotor) Index() *big.Int {
	return nil
}

func (rotor *Rotor) Size() int {
	return rotor.size
}

func (rotor *Rotor) Rotor() []byte {
	return rotor.rotor
}

func (r *Rotor) Apply_F(blk *[cryptors.CypherBlockBytes]byte) *[cryptors.CypherBlockBytes]byte {
	var res [cryptors.CypherBlockBytes]byte
	ress := res[:]
	rotor := r.rotor
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
	output.WriteString(fmt.Sprintf("rotor.New(%d, %d, %d,[...]byte{\n",
		rotor.size, rotor.start, rotor.step))
	for i := 0; i < 1024; i += 16 {
		output.WriteString("\t")
		if i != 1008 {
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
