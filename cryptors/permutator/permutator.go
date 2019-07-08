// permutator project main.go
package permutator

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	"github.com/bgallie/tnt2/cryptors"
	"github.com/bgallie/tnt2/cryptors/bitops"
)

// cycle describes a cycle for the permutator so it can adjust the permutation
// table used to permutate the block.  TNT currently uses 4 cycles to rearrange
type cycle struct {
	Start   int // The starting point (into randp) for this cycle.
	Length  int // The length of the cycle.
	Current int // The point in the cycle [0 .. cycle.length-1] to start
}

// Permutator is a type that defines a permutation cryptor in TNT.
type Permutator struct {
	CurrentState  int                                     // Current number of cycles for this permutator.
	MaximalStates int                                     // Maximum number of cycles this permutator can have before repeating.
	Cycles        [cryptors.NumberPermutationCycles]cycle // Cycles ordered by the current permutation.
	Randp         [cryptors.CypherBlockSize]byte          // Values 0 - 255 in a random order.
	bitPerm       [cryptors.CypherBlockSize]byte          // Permutation table created from randp.
}

// New creates a permutator and initializes it
func New(cycleSizes []int, randp *[cryptors.CypherBlockSize]byte) *Permutator {
	var p Permutator
	p.Randp = *randp

	for i := range cycleSizes {
		p.Cycles[i].Length = cycleSizes[i]
		p.Cycles[i].Current = 0
		// Adjust the start to reflect the lenght of the previous cycles
		if i == 0 { // no previous cycle so start at 0
			p.Cycles[i].Start = 0
		} else {
			p.Cycles[i].Start = p.Cycles[i-1].Start + p.Cycles[i-1].Length
		}
	}

	p.CurrentState = 0
	p.MaximalStates = p.Cycles[0].Length * p.Cycles[1].Length * p.Cycles[2].Length * p.Cycles[3].Length
	p.cycle()
	return &p
}

// Update the permutator with a new initialCycles and randp
func (p *Permutator) Update(cycleSizes []int, randp *[cryptors.CypherBlockSize]byte) {
	p.Randp = *randp

	for i := range cycleSizes {
		p.Cycles[i].Length = cycleSizes[i]
		p.Cycles[i].Current = 0
		// Adjust the start to reflect the lenght of the previous cycles
		if i == 0 { // no previous cycle so start at 0
			p.Cycles[i].Start = 0
		} else {
			p.Cycles[i].Start = p.Cycles[i-1].Start + p.Cycles[i-1].Length
		}
	}

	p.CurrentState = 0
	p.MaximalStates = p.Cycles[0].Length * p.Cycles[1].Length * p.Cycles[2].Length * p.Cycles[3].Length
	p.cycle()
}

// cycle bitPerm to it's next state.
func (p *Permutator) nextState() {
	for _, val := range p.Cycles {
		val.Current = (val.Current + 1) % val.Length
	}

	p.CurrentState = (p.CurrentState + 1) % p.MaximalStates
	p.cycle()
}

func (p *Permutator) cycle() {
	var wg sync.WaitGroup

	for _, val := range p.Cycles {
		wg.Add(1)

		go func(cycle []byte, sIdx int, length int) {
			defer wg.Done()

			for _, val := range cycle {
				p.bitPerm[val] = p.Randp[cycle[sIdx]]
				sIdx = (sIdx + 1) % length
			}
		}(p.Randp[val.Start:val.Start+val.Length], val.Current, val.Length)
	}

	wg.Wait()
}

// Set the Permutator to the state it would be in after encoding 'idx - 1' blocks
// of data.
func (p *Permutator) SetIndex(idx *big.Int) {
	q := new(big.Int)
	r := new(big.Int)
	q, r = q.DivMod(idx, big.NewInt(int64(p.MaximalStates)), r)
	p.CurrentState = int(r.Int64())

	for _, val := range p.Cycles {
		val.Current = p.CurrentState % val.Length
	}

	p.cycle()
}

func (p *Permutator) Index() *big.Int {
	return nil
}

func (p *Permutator) Apply_F(blk *[cryptors.CypherBlockBytes]byte) *[cryptors.CypherBlockBytes]byte {
	var res [cryptors.CypherBlockBytes]byte
	blks := blk[:]
	ress := res[:]

	for i, v := range p.bitPerm {
		if bitops.GetBit(blks, uint(i)) {
			bitops.SetBit(ress, uint(v))
		}
	}

	p.nextState()
	*blk = res
	return blk
}

func (p *Permutator) Apply_G(blk *[cryptors.CypherBlockBytes]byte) *[cryptors.CypherBlockBytes]byte {
	var res [cryptors.CypherBlockBytes]byte
	blks := blk[:]
	ress := res[:]

	for i, v := range p.bitPerm {
		if bitops.GetBit(blks, uint(v)) {
			bitops.SetBit(ress, uint(i))
		}
	}

	p.nextState()
	*blk = res
	return blk
}

func (p *Permutator) String() string {
	var output bytes.Buffer
	output.WriteString(fmt.Sprint("\tSetCycles([...]int8{"))

	for _, v := range p.Cycles[0 : cryptors.NumberPermutationCycles-1] {
		output.WriteString(fmt.Sprintf("%d, ", v.Length))
	}

	output.WriteString(fmt.Sprintf("%d})\n", p.Cycles[cryptors.NumberPermutationCycles-1].Length))
	output.WriteString(fmt.Sprint("\tSetCurrent([...]int8{"))

	for _, v := range p.Cycles[0 : cryptors.NumberPermutationCycles-1] {
		output.WriteString(fmt.Sprintf("%d, ", v.Current))
	}

	output.WriteString(fmt.Sprintf("%d})\n", p.Cycles[cryptors.NumberPermutationCycles-1].Current))
	output.WriteString(fmt.Sprintf(""))
	output.WriteString(fmt.Sprintf(""))
	output.WriteString(fmt.Sprint("\tSetRandp([...]byte{\n"))

	for i := 0; i < cryptors.CypherBlockSize; i += 16 {
		output.WriteString("\t\t")

		if i != (cryptors.CypherBlockSize - 16) {
			for _, k := range p.Randp[i : i+16] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
		} else {
			for _, k := range p.Randp[i : i+15] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
			output.WriteString(fmt.Sprintf("%d})", p.Randp[i+15]))
		}

		output.WriteString("\n")
	}

	output.WriteString(fmt.Sprint("\tSetBitPerm([...]byte{\n"))

	for i := 0; i < cryptors.CypherBlockSize; i += 16 {
		output.WriteString("\t\t")

		if i != (cryptors.CypherBlockSize - 16) {
			for _, k := range p.bitPerm[i : i+16] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
		} else {
			for _, k := range p.bitPerm[i : i+15] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
			output.WriteString(fmt.Sprintf("%d})", p.bitPerm[i+15]))
		}

		output.WriteString("\n")
	}

	return output.String()
}
