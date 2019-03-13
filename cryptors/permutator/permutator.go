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

// Permutator is a type that defines a permutation table in TNT.
type Permutator struct {
	currentState int                                   // The number of states bitPerm has taken.
	cycles       [cryptors.NumberPermutationCycles]int // Cycles ordered by the current permutation.
	current      [cryptors.NumberPermutationCycles]int // Current start point of the cycle.
	randp        [cryptors.CypherBlockSize]byte        // Values 0 - 255 in a random order.
	bitPerm      [cryptors.CypherBlockSize]byte        // Permutation table created from randp.
}

var i256 [cryptors.CypherBlockSize]byte

// New creates a permutator and initializes it
func New(cycleSizesIndex int, randp *[cryptors.CypherBlockSize]byte) *Permutator {
	var p Permutator
	p.randp = *randp

	for i := range cryptors.CycleSizes[cycleSizesIndex] {
		p.cycles[i] = cryptors.CycleSizes[cycleSizesIndex][i]
	}

	p.currentState = 0
	p.cycle()
	return &p
}

// Update the permutator with a new initialCycles and randp
func (p *Permutator) Update(cycleSizesIndex int, randp *[cryptors.CypherBlockSize]byte) {
	p.randp = *randp

	for i := range p.current {
		p.current[i] = 0
	}

	for i := range cryptors.CycleSizes[cycleSizesIndex] {
		p.cycles[i] = cryptors.CycleSizes[cycleSizesIndex][i]
	}

	p.currentState = 0
	p.cycle()
}

// cycle bitPerm to it's next state.
func (p *Permutator) nextState() {
	for i, val := range p.cycles {
		p.current[i] = (p.current[i] + 1) % val
	}

	p.currentState++
	p.cycle()
}

func (p *Permutator) cycle() {
	var wg sync.WaitGroup
	var cIdx int = 0

	for i, val := range p.cycles {
		wg.Add(1)

		go func(cycle []byte, sIdx int) {
			defer wg.Done()

			for _, val := range cycle {
				p.bitPerm[val] = p.randp[cycle[sIdx]]
				sIdx = (sIdx + 1) % len(cycle)
			}
		}(p.randp[cIdx:(cIdx+val)], p.current[i])

		cIdx = cIdx + val
	}

	wg.Wait()
}

// Set the Permutator to the state it would be in after encoding 'idx - 1' blocks
// of data.
func (p *Permutator) SetIndex(idx *big.Int) {
	maximalStates := int64(p.cycles[0] * p.cycles[1] * p.cycles[2] * p.cycles[3])
	q := new(big.Int)
	r := new(big.Int)
	q, r = q.DivMod(idx, big.NewInt(int64(maximalStates)), r)
	p.currentState = int(r.Int64())

	for i := range p.cycles {
		p.current[i] = p.currentState % p.cycles[i]
	}

	p.cycle()
}

func (p *Permutator) GetIndex() *big.Int {
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

	for idx, v := range p.bitPerm {
		if bitops.GetBit(blks, uint(v)) {
			bitops.SetBit(ress, uint(idx))
		}
	}

	p.nextState()
	*blk = res
	return blk
}

func (p *Permutator) String() string {
	var output bytes.Buffer
	output.WriteString(fmt.Sprintf("\tSetCurrentState(%d)\n", p.currentState))
	output.WriteString(fmt.Sprint("\tSetCycles([...]int8{"))

	for _, v := range p.cycles[0 : cryptors.NumberPermutationCycles-1] {
		output.WriteString(fmt.Sprintf("%d, ", v))
	}

	output.WriteString(fmt.Sprintf("%d})\n", p.cycles[cryptors.NumberPermutationCycles-1]))
	output.WriteString(fmt.Sprint("\tSetCurrent([...]int8{"))

	for _, v := range p.current[0 : cryptors.NumberPermutationCycles-1] {
		output.WriteString(fmt.Sprintf("%d, ", v))
	}

	output.WriteString(fmt.Sprintf("%d})\n", p.current[cryptors.NumberPermutationCycles-1]))
	output.WriteString(fmt.Sprintf(""))
	output.WriteString(fmt.Sprintf(""))
	output.WriteString(fmt.Sprint("\tSetRandp([...]byte{\n"))

	for i := 0; i < cryptors.CypherBlockSize; i += 16 {
		output.WriteString("\t\t")

		if i != (cryptors.CypherBlockSize - 16) {
			for _, k := range p.randp[i : i+16] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
		} else {
			for _, k := range p.randp[i : i+15] {
				output.WriteString(fmt.Sprintf("%d, ", k))
			}
			output.WriteString(fmt.Sprintf("%d})", p.randp[i+15]))
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
