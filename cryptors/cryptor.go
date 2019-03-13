// cyptor
package cryptors

import (
	"math/big"
)

const (
	BitsPerByte             = 8
	CypherBlockSize         = 256
	CypherBlockBytes        = CypherBlockSize / BitsPerByte
	MaximumRotorSize        = 8192
	NumberPermutationCycles = 4
	RotorSizeBytes          = (MaximumRotorSize + CypherBlockSize) / BitsPerByte
)

var (
	// rotoSizes is an array of possible rotor sizes.  It consists of prime
	// numbers less than 8192.  The rotor sizes selected from this list will
	// maximizes the number of unique states the rotors can take.
	RotorSizes = []int{
		7993, 8009, 8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089,
		8093, 8101, 8111, 8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191}

	// cycleSizes is an array of cycles to use when cycling the permutation table.
	// There are 4 cycles in each entry and they meet the following criteria:
	//      1.  The sum of the cycles is equal to 256.
	//      2.  The cycles are relatively prime to each other. (This maximizes
	//          the number of unique states the permutation can be in for the
	//          given cycles).
	CycleSizes = [...][4]int{
		{61, 63, 65, 67}, // Number of unique states: 16,736,265 [401,670,360]
		{53, 65, 67, 71}, // Number of unique states: 16,387,685 [393,304,440]
		{55, 57, 71, 73}, // Number of unique states: 16,248,705 [389,968,920]
		{53, 61, 63, 79}, // Number of unique states: 16,090,641 [386,175,384]
		{43, 57, 73, 83}, // Number of unique states: 14,850,609 [356,414,616]
		{49, 51, 73, 83}, // Number of unique states: 15,141,441 [363,394,584]
		{47, 53, 73, 83}, // Number of unique states: 15,092,969 [362,231,256]
		{47, 53, 71, 85}} // Number of unique states: 15,033,185 [360,796,440]

	// Define big ints zero and one.
	BigZero = big.NewInt(0)
	BigOne  = big.NewInt(1)
)

type CypherBlock struct {
	Length      int8
	CypherBlock [CypherBlockBytes]byte
}

type Counter struct {
	index *big.Int
}

type Crypter interface {
	SetIndex(*big.Int)
	GetIndex() *big.Int
	Apply_F(*[CypherBlockBytes]byte) *[CypherBlockBytes]byte
	Apply_G(*[CypherBlockBytes]byte) *[CypherBlockBytes]byte
}

func (cntr *Counter) SetIndex(index *big.Int) {
	cntr.index = index
}

func (cntr *Counter) GetIndex() *big.Int {
	return cntr.index
}

func (cntr *Counter) Apply_F(blk *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	cntr.index.Add(cntr.index, BigOne)
	return blk
}

func (cntr *Counter) Apply_G(blk *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	cntr.index.Add(cntr.index, BigOne)
	return blk
}

func Encrypt(ecm Crypter, blk *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	return ecm.Apply_F(blk)
}

func Decrypt(ecm Crypter, blk *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	return ecm.Apply_G(blk)
}

func SetIndex(ecm Crypter, idx *big.Int) {
	ecm.SetIndex(idx)
}

func AddBlock(blk, key *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	var p int

	for i, v := range *blk {
		p += int(v) + int(key[i])
		blk[i] = byte(p & 0xFF)
		p >>= BitsPerByte
	}

	return blk
}

func SubBlock(blk, key *[CypherBlockBytes]byte) *[CypherBlockBytes]byte {
	var p int

	for idx, val := range *blk {
		p = p + int(val) - int(key[idx])
		blk[idx] = byte(p & 0xFF)
		p = p >> BitsPerByte
	}

	return blk
}

func EncryptMachine(ecm Crypter, left chan CypherBlock) chan CypherBlock {
	right := make(chan CypherBlock)
	go func(ecm Crypter, left chan CypherBlock, right chan CypherBlock) {
		for {
			inp := <-left
			if inp.Length <= 0 {
				right <- inp
				break
			}

			ecm.Apply_F(&inp.CypherBlock)
			right <- inp
		}
	}(ecm, left, right)

	return right
}

func DecryptMachine(ecm Crypter, left chan CypherBlock) chan CypherBlock {
	right := make(chan CypherBlock)
	go func(ecm Crypter, left chan CypherBlock, right chan CypherBlock) {
		for {
			inp := <-left
			if inp.Length <= 0 {
				right <- inp
				break
			}

			ecm.Apply_G(&inp.CypherBlock)
			right <- inp
		}
	}(ecm, left, right)

	return right
}

func CreateEncryptMachine(index *big.Int, ecms ...Crypter) (left chan CypherBlock, right chan CypherBlock) {
	if ecms != nil {
		idx := 0
		left = make(chan CypherBlock)
		ecms[idx].SetIndex(index)
		right = EncryptMachine(ecms[idx], left)

		for idx++; idx < len(ecms); idx++ {
			ecms[idx].SetIndex(index)
			right = EncryptMachine(ecms[idx], right)
		}

	} else {
		panic("you must give at least one encryption device!")
	}

	return
}

func CreateDecryptMachine(index *big.Int, ecms ...Crypter) (left chan CypherBlock, right chan CypherBlock) {
	if ecms != nil {
		idx := len(ecms) - 1
		left = make(chan CypherBlock)
		ecms[idx].SetIndex(index)
		right = DecryptMachine(ecms[idx], left)

		for idx--; idx >= 0; idx-- {
			ecms[idx].SetIndex(index)
			right = DecryptMachine(ecms[idx], right)
		}
	} else {
		panic("you must give at least one decryption device!")
	}

	return
}
