// Package cryptors - bit manipulation routines
package cryptors

// SetBit - set bit in a byte array
func SetBit(ary []byte, bit uint) []byte {
	ary[bit>>3] |= (1 << (bit & 7))
	return ary
}

// ClrBit - clear bit in a byte array
func ClrBit(ary []byte, bit uint) []byte {
	ary[bit>>3] &= ^(1 << (bit & 7))
	return ary
}

// GetBit - return the value of a bit in a byte array
func GetBit(ary []byte, bit uint) bool {
	return (ary[bit>>3]&(1<<(bit&7)) != 0)
}