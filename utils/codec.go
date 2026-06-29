package utils

import (
	"errors"
	"slices"

	"github.com/holiman/uint256"
)

// I2LEOSP Integer to Little-Endian Octet String
// converts uint (0 - 2**l) to bytes (little endian) of size ceil(l/8)
func I2LEOSP(val uint, l uint) ([]byte, error) {
	lCeiled := (l + 8 - 1) / 8
	r := make([]byte, lCeiled)
	for i := range lCeiled {
		r[i] = byte(val)
		val = val >> 8
	}
	return r, nil
}

func I2LEOSPu256(val uint256.Int, l uint) ([]byte, error) {
	// BE encoded bytes
	r := val.Bytes32()
	// reverse it
	slices.Reverse(r[(l+8-1)/8:])
	return r[:8], nil
}

// L2LEBSP - Integer to Little-Endian Bit String
// maximum performance without heap allocations, Bitwise Masking is the best option.
// It isolates each bit using the bitwise AND (&) and shifts the integer right (>>), repeat
func I2LEBSP(val uint, l uint) ([]bool, error) {
	r := make([]bool, l)
	for i := range l {
		r[i] = (val & 1) == 1
		val = val >> 1
	}

	return r, nil
}

func I2LEBSPu256(val uint256.Int, l uint) ([]bool, error) {
	if l < uint(val.BitLen()) {
		// throw error
		return []bool{}, errors.New("insufficient l")
	}
	r := make([]bool, l)

	one := uint256.NewInt(1)
	v := val.Clone()
	bsh := new(uint256.Int)

	for i := range l {
		bsh.And(v, one)
		r[i] = bsh.Eq(one)
		v.Rsh(v, 1)
	}
	return r, nil
}
