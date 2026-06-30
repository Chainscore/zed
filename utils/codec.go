package utils

import (
	"errors"
	"slices"

	"github.com/holiman/uint256"
)

// I2LEOSP Integer to Little-Endian Octet Sequence Protocol
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

// I2LEOSPu256 converts a uint256 integer to little-endian bytes of size ceil(l/8).
func I2LEOSPu256(val uint256.Int, l uint) ([]byte, error) {
	// BE encoded bytes
	dest := make([]byte, (l+8-1)/8)
	val.WriteToSlice(dest)
	// reverse it
	slices.Reverse(dest)
	return dest, nil
}

// I2LEBSP - Integer to Little-Endian Bit Sequence Protocol
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

// I2LEBSPu256 converts a uint256 integer to a little-endian bit sequence of length l.
func I2LEBSPu256(val uint256.Int, l uint) ([]bool, error) {
	r := make([]bool, l)
	// we've got chunks of u64's in LE order
	// simply convert them to bits as it is
	for i := range 4 {
		limit := min(l, 64)
		res, _ := I2LEBSP(uint(val[i]), limit)
		for j := range res {
			r[i*64+j] = res[j]
		}
		if l < 64 {
			break
		}
		l -= limit
	}
	return r, nil
}

// I2BEBSP - Integer to Big-Endian Bit Sequence Protocol
func I2BEBSP(val uint, l uint) ([]bool, error) {
	r := make([]bool, l)
	// ulta of I2LE
	for i := uint(1); i <= l; i++ {
		r[l-i] = (val & 1) == 1
		val = val >> 1
	}
	return r, nil
}

// I2BEBSPu256 converts a uint256 integer to a big-endian bit sequence of length l.
func I2BEBSPu256(val uint256.Int, l uint) ([]bool, error) {
	r := make([]bool, l)
	for i := range val {
		if uint(len(r)) > l {
			continue
		}
		limit := min(l, 64)
		res, _ := I2BEBSP(uint(val[i]), limit)
		for j := range res {
			r[int(l-limit)+j] = res[j]
		}
		l -= limit
	}
	return r, nil
}

// LEBS2IP - Little-Endian Bit Sequence to Integer Protocol
func LEBS2IP(bits []bool) (uint, error) {
	res := uint(0)
	for i := len(bits) - 1; i >= 0; i-- {
		var b uint
		if bits[i] {
			b = 1
		}
		res = (res << 1) | b
	}
	return res, nil
}

// LEBS2IPu256 converts a little-endian bit sequence to a uint256 integer.
func LEBS2IPu256(bits []bool) (*uint256.Int, error) {
	res := uint256.NewInt(0)

	for i := range 4 {
		limit := min((i+1)*64, len(bits))
		tmp, _ := LEBS2IP(bits[i*64 : limit])
		res[i] = uint64(tmp)
		if (i+1)*64 >= len(bits) {
			break
		}
	}

	return res, nil
}

// LEOS2IP converts a little-endian octet sequence to a native uint.
func LEOS2IP(data []byte, l uint) (uint, error) {
	if l%8 != 0 || len(data) > 8 {
		return 0, errors.ErrUnsupported
	}
	if uint(len(data)) != l/8 {
		return 0, errors.New("invalid length")
	}

	val := uint(0)
	for i := range l / 8 {
		val += uint(data[i]) << (8 * i)
	}
	return val, nil
}

// LEOS2IPu256 converts a little-endian octet sequence to a uint256 integer.
func LEOS2IPu256(data []byte, l uint) (uint256.Int, error) {
	if l%8 != 0 || len(data) > 32 {
		return uint256.Int{0}, errors.ErrUnsupported
	}
	if uint(len(data)) != l/8 {
		return uint256.Int{0}, errors.New("invalid length")
	}

	reversed := slices.Clone(data)
	slices.Reverse(reversed)
	return *new(uint256.Int).SetBytes(reversed), nil
}

// BEOS2IP converts a big-endian octet sequence to a native uint.
func BEOS2IP(data []byte, l uint) (uint, error) {
	if l%8 != 0 || len(data) > 8 {
		return 0, errors.ErrUnsupported
	}

	val := uint(0)
	for i := range uint(l / 8) {
		val = (val << 8) + uint(data[i])
	}
	return val, nil
}

// BEOS2IPu256 converts a big-endian octet sequence to a uint256 integer.
func BEOS2IPu256(data []byte, l uint) (uint256.Int, error) {
	if l%8 != 0 || len(data) > 32 {
		return uint256.Int{0}, errors.ErrUnsupported
	}

	return *new(uint256.Int).SetBytes(data[:l/8]), nil
}

// LEBS2OSP converts a little-endian bit sequence to octets, padding the final byte with zero bits.
func LEBS2OSP(l uint, bits []bool) ([]byte,
	error,
) {
	if uint(len(bits)) != l {
		return nil, errors.New("invalid length")
	}

	out := make([]byte, (l+7)/8)

	for i, bit := range bits {
		if bit {
			out[i/8] |= 1 << uint(i%8)
		}
	}

	return out, nil
}

// LEOS2BSP expands little-endian octets into a bit sequence of length l.
func LEOS2BSP(data []byte, l uint) ([]bool,
	error,
) {
	if l%8 != 0 {
		return nil, errors.ErrUnsupported
	}
	if uint(len(data)) != (l+7)/8 {
		return nil, errors.New("invalid length")
	}

	out := make([]bool, l)

	for i, b := range data {
		for j := range 8 {
			out[i*8+j] = (b & (1 << uint(j))) != 0
		}
	}

	return out, nil
}
