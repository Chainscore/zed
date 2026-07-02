package zcrypto

import (
	"fmt"
	"zed/utils"
)

func Expand() []byte {
	fmt.Println("Hello", MerkleDepthOrchard)
	return []byte{1, 2}
}

// -------------------------------------------------
// Sprout PRFs
// -------------------------------------------------

// PRFAddr derives Sprout address key material
func PRFAddr(x [32]byte, t byte) [32]byte {
	var block [64]byte

	block[0] = 0xc0 | (x[0] & 0x0f)
	copy(block[1:32], x[1:])
	block[32] = t

	return utils.SHA256Compress(block)
}

// PRFnfSprout derives Sprout Nullifier
func PRFnfSprout(ask [32]byte, rho [32]byte) [32]byte {
	var block [64]byte

	block[0] = 0xe0 | (ask[0] & 0x0f)
	copy(block[1:32], ask[1:])
	copy(block[32:], rho[:])

	return utils.SHA256Compress(block)
}

// PRFPk derives h_i for Sprout JoinSplit input i
func PRFPk(ask [32]byte, i uint8, hSig [32]byte) [32]byte {
	if i != 1 && i != 2 {
		panic("PRFpk index must be 1 or 2")
	}

	var block [64]byte

	prefix := (i - 1) << 6
	block[0] = prefix | (ask[0] & 0x0f)
	copy(block[1:32], ask[1:])
	copy(block[32:], hSig[:])

	return utils.SHA256Compress(block)
}

// PRFRho derives rho_i for Sprout output note i
func PRFRho(phi [32]byte, i uint8, hSig [32]byte) [32]byte {
	if i != 1 && i != 2 {
		panic("PRFrho index must be 1 or 2")
	}

	var block [64]byte

	prefix := (i-1)<<6 | 0x20
	block[0] = prefix | (phi[0] & 0x0f)
	copy(block[1:32], phi[1:])
	copy(block[32:], hSig[:])

	return utils.SHA256Compress(block)
}

// -------------------------------------------------
// Sapling PRFs
// -------------------------------------------------

// -------------------------------------------------
// Orchard PRFs
// -------------------------------------------------
