package zcrypto

import "zed/utils"

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

// PRFExpand derives Sapling/Orchard expanded key material
func PRFExpand(sk [32]byte, t []byte) [64]byte {
	data := make([]byte, 0, 32+len(t))
	data = append(data, sk[:]...)
	data = append(data, t...)

	return utils.BLAKE2b512([]byte("Zcash_ExpandSeed"), data)
}

// PRFockSapling derives Sapling outgoing cipher key
func PRFockSapling(ovk, cv, cmu, ephemeralKey [32]byte) [32]byte {
	var data [128]byte
	copy(data[0:32], ovk[:])
	copy(data[32:64], cv[:])
	copy(data[64:96], cmu[:])
	copy(data[96:128], ephemeralKey[:])

	return utils.BLAKE2b256([]byte("Zcash_Derive_ock"), data[:])
}

// PRFnfSapling derives Sapling note nullifier
func PRFnfSapling(nk, rho [32]byte) [32]byte {
	var data [64]byte
	copy(data[0:32], nk[:])
	copy(data[32:64], rho[:])

	return utils.BLAKE2s256([]byte("Zcash_nf"), data[:])
}

// -------------------------------------------------
// Orchard PRFs
// -------------------------------------------------

// PRFockOrchard derives Orchard outgoing cipher key
func PRFockOrchard(ovk, cv, cmx, ephemeralKey [32]byte) [32]byte {
	var data [128]byte

	copy(data[0:32], ovk[:])
	copy(data[32:64], cv[:])
	copy(data[64:96], cmx[:])
	copy(data[96:128], ephemeralKey[:])

	return utils.BLAKE2b256([]byte("Zcash_Orchardock"), data[:])
}

// PRFnfOrchard derives Orchard note nullifier
func PRFnfOrchard(nk, rho [32]byte) {
	panic("PRFnfOrchard not yet implemented")
}
