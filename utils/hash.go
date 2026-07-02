package utils

import (
	"crypto/sha256"
	"crypto/sha512"

	"github.com/gtank/blake2/blake2b"
	"github.com/gtank/blake2/blake2s"
)

// SHA256 Standard SHA-256 digest of arbitrary bytes data, returns 32 byte digest
// Used for sprout-era constructions
func SHA256(data []byte) [32]byte {
	return sha256.Sum256(data)
}

// SHA256d Double hashed SHA256 digest, returns 32 byte digest
// Used specifically for hashing block
func SHA256d(data []byte) [32]byte {
	firstHash := sha256.Sum256(data)
	return sha256.Sum256(firstHash[:])
}

// SHA512 Standard SHA-512 digest of arbitrary bytes data
// returns 64 byte digest
func SHA512(data []byte) [64]byte {
	return sha512.Sum512(data)
}

// SHA256Compress Raw SHA-256 compression fn for 64 byte data, returns 32 byte digest
// Used in PRFs
func SHA256Compress(data [64]byte) [32]byte {
	return compress(data)
}

// BLAKE2b256 returns personalized BLAKE2b-256 digest of data.
// Used in KDFs, Cipher keys, hSig
func BLAKE2b256(personal []byte, data []byte) [32]byte {
	if personal != nil && len(personal) != 16 {
		panic("BLAKE2b personalization must be 16 bytes")
	}

	digest, err := blake2b.NewDigest(nil, nil, personal[:], 32)
	if err != nil {
		panic(err)
	}

	_, _ = digest.Write(data)
	sum := digest.Sum(nil)

	var res [32]byte
	copy(res[:], sum)
	return res
}

// BLAKE2b512 returns personalized BLAKE2b-512 digest of data.
// Used in Key Expansion (Sapling), RedJubJub Signs, Orchard hash to field
func BLAKE2b512(personal []byte, data []byte) [64]byte {
	if personal != nil && len(personal) != 16 {
		panic("BLAKE2b personalization must be 16 bytes")
	}

	digest, err := blake2b.NewDigest(nil, nil, personal[:], 64)
	if err != nil {
		panic(err)
	}

	_, _ = digest.Write(data)
	sum := digest.Sum(nil)

	var res [64]byte
	copy(res[:], sum)
	return res
}

// BLAKE2s256 returns personalized BLAKE2s-256 digest of data.
// Used in Sapling ivk, nullifiers, JubJub group hashing
func BLAKE2s256(personal []byte, data []byte) [32]byte {
	if personal != nil && len(personal) != 8 {
		panic("BLAKE2s personalization must be 8 bytes")
	}

	digest, err := blake2s.NewDigest(nil, nil, personal[:], 32)
	if err != nil {
		panic(err)
	}

	_, _ = digest.Write(data)
	sum := digest.Sum(nil)

	var res [32]byte
	copy(res[:], sum)
	return res
}
