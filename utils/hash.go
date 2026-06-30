package utils

import (
	"crypto/sha256"
	"crypto/sha512"
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
	// Complete this later
	var out [32]byte
	return out
}
