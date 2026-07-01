package utils

import (
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
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
	// TODO: Complete this later
	var out [32]byte
	return out
}

// BLAKE2b256 returns BLAKE2b-256 digest of data.
func BLAKE2b256(data []byte) [32]byte {
	return blake2b.Sum256(data)
}

// BLAKE2b512 returns BLAKE2b-512 digest of data.
func BLAKE2b512(data []byte) [64]byte {
	return blake2b.Sum512(data)
}

// BLAKE2b returns BLAKE2b digest of size bytes.
func BLAKE2b(size int, data []byte) ([]byte, error) {
	h, err := blake2b.New(size, nil)
	if err != nil {
		return nil, err
	}

	_, _ = h.Write(data)
	return h.Sum(nil), nil
}

// BLAKE2s256 returns BLAKE2s-256 digest of data.
func BLAKE2s256(data []byte) [32]byte {
	return blake2s.Sum256(data)
}

// BLAKE2s returns BLAKE2s digest of size bytes.
func BLAKE2s(size int, data []byte) ([]byte, error) {
	// TODO: Complete this later
	return []byte{}, nil
}
