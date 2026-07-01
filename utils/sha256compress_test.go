package utils

import (
	"crypto/sha256"
	"testing"
)

func padBlock(message []byte) [64]byte {
	var block [64]byte
	copy(block[:], message)
	block[len(message)] = 0x80
	bitLen := uint64(len(message) * 8)
	for i := 0; i < 8; i++ {
		block[63-i] = byte(bitLen >> (8 * i))
	}
	return block
}

func TestSHA256Compress(t *testing.T) {
	tests := [][]byte{
		{},
		[]byte("abc"),
		[]byte("Zcash Sprout SHA256Compress"),
		[]byte("Lorem Ipsum Dolor sit Amet"),
	}

	for _, message := range tests {
		got := SHA256Compress(padBlock(message))
		exp := sha256.Sum256(message)
		if got != exp {
			t.Fatalf("SHA256Compress(padded %q) = %x, want %x", message, got, exp)
		}
	}
}
