package zcrypto

type SproutKey struct {
	Ask   [32]byte
	Apk   [32]byte
	SKenc [32]byte
	PKenc [32]byte
}

type SaplingKey struct{}

func KeygenSprout() {
}
