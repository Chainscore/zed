package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, encoded string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func padSHA256Block(message []byte) [64]byte {
	var block [64]byte
	copy(block[:], message)
	block[len(message)] = 0x80
	bitLen := uint64(len(message) * 8)
	for i := 0; i < 8; i++ {
		block[63-i] = byte(bitLen >> (8 * i))
	}
	return block
}

func TestSHA256Vectors(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		exp  string
	}{
		{
			name: "CAVS Len 0",
			msg:  []byte{},
			exp:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "CAVS Len 8",
			msg:  mustHex(t, "d3"),
			exp:  "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
		},
		{
			name: "CAVS Len 24",
			msg:  mustHex(t, "b4190e"),
			exp:  "dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2",
		},
		{
			name: "CAVS Len 448",
			msg:  mustHex(t, "2d52447d1244d2ebc28650e7b05654bad35b3a68eedc7f8515306b496d75f3e73385dd1b002625024b81a02f2fd6dffb6e6d561cb7d0bd7a"),
			exp:  "cfb88d6faf2de3a69d36195acec2e255e2af2b7d933997f348e09f6ce5758360",
		},
		{
			name: "CAVS Len 512",
			msg:  mustHex(t, "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509"),
			exp:  "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa",
		},
		{
			name: "CAVS Len 1304",
			msg:  mustHex(t, "451101250ec6f26652249d59dc974b7361d571a8101cdfd36aba3b5854d3ae086b5fdd4597721b66e3c0dc5d8c606d9657d0e323283a5217d1f53f2f284f57b85c8a61ac8924711f895c5ed90ef17745ed2d728abd22a5f7a13479a462d71b56c19a74a40b655c58edfe0a188ad2cf46cbf30524f65d423c837dd1ff2bf462ac4198007345bb44dbb7b1c861298cdf61982a833afc728fae1eda2f87aa2c9480858bec"),
			exp:  "3c593aa539fdcdae516cdf2f15000f6634185c88f505b39775fb9ab137a10aa2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SHA256(tt.msg)
			exp := mustHex(t, tt.exp)
			if !bytes.Equal(got[:], exp) {
				t.Fatalf("SHA256(%x) = %x, exp %x", tt.msg, got, exp)
			}
		})
	}
}

func TestSHA512Vectors(t *testing.T) {
	tests := []struct {
		name string
		msg  []byte
		exp  string
	}{
		{
			name: "CAVS Len 0",
			msg:  []byte{},
			exp:  "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
		},
		{
			name: "CAVS Len 8",
			msg:  mustHex(t, "21"),
			exp:  "3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a",
		},
		{
			name: "CAVS Len 24",
			msg:  mustHex(t, "0a55db"),
			exp:  "7952585e5330cb247d72bae696fc8a6b0f7d0804577e347d99bc1b11e52f384985a428449382306a89261ae143c2f3fb613804ab20b42dc097e5bf4a96ef919b",
		},
		{
			name: "CAVS Len 896",
			msg:  mustHex(t, "518985977ee21d2bf622a20567124fcbf11c72df805365835ab3c041f4a9cd8a0ad63c9dee1018aa21a9fa3720f47dc48006f1aa3dba544950f87e627f369bc2793ede21223274492cceb77be7eea50e5a509059929a16d33a9f54796cde5770c74bd3ecc25318503f1a41976407aff2"),
			exp:  "c00926a374cde55b8fbd77f50da1363da19744d3f464e07ce31794c5a61b6f9c85689fa1cfe136553527fd876be91673c2cac2dd157b2defea360851b6d92cf4",
		},
		{
			name: "CAVS Len 1024",
			msg:  mustHex(t, "fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8"),
			exp:  "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc",
		},
		{
			name: "CAVS Len 1816",
			msg:  mustHex(t, "4f05600950664d5190a2ebc29c9edb89c20079a4d3e6bc3b27d75e34e2fa3d02768502bd69790078598d5fcf3d6779bfed1284bbe5ad72fb456015181d9587d6e864c940564eaafb4f2fead4346ea09b6877d9340f6b82eb1515880872213da3ad88feba9f4f13817a71d6f90a1a17c43a15c038d988b5b29edffe2d6a062813cedbe852cde302b3e33b696846d2a8e36bd680efcc6cd3f9e9a4c1ae8cac10cc5244d131677140399176ed46700019a004a163806f7fa467fc4e17b4617bbd7641aaff7ff56396ba8c08a8be100b33a20b5daf134a2aefa5e1c3496770dcf6baa4f7bb"),
			exp:  "a9db490c708cc72548d78635aa7da79bb253f945d710e5cb677a474efc7c65a2aab45bc7ca1113c8ce0f3c32e1399de9c459535e8816521ab714b2a6cd200525",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SHA512(tt.msg)
			exp := mustHex(t, tt.exp)
			if !bytes.Equal(got[:], exp) {
				t.Fatalf("SHA512(%x) = %x, exp %x", tt.msg, got, exp)
			}
		})
	}
}

func TestSHA256d(t *testing.T) {
	msg := []byte("abc")
	first := sha256.Sum256(msg)
	exp := sha256.Sum256(first[:])

	got := SHA256d(msg)
	if got != exp {
		t.Fatalf("SHA256d(%q) = %x, exp %x", msg, got, exp)
	}
}

func TestSHA256Compress(t *testing.T) {
	tests := [][]byte{
		{},
		[]byte("abc"),
		[]byte("Zcash Sprout SHA256Compress"),
		[]byte("Lorem Ipsum Dolor sit Amet"),
	}

	for _, message := range tests {
		got := SHA256Compress(padSHA256Block(message))
		exp := sha256.Sum256(message)
		if got != exp {
			t.Fatalf("SHA256Compress(padded %q) = %x, exp %x", message, got, exp)
		}
	}
}

func TestBLAKE2b256ZcashVectors(t *testing.T) {
	tests := []struct {
		name     string
		personal []byte
		msg      []byte
		exp      string
	}{
		{
			name:     "hashPrevouts empty",
			personal: []byte("ZcashPrevoutHash"),
			msg:      []byte{},
			exp:      "d53a633bbecf82fe9e9484d8a0e727c73bb9e68c96e72dec30144f6a84afa136",
		},
		{
			name:     "hashSequence empty",
			personal: []byte("ZcashSequencHash"),
			msg:      []byte{},
			exp:      "a5f25f01959361ee6eb56a7401210ee268226f6ce764a4f10b7f29e54db37272",
		},
		{
			name:     "hashOutputs Sapling v4 example",
			personal: []byte("ZcashOutputsHash"),
			msg:      mustHex(t, "e7719811893e0000095200ac6551ac636565b2835a0805750200025151"),
			exp:      "ab6f7f6c5ad6b56357b5f37e16981723db6c32411753e28c175e15589172194a",
		},
		{
			name:     "hashPrevouts non-empty",
			personal: []byte("ZcashPrevoutHash"),
			msg:      mustHex(t, "4201cfb1cd8dbf69b8250c18ef41294ca97993db546c1fe01f7e9c8e36d6a5e29d4e30a7378af1e40f64e125946f62c2fa7b2fecbcb64b6968912a6381ce3dc166d56a1d62f5a8d7"),
			exp:      "92b8af1f7e12cb8de105af154470a2ae0a11e64a24a514a562ff943ca0f35d7f",
		},
		{
			name:     "hashOutputs compact example",
			personal: []byte("ZcashOutputsHash"),
			msg:      mustHex(t, "23752997f4ff04000751510053536565"),
			exp:      "e03b74bc5187184406285bb9f03b4be510f5700c5859738434cf7b8f5bdb6772",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BLAKE2b256(tt.personal, tt.msg)
			exp := mustHex(t, tt.exp)
			if !bytes.Equal(got[:], exp) {
				t.Fatalf("BLAKE2b256(%q, %x) = %x, exp %x", tt.personal, tt.msg, got, exp)
			}
		})
	}
}

func TestBLAKE2b512(t *testing.T) {
	got := BLAKE2b512([]byte("Zcash_ExpandSeed"), []byte("abc"))
	exp := mustHex(t, "5f464a609fab1d4eafcc0074f7d3a48680796e835024a4da6ce9f68005992c8ee3d0e7c7c5a4578eab87ed1ba52f914f7877b26de9a7ee650f66352b2808d696")
	if !bytes.Equal(got[:], exp) {
		t.Fatalf("BLAKE2b512 = %x, exp %x", got, exp)
	}
}

func TestBLAKE2s256(t *testing.T) {
	got := BLAKE2s256([]byte("Zcashivk"), []byte("abc"))
	exp := mustHex(t, "1471557709249c69c97a0df88944e9a0b0f2b28df6b55bc48fd29379ca1a47d6")
	if !bytes.Equal(got[:], exp) {
		t.Fatalf("BLAKE2s256 = %x, exp %x", got, exp)
	}
}
