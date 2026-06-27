package zcrypto

const (
	MerkleDepthSprout  int8  = 29
	MerkleDepthSapling int8  = 32
	MerkleDepthOrchard int8  = 32
	MerkleLenSprout    int   = 256
	MerkleLenSapling   int   = 255
	MerkleLenOrchard   int   = 255
	Nold               uint8 = 2
	Nnew               uint8 = 2
	ValueLen           int   = 64
	HSigLen            int   = 256
	PrfLenSprout       int   = 256
	PrfExpandLen             = 512
	PrfNfSaplingLen          = 256
	RcmLenSapling            = 256
	SeedLen                  = 256
	AskLen                   = 252
	PsiSproutLen             = 252
	SkLen              int   = 256
	DLen               int   = 88
	IvkSaplingLen      int   = 251
	OvkLen             int   = 256
	ScalarSaplingLen   int   = 252
	ScalarOrchardLen   int   = 255
	BaseOrchardLen     int   = 255
)

var (
	UncommittedSprout = [MerkleLenSprout]byte{}
	// update on impl serialisation
	UncommittedSapling = [MerkleLenSapling]byte{}
	// Update
	UncommittedOrchard = []byte{0}
)
