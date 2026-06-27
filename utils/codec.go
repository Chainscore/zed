package utils

func L2LEBSP64(l uint64) [8]byte {
	var r [8]byte
	for i := range 8 {
		r[i] = byte(l)
		l = l >> 8
	}
	return r
}

func L2LEBSP32(l uint32) [4]byte {
	var r [4]byte
	for i := range 4 {
		r[i] = byte(l)
		l = l >> 8
	}
	return r
}
