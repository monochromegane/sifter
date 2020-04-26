package sifter

const (
	A uint = 1 << iota // 0000 0001
	B                  // 0000 0010
	C                  // 0000 0100
	D                  // 0000 1000
	E                  // 0001 0000
	F                  // 0010 0000
	G                  // 0100 0000
	H                  // 1000 0000
)

func readBitAt(i int, b byte) bool {
	bits := uint(b)
	switch i {
	case 0:
		return bits&H == H
	case 1:
		return bits&G == G
	case 2:
		return bits&F == F
	case 3:
		return bits&E == E
	case 4:
		return bits&D == D
	case 5:
		return bits&C == C
	case 6:
		return bits&B == B
	case 7:
		return bits&A == A
	default:
		return false
	}
}

func fromByte(b byte) []bool {
	bits := uint(b)

	v := make([]bool, 8)

	if bits&H == H {
		v[0] = true
	}
	if bits&G == G {
		v[1] = true
	}
	if bits&F == F {
		v[2] = true
	}
	if bits&E == E {
		v[3] = true
	}
	if bits&D == D {
		v[4] = true
	}
	if bits&C == C {
		v[5] = true
	}
	if bits&B == B {
		v[6] = true
	}
	if bits&A == A {
		v[7] = true
	}
	return v
}

func toBytes(v []bool) []byte {
	byteLength := (len(v) / 8) + 1
	bs := make([]byte, byteLength)
	for i := 0; i < byteLength; i++ {
		s := i * 8
		e := s + 8
		if e > len(v) {
			e = len(v)
		}
		bs[i] = toByte(v[s:e])
	}
	return bs
}

func toByte(v []bool) byte {
	var bits uint
	for i, b := range v {
		if i > 7 {
			break
		}

		switch i {
		case 0:
			if b {
				bits |= H
			}
		case 1:
			if b {
				bits |= G
			}
		case 2:
			if b {
				bits |= F
			}
		case 3:
			if b {
				bits |= E
			}
		case 4:
			if b {
				bits |= D
			}
		case 5:
			if b {
				bits |= C
			}
		case 6:
			if b {
				bits |= B
			}
		case 7:
			if b {
				bits |= A
			}
		}
	}
	return byte(bits)
}
