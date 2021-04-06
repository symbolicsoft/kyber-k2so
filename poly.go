/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

type poly [paramsPolyBytes]int16
type polyvec []poly

// polyCompress lossily compresses and subsequently serializes a polynomial.
func polyCompress(a poly, paramsK int) []byte {
	t := make([]byte, 8)
	a = polyCSubQ(a)
	rr := 0
	switch paramsK {
	case 2, 3:
		r := make([]byte, paramsPolyCompressedBytesK768) // 128
		for i := 0; i < paramsN/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = byte(((uint16(a[8*i+j])<<4)+uint16(paramsQ/2))/uint16(paramsQ)) & 15
			}
			r[rr+0] = t[0] | (t[1] << 4)
			r[rr+1] = t[2] | (t[3] << 4)
			r[rr+2] = t[4] | (t[5] << 4)
			r[rr+3] = t[6] | (t[7] << 4)
			rr = rr + 4
		}
		return r
	default:
		r := make([]byte, paramsPolyCompressedBytesK1024) // 160
		for i := 0; i < paramsN/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = byte(((uint32(a[8*i+j])<<5)+uint32(paramsQ/2))/uint32(paramsQ)) & 31
			}
			r[rr+0] = (t[0] >> 0) | (t[1] << 5)
			r[rr+1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
			r[rr+2] = (t[3] >> 1) | (t[4] << 4)
			r[rr+3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
			r[rr+4] = (t[6] >> 2) | (t[7] << 3)
			rr = rr + 5
		}
		return r
	}
}

// polyDecompress de-serializes and subsequently decompresses a polynomial,
// representing the approximate inverse of polyCompress.
// Note that compression is lossy, and thus decompression will not match the
// original input.
func polyDecompress(a []byte, paramsK int) poly {
	var r poly
	t := make([]byte, 8)
	aa := 0
	switch paramsK {
	case 2, 3:
		for i := 0; i < paramsN/2; i++ {
			r[2*i+0] = int16(((uint16(a[aa]&15) * uint16(paramsQ)) + 8) >> 4)
			r[2*i+1] = int16(((uint16(a[aa]>>4) * uint16(paramsQ)) + 8) >> 4)
			aa = aa + 1
		}
	case 4:
		for i := 0; i < paramsN/8; i++ {
			t[0] = (a[aa+0] >> 0)
			t[1] = (a[aa+0] >> 5) | (a[aa+1] << 3)
			t[2] = (a[aa+1] >> 2)
			t[3] = (a[aa+1] >> 7) | (a[aa+2] << 1)
			t[4] = (a[aa+2] >> 4) | (a[aa+3] << 4)
			t[5] = (a[aa+3] >> 1)
			t[6] = (a[aa+3] >> 6) | (a[aa+4] << 2)
			t[7] = (a[aa+4] >> 3)
			aa = aa + 5
			for j := 0; j < 8; j++ {
				r[8*i+j] = int16(((uint32(t[j]&31) * uint32(paramsQ)) + 16) >> 5)
			}
		}
	}
	return r
}

// polyToBytes serializes a polynomial into an array of bytes.
func polyToBytes(a poly) []byte {
	var t0, t1 uint16
	r := make([]byte, paramsPolyBytes)
	a = polyCSubQ(a)
	for i := 0; i < paramsN/2; i++ {
		t0 = uint16(a[2*i])
		t1 = uint16(a[2*i+1])
		r[3*i+0] = byte(t0 >> 0)
		r[3*i+1] = byte(t0>>8) | byte(t1<<4)
		r[3*i+2] = byte(t1 >> 4)
	}
	return r
}

// polyFromBytes de-serialises an array of bytes into a polynomial,
// and represents the inverse of polyToBytes.
func polyFromBytes(a []byte) poly {
	var r poly
	for i := 0; i < paramsN/2; i++ {
		r[2*i] = int16(((uint16(a[3*i+0]) >> 0) | (uint16(a[3*i+1]) << 8)) & 0xFFF)
		r[2*i+1] = int16(((uint16(a[3*i+1]) >> 4) | (uint16(a[3*i+2]) << 4)) & 0xFFF)
	}
	return r
}

// polyFromMsg converts a 32-byte message to a polynomial.
func polyFromMsg(msg []byte) poly {
	var r poly
	var mask int16
	for i := 0; i < paramsN/8; i++ {
		for j := 0; j < 8; j++ {
			mask = -int16((msg[i] >> j) & 1)
			r[8*i+j] = mask & int16((paramsQ+1)/2)
		}
	}
	return r
}

// polyToMsg converts a polynomial to a 32-byte message
// and represents the inverse of polyFromMsg.
func polyToMsg(a poly) []byte {
	msg := make([]byte, paramsSymBytes)
	var t uint16
	a = polyCSubQ(a)
	for i := 0; i < paramsN/8; i++ {
		msg[i] = 0
		for j := 0; j < 8; j++ {
			t = (((uint16(a[8*i+j]) << 1) + uint16(paramsQ/2)) / uint16(paramsQ)) & 1
			msg[i] |= byte(t << j)
		}
	}
	return msg
}

// polyGetNoise samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution.
func polyGetNoise(seed []byte, nonce byte, paramsK int) poly {
	switch paramsK {
	case 2:
		l := paramsETAK512 * paramsN / 4
		p := indcpaPrf(l, seed, nonce)
		return byteopsCbd(p, paramsK)
	default:
		l := paramsETAK768K1024 * paramsN / 4
		p := indcpaPrf(l, seed, nonce)
		return byteopsCbd(p, paramsK)
	}
}

// polyNtt computes a negacyclic number-theoretic transform (NTT) of
// a polynomial in-place; the input is assumed to be in normal order,
// while the output is in bit-reversed order.
func polyNtt(r poly) poly {
	return ntt(r)
}

// polyInvNttToMont computes the inverse of a negacyclic number-theoretic
// transform (NTT) of a polynomial in-place; the input is assumed to be in
// bit-reversed order, while the output is in normal order.
func polyInvNttToMont(r poly) poly {
	return nttInv(r)
}

// polyBaseMulMontgomery performs the multiplication of two polynomials
// in the number-theoretic transform (NTT) domain.
func polyBaseMulMontgomery(a poly, b poly) poly {
	for i := 0; i < paramsN/4; i++ {
		rx := nttBaseMul(
			a[4*i+0], a[4*i+1],
			b[4*i+0], b[4*i+1],
			nttZetas[64+i],
		)
		ry := nttBaseMul(
			a[4*i+2], a[4*i+3],
			b[4*i+2], b[4*i+3],
			-nttZetas[64+i],
		)
		a[4*i+0] = rx[0]
		a[4*i+1] = rx[1]
		a[4*i+2] = ry[0]
		a[4*i+3] = ry[1]
	}
	return a
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
func polyToMont(r poly) poly {
	var f int16 = int16((uint64(1) << 32) % uint64(paramsQ))
	for i := 0; i < paramsN; i++ {
		r[i] = byteopsMontgomeryReduce(int32(r[i]) * int32(f))
	}
	return r
}

// polyReduce applies Barrett reduction to all coefficients of a polynomial.
func polyReduce(r poly) poly {
	for i := 0; i < paramsN; i++ {
		r[i] = byteopsBarrettReduce(r[i])
	}
	return r
}

// polyCSubQ applies the conditional subtraction of `Q` to each coefficient
// of a polynomial.
func polyCSubQ(r poly) poly {
	for i := 0; i < paramsN; i++ {
		r[i] = byteopsCSubQ(r[i])
	}
	return r
}

// polyAdd adds two polynomials.
func polyAdd(a poly, b poly) poly {
	for i := 0; i < paramsN; i++ {
		a[i] = a[i] + b[i]
	}
	return a
}

// polySub subtracts two polynomials.
func polySub(a poly, b poly) poly {
	for i := 0; i < paramsN; i++ {
		a[i] = a[i] - b[i]
	}
	return a
}

// polyvecNew instantiates a new vector of polynomials.
func polyvecNew(paramsK int) polyvec {
	var pv polyvec = make([]poly, paramsK)
	return pv
}

// polyvecCompress lossily compresses and serializes a vector of polynomials.
func polyvecCompress(a polyvec, paramsK int) []byte {
	var r []byte
	polyvecCSubQ(a, paramsK)
	rr := 0
	switch paramsK {
	case 2:
		r = make([]byte, paramsPolyvecCompressedBytesK512)
	case 3:
		r = make([]byte, paramsPolyvecCompressedBytesK768)
	case 4:
		r = make([]byte, paramsPolyvecCompressedBytesK1024)
	}
	switch paramsK {
	case 2, 3:
		t := make([]uint16, 4)
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/4; j++ {
				for k := 0; k < 4; k++ {
					t[k] = uint16((((uint32(a[i][4*j+k]) << 10) + uint32(paramsQ/2)) / uint32(paramsQ)) & 0x3ff)
				}
				r[rr+0] = byte(t[0] >> 0)
				r[rr+1] = byte((t[0] >> 8) | (t[1] << 2))
				r[rr+2] = byte((t[1] >> 6) | (t[2] << 4))
				r[rr+3] = byte((t[2] >> 4) | (t[3] << 6))
				r[rr+4] = byte((t[3] >> 2))
				rr = rr + 5
			}
		}
		return r
	default:
		t := make([]uint16, 8)
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/8; j++ {
				for k := 0; k < 8; k++ {
					t[k] = uint16((((uint32(a[i][8*j+k]) << 11) + uint32(paramsQ/2)) / uint32(paramsQ)) & 0x7ff)
				}
				r[rr+0] = byte((t[0] >> 0))
				r[rr+1] = byte((t[0] >> 8) | (t[1] << 3))
				r[rr+2] = byte((t[1] >> 5) | (t[2] << 6))
				r[rr+3] = byte((t[2] >> 2))
				r[rr+4] = byte((t[2] >> 10) | (t[3] << 1))
				r[rr+5] = byte((t[3] >> 7) | (t[4] << 4))
				r[rr+6] = byte((t[4] >> 4) | (t[5] << 7))
				r[rr+7] = byte((t[5] >> 1))
				r[rr+8] = byte((t[5] >> 9) | (t[6] << 2))
				r[rr+9] = byte((t[6] >> 6) | (t[7] << 5))
				r[rr+10] = byte((t[7] >> 3))
				rr = rr + 11
			}
		}
		return r
	}
}

// polyvecDecompress de-serializes and decompresses a vector of polynomials and
// represents the approximate inverse of polyvecCompress. Since compression is lossy,
// the results of decompression will may not match the original vector of polynomials.
func polyvecDecompress(a []byte, paramsK int) polyvec {
	r := polyvecNew(paramsK)
	aa := 0
	switch paramsK {
	case 2, 3:
		t := make([]uint16, 4)
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/4; j++ {
				t[0] = (uint16(a[aa+0]) >> 0) | (uint16(a[aa+1]) << 8)
				t[1] = (uint16(a[aa+1]) >> 2) | (uint16(a[aa+2]) << 6)
				t[2] = (uint16(a[aa+2]) >> 4) | (uint16(a[aa+3]) << 4)
				t[3] = (uint16(a[aa+3]) >> 6) | (uint16(a[aa+4]) << 2)
				aa = aa + 5
				for k := 0; k < 4; k++ {
					r[i][4*j+k] = int16((uint32(t[k]&0x3FF)*uint32(paramsQ) + 512) >> 10)
				}
			}
		}
	case 4:
		t := make([]uint16, 8)
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/8; j++ {
				t[0] = (uint16(a[aa+0]) >> 0) | (uint16(a[aa+1]) << 8)
				t[1] = (uint16(a[aa+1]) >> 3) | (uint16(a[aa+2]) << 5)
				t[2] = (uint16(a[aa+2]) >> 6) | (uint16(a[aa+3]) << 2) | (uint16(a[aa+4]) << 10)
				t[3] = (uint16(a[aa+4]) >> 1) | (uint16(a[aa+5]) << 7)
				t[4] = (uint16(a[aa+5]) >> 4) | (uint16(a[aa+6]) << 4)
				t[5] = (uint16(a[aa+6]) >> 7) | (uint16(a[aa+7]) << 1) | (uint16(a[aa+8]) << 9)
				t[6] = (uint16(a[aa+8]) >> 2) | (uint16(a[aa+9]) << 6)
				t[7] = (uint16(a[aa+9]) >> 5) | (uint16(a[aa+10]) << 3)
				aa = aa + 11
				for k := 0; k < 8; k++ {
					r[i][8*j+k] = int16((uint32(t[k]&0x7FF)*uint32(paramsQ) + 1024) >> 11)
				}
			}
		}
	}
	return r
}

// polyvecToBytes serializes a vector of polynomials.
func polyvecToBytes(a polyvec, paramsK int) []byte {
	r := []byte{}
	for i := 0; i < paramsK; i++ {
		r = append(r, polyToBytes(a[i])...)
	}
	return r
}

// polyvecFromBytes deserializes a vector of polynomials.
func polyvecFromBytes(a []byte, paramsK int) polyvec {
	r := polyvecNew(paramsK)
	for i := 0; i < paramsK; i++ {
		start := (i * paramsPolyBytes)
		end := (i + 1) * paramsPolyBytes
		r[i] = polyFromBytes(a[start:end])
	}
	return r
}

// polyvecNtt applies forward number-theoretic transforms (NTT)
// to all elements of a vector of polynomials.
func polyvecNtt(r polyvec, paramsK int) {
	for i := 0; i < paramsK; i++ {
		r[i] = polyNtt(r[i])
	}
}

// polyvecInvNttToMont applies the inverse number-theoretic transform (NTT)
// to all elements of a vector of polynomials and multiplies by Montgomery
// factor `2^16`.
func polyvecInvNttToMont(r polyvec, paramsK int) {
	for i := 0; i < paramsK; i++ {
		r[i] = polyInvNttToMont(r[i])
	}
}

// polyvecPointWiseAccMontgomery pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.
func polyvecPointWiseAccMontgomery(a polyvec, b polyvec, paramsK int) poly {
	r := polyBaseMulMontgomery(a[0], b[0])
	for i := 1; i < paramsK; i++ {
		t := polyBaseMulMontgomery(a[i], b[i])
		r = polyAdd(r, t)
	}
	return polyReduce(r)
}

// polyvecReduce applies Barrett reduction to each coefficient of each element
// of a vector of polynomials.
func polyvecReduce(r polyvec, paramsK int) {
	for i := 0; i < paramsK; i++ {
		r[i] = polyReduce(r[i])
	}
}

// polyvecCSubQ applies the conditional subtraction of `Q` to each coefficient
// of each element of a vector of polynomials.
func polyvecCSubQ(r polyvec, paramsK int) {
	for i := 0; i < paramsK; i++ {
		r[i] = polyCSubQ(r[i])
	}
}

// polyvecAdd adds two vectors of polynomials.
func polyvecAdd(a polyvec, b polyvec, paramsK int) {
	for i := 0; i < paramsK; i++ {
		a[i] = polyAdd(a[i], b[i])
	}
}
