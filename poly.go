/* SPDX-FileCopyrightText: © 2020-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import "golang.org/x/crypto/sha3"

type poly [paramsN]int16
type polyvec [4]poly

// polyCompress lossily compresses and subsequently serializes a polynomial.
func polyCompress(dst []byte, a *poly, paramsK int) {
	var t [8]byte
	rr := 0
	switch paramsK {
	case 2, 3:
		for i := 0; i < paramsN/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = byte((((uint32(a[8*i+j]) << 4) + paramsQDivBy2Ceil) * params2Pow28DivByQ) >> 28)
			}
			dst[rr] = t[0] | (t[1] << 4)
			dst[rr+1] = t[2] | (t[3] << 4)
			dst[rr+2] = t[4] | (t[5] << 4)
			dst[rr+3] = t[6] | (t[7] << 4)
			rr += 4
		}
	default:
		for i := 0; i < paramsN/8; i++ {
			for j := 0; j < 8; j++ {
				t[j] = byte((((uint32(a[8*i+j]) << 5) + (paramsQDivBy2Ceil - 1)) * params2Pow27DivByQ) >> 27)
			}
			dst[rr] = t[0] | (t[1] << 5)
			dst[rr+1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7)
			dst[rr+2] = (t[3] >> 1) | (t[4] << 4)
			dst[rr+3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6)
			dst[rr+4] = (t[6] >> 2) | (t[7] << 3)
			rr += 5
		}
	}
}

// polyDecompress de-serializes and subsequently decompresses a polynomial,
// representing the approximate inverse of polyCompress.
// Note that compression is lossy, and thus decompression will not match the
// original input.
func polyDecompress(a []byte, paramsK int) poly {
	var r poly
	var t [8]byte
	aa := 0
	switch paramsK {
	case 2, 3:
		for i := 0; i < paramsN/2; i++ {
			r[2*i] = int16(((uint16(a[aa]&15) * uint16(paramsQ)) + 8) >> 4)
			r[2*i+1] = int16(((uint16(a[aa]>>4) * uint16(paramsQ)) + 8) >> 4)
			aa++
		}
	case 4:
		for i := 0; i < paramsN/8; i++ {
			t[0] = a[aa]
			t[1] = (a[aa] >> 5) | (a[aa+1] << 3)
			t[2] = a[aa+1] >> 2
			t[3] = (a[aa+1] >> 7) | (a[aa+2] << 1)
			t[4] = (a[aa+2] >> 4) | (a[aa+3] << 4)
			t[5] = a[aa+3] >> 1
			t[6] = (a[aa+3] >> 6) | (a[aa+4] << 2)
			t[7] = a[aa+4] >> 3
			aa += 5
			for j := 0; j < 8; j++ {
				r[8*i+j] = int16(((uint32(t[j]&31) * uint32(paramsQ)) + 16) >> 5)
			}
		}
	}
	return r
}

// polyToBytes serializes a polynomial into an array of bytes.
func polyToBytes(dst []byte, a *poly) {
	var t0, t1 uint16
	for i := 0; i < paramsN/2; i++ {
		t0 = uint16(a[2*i])
		t1 = uint16(a[2*i+1])
		dst[3*i+0] = byte(t0 >> 0)
		dst[3*i+1] = byte(t0>>8) | byte(t1<<4)
		dst[3*i+2] = byte(t1 >> 4)
	}
}

// polyFromBytes de-serialises an array of bytes into a polynomial,
// and represents the inverse of polyToBytes.
// Per FIPS 203 Algorithm 6 (ByteDecode₁₂), coefficients are reduced mod Q.
func polyFromBytes(a []byte) poly {
	var r poly
	for i := 0; i < paramsN/2; i++ {
		r[2*i] = int16(((uint16(a[3*i+0]) >> 0) | (uint16(a[3*i+1]) << 8)) & 0xFFF)
		r[2*i+1] = int16(((uint16(a[3*i+1]) >> 4) | (uint16(a[3*i+2]) << 4)) & 0xFFF)
		r[2*i] %= int16(paramsQ)
		r[2*i+1] %= int16(paramsQ)
	}
	return r
}

// polyvecBytesValid checks that a serialized polynomial vector encodes
// coefficients in [0, q-1] per FIPS 203 §7.2 (encapsulation key modulus check).
// It performs ByteEncode₁₂(ByteDecode₁₂(a)) and checks equality with a.
func polyvecBytesValid(a []byte, paramsK int) bool {
	var roundTrip [paramsMaxK * paramsPolyBytes]byte
	for i := 0; i < paramsK; i++ {
		start := i * paramsPolyBytes
		end := start + paramsPolyBytes
		p := polyFromBytes(a[start:end])
		polyToBytes(roundTrip[start:end], &p)
	}
	for i := 0; i < paramsK*paramsPolyBytes; i++ {
		if a[i] != roundTrip[i] {
			return false
		}
	}
	return true
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
func polyToMsg(dst []byte, a *poly) {
	var t uint32
	for i := 0; i < paramsN/8; i++ {
		dst[i] = 0
		for j := 0; j < 8; j++ {
			t = (uint32(a[8*i+j]) << 1) + paramsQDivBy2Ceil
			t = ((t * params2Pow28DivByQ) >> 28) & 1
			dst[i] |= byte(t << j)
		}
	}
}

// polyGetNoise samples a polynomial deterministically from a seed
// and nonce, with the output polynomial being close to a centered
// binomial distribution.
func polyGetNoise(prf sha3.ShakeHash, seed []byte, nonce byte, paramsK int) poly {
	var buf [192]byte
	switch paramsK {
	case 2:
		l := paramsETAK512 * paramsN / 4
		indcpaPrf(buf[:l], prf, seed, nonce)
		return byteopsCbd(buf[:l], paramsK)
	default:
		l := paramsETAK768K1024 * paramsN / 4
		indcpaPrf(buf[:l], prf, seed, nonce)
		return byteopsCbd(buf[:l], paramsK)
	}
}

// polyNtt computes a negacyclic number-theoretic transform (NTT) of
// a polynomial in-place; the input is assumed to be in normal order,
// while the output is in bit-reversed order.
func polyNtt(p *poly) poly {
	return ntt(p)
}

// polyInvNttToMont computes the inverse of a negacyclic number-theoretic
// transform (NTT) of a polynomial in-place; the input is assumed to be in
// bit-reversed order, while the output is in normal order.
func polyInvNttToMont(p *poly) poly {
	return nttInv(p)
}

// polyBaseMulMontgomery performs the multiplication of two polynomials
// in the number-theoretic transform (NTT) domain.
func polyBaseMulMontgomery(a, b *poly) poly {
	var r poly
	for i := 0; i < paramsN/4; i++ {
		r[4*i+0], r[4*i+1] = nttBaseMul(
			a[4*i+0], a[4*i+1],
			b[4*i+0], b[4*i+1],
			nttZetas[64+i],
		)
		r[4*i+2], r[4*i+3] = nttBaseMul(
			a[4*i+2], a[4*i+3],
			b[4*i+2], b[4*i+3],
			-nttZetas[64+i],
		)
	}
	return r
}

// polyToMont performs the in-place conversion of all coefficients
// of a polynomial from the normal domain to the Montgomery domain.
func polyToMont(p *poly) poly {
	var r poly
	for i := 0; i < paramsN; i++ {
		r[i] = byteopsMontgomeryReduce(int32(p[i]) * int32(paramsMontFactor))
	}
	return r
}

// polyReduce applies Barrett reduction to all coefficients of a polynomial.
func polyReduce(p *poly) poly {
	var r poly
	for i := 0; i < paramsN; i++ {
		r[i] = byteopsBarrettReduce(p[i])
	}
	return r
}

// polyCSubQ applies the conditional subtraction of `Q` to each coefficient
// of a polynomial.
func polyCSubQ(p *poly) poly {
	var r poly
	for i := 0; i < paramsN; i++ {
		r[i] = byteopsCSubQ(p[i])
	}
	return r
}

// polyReduceFull applies Barrett reduction followed by conditional subtraction
// of Q to each coefficient in a single pass.
func polyReduceFull(p *poly) poly {
	var r poly
	for i := 0; i < paramsN; i++ {
		r[i] = byteopsCSubQ(byteopsBarrettReduce(p[i]))
	}
	return r
}

// polyAdd adds two polynomials.
func polyAdd(a, b *poly) poly {
	var r poly
	for i := 0; i < paramsN; i++ {
		r[i] = a[i] + b[i]
	}
	return r
}

// polySub subtracts two polynomials.
func polySub(a, b *poly) poly {
	var r poly
	for i := 0; i < paramsN; i++ {
		r[i] = a[i] - b[i]
	}
	return r
}

// polyvecCompress lossily compresses and serializes a vector of polynomials.
func polyvecCompress(dst []byte, a *polyvec, paramsK int) {
	rr := 0
	switch paramsK {
	case 2, 3:
		var t [4]uint16
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/4; j++ {
				for k := 0; k < 4; k++ {
					t[k] = uint16(((((uint64(a[i][4*j+k]) << 10) + uint64(paramsQDivBy2Ceil)) * params2Pow32DivByQ) >> 32) & 0x3ff)
				}
				dst[rr] = byte(t[0])
				dst[rr+1] = byte((t[0] >> 8) | (t[1] << 2))
				dst[rr+2] = byte((t[1] >> 6) | (t[2] << 4))
				dst[rr+3] = byte((t[2] >> 4) | (t[3] << 6))
				dst[rr+4] = byte(t[3] >> 2)
				rr += 5
			}
		}
	default:
		var t [8]uint16
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/8; j++ {
				for k := 0; k < 8; k++ {
					t[k] = uint16(((((uint64(a[i][8*j+k]) << 11) + uint64(paramsQDivBy2Ceil-1)) * params2Pow31DivByQ) >> 31) & 0x7ff)
				}
				dst[rr] = byte(t[0])
				dst[rr+1] = byte((t[0] >> 8) | (t[1] << 3))
				dst[rr+2] = byte((t[1] >> 5) | (t[2] << 6))
				dst[rr+3] = byte(t[2] >> 2)
				dst[rr+4] = byte((t[2] >> 10) | (t[3] << 1))
				dst[rr+5] = byte((t[3] >> 7) | (t[4] << 4))
				dst[rr+6] = byte((t[4] >> 4) | (t[5] << 7))
				dst[rr+7] = byte(t[5] >> 1)
				dst[rr+8] = byte((t[5] >> 9) | (t[6] << 2))
				dst[rr+9] = byte((t[6] >> 6) | (t[7] << 5))
				dst[rr+10] = byte(t[7] >> 3)
				rr += 11
			}
		}
	}
}

// polyvecDecompress de-serializes and decompresses a vector of polynomials and
// represents the approximate inverse of polyvecCompress. Since compression is lossy,
// the results of decompression will may not match the original vector of polynomials.
func polyvecDecompress(a []byte, paramsK int) polyvec {
	var r polyvec
	aa := 0
	switch paramsK {
	case 2, 3:
		var t [4]uint16
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/4; j++ {
				t[0] = uint16(a[aa]) | (uint16(a[aa+1]) << 8)
				t[1] = (uint16(a[aa+1]) >> 2) | (uint16(a[aa+2]) << 6)
				t[2] = (uint16(a[aa+2]) >> 4) | (uint16(a[aa+3]) << 4)
				t[3] = (uint16(a[aa+3]) >> 6) | (uint16(a[aa+4]) << 2)
				aa += 5
				for k := 0; k < 4; k++ {
					r[i][4*j+k] = int16((uint32(t[k]&0x3FF)*uint32(paramsQ) + 512) >> 10)
				}
			}
		}
	case 4:
		var t [8]uint16
		for i := 0; i < paramsK; i++ {
			for j := 0; j < paramsN/8; j++ {
				t[0] = uint16(a[aa]) | (uint16(a[aa+1]) << 8)
				t[1] = (uint16(a[aa+1]) >> 3) | (uint16(a[aa+2]) << 5)
				t[2] = (uint16(a[aa+2]) >> 6) | (uint16(a[aa+3]) << 2) | (uint16(a[aa+4]) << 10)
				t[3] = (uint16(a[aa+4]) >> 1) | (uint16(a[aa+5]) << 7)
				t[4] = (uint16(a[aa+5]) >> 4) | (uint16(a[aa+6]) << 4)
				t[5] = (uint16(a[aa+6]) >> 7) | (uint16(a[aa+7]) << 1) | (uint16(a[aa+8]) << 9)
				t[6] = (uint16(a[aa+8]) >> 2) | (uint16(a[aa+9]) << 6)
				t[7] = (uint16(a[aa+9]) >> 5) | (uint16(a[aa+10]) << 3)
				aa += 11
				for k := 0; k < 8; k++ {
					r[i][8*j+k] = int16((uint32(t[k]&0x7FF)*uint32(paramsQ) + 1024) >> 11)
				}
			}
		}
	}
	return r
}

// polyvecToBytes serializes a vector of polynomials.
func polyvecToBytes(dst []byte, a *polyvec, paramsK int) {
	for i := 0; i < paramsK; i++ {
		polyToBytes(dst[i*paramsPolyBytes:], &a[i])
	}
}

// polyvecFromBytes deserializes a vector of polynomials.
func polyvecFromBytes(a []byte, paramsK int) polyvec {
	var r polyvec
	for i := 0; i < paramsK; i++ {
		start := i * paramsPolyBytes
		end := (i + 1) * paramsPolyBytes
		r[i] = polyFromBytes(a[start:end])
	}
	return r
}

// polyvecNtt applies forward number-theoretic transforms (NTT)
// to all elements of a vector of polynomials.
func polyvecNtt(pv *polyvec, paramsK int) polyvec {
	var r polyvec
	for i := 0; i < paramsK; i++ {
		r[i] = polyNtt(&pv[i])
	}
	return r
}

// polyvecInvNttToMont applies the inverse number-theoretic transform (NTT)
// to all elements of a vector of polynomials and multiplies by Montgomery
// factor `2^16`.
func polyvecInvNttToMont(pv *polyvec, paramsK int) polyvec {
	var r polyvec
	for i := 0; i < paramsK; i++ {
		r[i] = polyInvNttToMont(&pv[i])
	}
	return r
}

// polyvecPointWiseAccMontgomery pointwise-multiplies elements of polynomial-vectors
// `a` and `b`, accumulates the results into `r`, and then multiplies by `2^-16`.
func polyvecPointWiseAccMontgomery(a, b *polyvec, paramsK int) poly {
	r := polyBaseMulMontgomery(&a[0], &b[0])
	for i := 1; i < paramsK; i++ {
		t := polyBaseMulMontgomery(&a[i], &b[i])
		r = polyAdd(&r, &t)
	}
	return polyReduce(&r)
}

// polyvecReduce applies Barrett reduction to each coefficient of each element
// of a vector of polynomials.
func polyvecReduce(pv *polyvec, paramsK int) polyvec {
	var r polyvec
	for i := 0; i < paramsK; i++ {
		r[i] = polyReduce(&pv[i])
	}
	return r
}

// polyvecReduceFull applies Barrett reduction followed by conditional subtraction
// of Q to each coefficient of each element of a vector of polynomials.
func polyvecReduceFull(pv *polyvec, paramsK int) polyvec {
	var r polyvec
	for i := 0; i < paramsK; i++ {
		r[i] = polyReduceFull(&pv[i])
	}
	return r
}

// polyvecCSubQ applies the conditional subtraction of `Q` to each coefficient
// of each element of a vector of polynomials.
func polyvecCSubQ(pv *polyvec, paramsK int) polyvec {
	var r polyvec
	for i := 0; i < paramsK; i++ {
		r[i] = polyCSubQ(&pv[i])
	}
	return r
}

// polyvecAdd adds two vectors of polynomials.
func polyvecAdd(a, b *polyvec, paramsK int) polyvec {
	var r polyvec
	for i := 0; i < paramsK; i++ {
		r[i] = polyAdd(&a[i], &b[i])
	}
	return r
}
