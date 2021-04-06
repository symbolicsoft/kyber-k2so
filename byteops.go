/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

// byteopsLoad32 returns a 32-bit unsigned integer loaded from byte x.
func byteopsLoad32(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r = r | (uint32(x[1]) << 8)
	r = r | (uint32(x[2]) << 16)
	r = r | (uint32(x[3]) << 24)
	return r
}

// byteopsLoad24 returns a 32-bit unsigned integer loaded from byte x.
func byteopsLoad24(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r = r | (uint32(x[1]) << 8)
	r = r | (uint32(x[2]) << 16)
	return r
}

// byteopsCbd computers a polynomial with coefficients distributed
// according to a centered binomial distribution with parameter eta,
// given an array of uniformly random bytes.
func byteopsCbd(buf []byte, paramsK int) poly {
	var t, d uint32
	var a, b int16
	var r poly
	switch paramsK {
	case 2:
		for i := 0; i < paramsN/4; i++ {
			t = byteopsLoad24(buf[3*i:])
			d = t & 0x00249249
			d = d + ((t >> 1) & 0x00249249)
			d = d + ((t >> 2) & 0x00249249)
			for j := 0; j < 4; j++ {
				a = int16((d >> (6*j + 0)) & 0x7)
				b = int16((d >> (6*j + paramsETAK512)) & 0x7)
				r[4*i+j] = a - b
			}
		}
	default:
		for i := 0; i < paramsN/8; i++ {
			t = byteopsLoad32(buf[4*i:])
			d = t & 0x55555555
			d = d + ((t >> 1) & 0x55555555)
			for j := 0; j < 8; j++ {
				a = int16((d >> (4*j + 0)) & 0x3)
				b = int16((d >> (4*j + paramsETAK768K1024)) & 0x3)
				r[8*i+j] = a - b
			}
		}
	}
	return r
}

// byteopsMontgomeryReduce computes a Montgomery reduction; given
// a 32-bit integer `a`, returns `a * R^-1 mod Q` where `R=2^16`.
func byteopsMontgomeryReduce(a int32) int16 {
	u := int16(a * int32(paramsQinv))
	t := int32(u) * int32(paramsQ)
	t = a - t
	t >>= 16
	return int16(t)
}

// byteopsBarrettReduce computes a Barrett reduction; given
// a 16-bit integer `a`, returns a 16-bit integer congruent to
// `a mod Q` in {0,...,Q}.
func byteopsBarrettReduce(a int16) int16 {
	var t int16
	var v int16 = int16(((uint32(1) << 26) + uint32(paramsQ/2)) / uint32(paramsQ))
	t = int16(int32(v) * int32(a) >> 26)
	t = t * int16(paramsQ)
	return a - t
}

// byteopsCSubQ conditionally subtracts Q from a.
func byteopsCSubQ(a int16) int16 {
	a = a - int16(paramsQ)
	a = a + ((a >> 15) & int16(paramsQ))
	return a
}
