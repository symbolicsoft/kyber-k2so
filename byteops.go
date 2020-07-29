/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

func byteopsLoad32(x []byte) uint32 {
	var r uint32
	r = uint32(x[0])
	r = r | (uint32(x[1]) << 8)
	r = r | (uint32(x[2]) << 16)
	r = r | (uint32(x[3]) << 24)
	return r
}

func byteopsCbd(buf []byte) poly {
	var t, d uint32
	var a, b int16
	r := polyNew()
	for i := 0; i < params.n/8; i++ {
		t = byteopsLoad32(buf[4*i : (4*i)+4])
		d = t & 0x55555555
		d = d + ((t >> 1) & 0x55555555)
		for j := 0; j < 8; j++ {
			a = int16((d >> (4*j + 0)) & 0x3)
			b = int16((d >> (4*j + 2)) & 0x3)
			r.coeffs[8*i+j] = a - b
		}
	}
	return r
}

func byteopsMontgomeryReduce(a int32) int16 {
	u := int16(a * int32(params.qinv))
	t := int32(u) * int32(params.q)
	t = a - t
	t >>= 16
	return int16(t)
}

func byteopsBarrettReduce(a int16) int16 {
	var t int16
	var v int16 = int16(((uint32(1) << 26) + uint32(params.q/2)) / uint32(params.q))
	t = int16(int32(v) * int32(a) >> 26)
	t = t * int16(params.q)
	return a - t
}

func byteopsCSubQ(a int16) int16 {
	a = a - int16(params.q)
	a = a + ((a >> 15) & int16(params.q))
	return a
}
