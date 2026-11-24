/* SPDX-FileCopyrightText: © 2026 Abhishek Biswas
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"testing"
)

func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func checkCanonical12Bit(a []byte, paramsK int) bool {
	for i := 0; i < paramsK; i++ {
		off := i * paramsPolyBytes
		for j := 0; j < paramsN/2; j++ {
			b0 := uint16(a[off+3*j])
			b1 := uint16(a[off+3*j+1])
			b2 := uint16(a[off+3*j+2])
			c0 := (b0 | (b1 << 8)) & 0xFFF
			c1 := ((b1 >> 4) | (b2 << 4)) & 0xFFF
			if int(c0) >= paramsQ || int(c1) >= paramsQ {
				return false
			}
		}
	}
	return true
}

func assertDecapsMalformedResult(t *testing.T, validHash bool, ss [KyberSSBytes]byte, err error) {
	t.Helper()
	if !validHash {
		if !errors.Is(err, ErrInvalidDecapsulationKey) {
			t.Fatalf("expected ErrInvalidDecapsulationKey, got %v", err)
		}
		if !isAllZero(ss[:]) {
			t.Fatal("expected zero shared secret on invalid decapsulation key")
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error on valid decapsulation key hash: %v", err)
	}
}

func assertEncapsResult(t *testing.T, validPK bool, ct []byte, ss [KyberSSBytes]byte, err error) {
	t.Helper()
	if !validPK {
		if !errors.Is(err, ErrInvalidEncapsulationKey) {
			t.Fatalf("expected ErrInvalidEncapsulationKey, got %v", err)
		}
		if !isAllZero(ct) || !isAllZero(ss[:]) {
			t.Fatal("expected zero ciphertext and shared secret on invalid encapsulation key")
		}
		return
	}
	if err != nil {
		t.Fatalf("unexpected error on valid encapsulation key: %v", err)
	}
}

func FuzzKemDecrypt512(f *testing.F) {
	f.Add(benchCt512[:], benchKey512sk[:])
	f.Add(make([]byte, Kyber512CTBytes), make([]byte, Kyber512SKBytes))
	f.Add(bytes.Repeat([]byte{0xFF}, Kyber512CTBytes), bytes.Repeat([]byte{0xFF}, Kyber512SKBytes))

	f.Fuzz(func(t *testing.T, ctBytes, dkBytes []byte) {
		var ct [Kyber512CTBytes]byte
		var dk [Kyber512SKBytes]byte
		copy(ct[:], ctBytes)
		copy(dk[:], dkBytes)

		ss1, err1 := KemDecrypt512(ct, benchKey512sk)
		if err1 != nil {
			t.Fatalf("KemDecrypt512 failed on valid key: %v", err1)
		}
		ss2, err2 := KemDecrypt512(ct, benchKey512sk)
		if err2 != nil {
			t.Fatalf("KemDecrypt512 repeat call failed: %v", err2)
		}
		if subtle.ConstantTimeCompare(ss1[:], ss2[:]) == 0 {
			t.Fatal("KemDecrypt512 produced non-deterministic shared secret")
		}

		ssMalformed, errMalformed := KemDecrypt512(ct, dk)
		assertDecapsMalformedResult(t, kemDecapsInputCheck(dk[:], 2), ssMalformed, errMalformed)
	})
}

func FuzzKemDecrypt768(f *testing.F) {
	f.Add(benchCt768[:], benchKey768sk[:])
	f.Add(make([]byte, Kyber768CTBytes), make([]byte, Kyber768SKBytes))
	f.Add(bytes.Repeat([]byte{0xFF}, Kyber768CTBytes), bytes.Repeat([]byte{0xFF}, Kyber768SKBytes))

	f.Fuzz(func(t *testing.T, ctBytes, dkBytes []byte) {
		var ct [Kyber768CTBytes]byte
		var dk [Kyber768SKBytes]byte
		copy(ct[:], ctBytes)
		copy(dk[:], dkBytes)

		ss1, err1 := KemDecrypt768(ct, benchKey768sk)
		if err1 != nil {
			t.Fatalf("KemDecrypt768 failed on valid key: %v", err1)
		}
		ss2, err2 := KemDecrypt768(ct, benchKey768sk)
		if err2 != nil {
			t.Fatalf("KemDecrypt768 repeat call failed: %v", err2)
		}
		if subtle.ConstantTimeCompare(ss1[:], ss2[:]) == 0 {
			t.Fatal("KemDecrypt768 produced non-deterministic shared secret")
		}

		ssMalformed, errMalformed := KemDecrypt768(ct, dk)
		assertDecapsMalformedResult(t, kemDecapsInputCheck(dk[:], 3), ssMalformed, errMalformed)
	})
}

func FuzzKemDecrypt1024(f *testing.F) {
	f.Add(benchCt1024[:], benchKey1024sk[:])
	f.Add(make([]byte, Kyber1024CTBytes), make([]byte, Kyber1024SKBytes))
	f.Add(bytes.Repeat([]byte{0xFF}, Kyber1024CTBytes), bytes.Repeat([]byte{0xFF}, Kyber1024SKBytes))

	f.Fuzz(func(t *testing.T, ctBytes, dkBytes []byte) {
		var ct [Kyber1024CTBytes]byte
		var dk [Kyber1024SKBytes]byte
		copy(ct[:], ctBytes)
		copy(dk[:], dkBytes)

		ss1, err1 := KemDecrypt1024(ct, benchKey1024sk)
		if err1 != nil {
			t.Fatalf("KemDecrypt1024 failed on valid key: %v", err1)
		}
		ss2, err2 := KemDecrypt1024(ct, benchKey1024sk)
		if err2 != nil {
			t.Fatalf("KemDecrypt1024 repeat call failed: %v", err2)
		}
		if subtle.ConstantTimeCompare(ss1[:], ss2[:]) == 0 {
			t.Fatal("KemDecrypt1024 produced non-deterministic shared secret")
		}

		ssMalformed, errMalformed := KemDecrypt1024(ct, dk)
		assertDecapsMalformedResult(t, kemDecapsInputCheck(dk[:], 4), ssMalformed, errMalformed)
	})
}

func FuzzKemEncryptDerand(f *testing.F) {
	zeroMsg := make([]byte, paramsSymBytes)
	f.Add(benchKey512pk[:], zeroMsg)
	f.Add(benchKey768pk[:], zeroMsg)
	f.Add(benchKey1024pk[:], zeroMsg)
	f.Add(bytes.Repeat([]byte{0xFF}, Kyber1024PKBytes), bytes.Repeat([]byte{0xAA}, paramsSymBytes))

	f.Fuzz(func(t *testing.T, pkBytes, mBytes []byte) {
		var m [32]byte
		copy(m[:], mBytes)

		var pk512 [Kyber512PKBytes]byte
		copy(pk512[:], pkBytes)
		ct512, ss512, err512 := KemEncryptDerand512(pk512, m)
		assertEncapsResult(t, polyvecBytesValid(pk512[:paramsPolyvecBytesK512], 2), ct512[:], ss512, err512)

		var pk768 [Kyber768PKBytes]byte
		copy(pk768[:], pkBytes)
		ct768, ss768, err768 := KemEncryptDerand768(pk768, m)
		assertEncapsResult(t, polyvecBytesValid(pk768[:paramsPolyvecBytesK768], 3), ct768[:], ss768, err768)

		var pk1024 [Kyber1024PKBytes]byte
		copy(pk1024[:], pkBytes)
		ct1024, ss1024, err1024 := KemEncryptDerand1024(pk1024, m)
		assertEncapsResult(t, polyvecBytesValid(pk1024[:paramsPolyvecBytesK1024], 4), ct1024[:], ss1024, err1024)
	})
}

func assertPolyCompressRoundTrip(t *testing.T, in []byte, paramsK int) {
	t.Helper()
	p := polyDecompress(in, paramsK)
	for i, c := range p {
		if c < 0 || int(c) >= paramsQ {
			t.Fatalf("polyDecompress(k=%d) coeff[%d]=%d out of [0, %d)", paramsK, i, c, paramsQ)
		}
	}
	out := make([]byte, len(in))
	polyCompress(out, &p, paramsK)
	if !bytes.Equal(in, out) {
		t.Fatalf("polyDecompress->polyCompress(k=%d) round-trip mismatch", paramsK)
	}
}

func assertPolyvecCompressRoundTrip(t *testing.T, in []byte, paramsK int) {
	t.Helper()
	pv := polyvecDecompress(in, paramsK)
	for i := 0; i < paramsK; i++ {
		for j, c := range pv[i] {
			if c < 0 || int(c) >= paramsQ {
				t.Fatalf("polyvecDecompress(k=%d) coeff[%d][%d]=%d out of [0, %d)", paramsK, i, j, c, paramsQ)
			}
		}
	}
	out := make([]byte, len(in))
	polyvecCompress(out, &pv, paramsK)
	if !bytes.Equal(in, out) {
		t.Fatalf("polyvecDecompress->polyvecCompress(k=%d) round-trip mismatch", paramsK)
	}
}

func FuzzPolyDecoding(f *testing.F) {
	f.Add(make([]byte, paramsPolyvecBytesK1024))
	f.Add(bytes.Repeat([]byte{0xFF}, paramsPolyvecBytesK1024))
	f.Add(benchKey1024pk[:paramsPolyvecBytesK1024])
	f.Add(benchCt1024[:])

	f.Fuzz(func(t *testing.T, input []byte) {
		var buf [paramsPolyvecBytesK1024]byte
		copy(buf[:], input)

		p := polyFromBytes(buf[:paramsPolyBytes])
		for i, c := range p {
			if c < 0 || int(c) >= paramsQ {
				t.Fatalf("polyFromBytes coeff[%d]=%d out of [0, %d)", i, c, paramsQ)
			}
		}
		var encoded [paramsPolyBytes]byte
		polyToBytes(encoded[:], &p)
		if p2 := polyFromBytes(encoded[:]); p != p2 {
			t.Fatal("polyFromBytes->polyToBytes->polyFromBytes idempotence failed")
		}

		for _, k := range []int{2, 3, 4} {
			got := polyvecBytesValid(buf[:k*paramsPolyBytes], k)
			want := checkCanonical12Bit(buf[:k*paramsPolyBytes], k)
			if got != want {
				t.Fatalf("polyvecBytesValid(k=%d)=%v, want %v", k, got, want)
			}
		}

		assertPolyCompressRoundTrip(t, buf[:paramsPolyCompressedBytesK512], 2)
		assertPolyCompressRoundTrip(t, buf[:paramsPolyCompressedBytesK1024], 4)
		assertPolyvecCompressRoundTrip(t, buf[:paramsPolyvecCompressedBytesK512], 2)
		assertPolyvecCompressRoundTrip(t, buf[:paramsPolyvecCompressedBytesK768], 3)
		assertPolyvecCompressRoundTrip(t, buf[:paramsPolyvecCompressedBytesK1024], 4)

		msgPoly := polyFromMsg(buf[:paramsSymBytes])
		var msgOut [paramsSymBytes]byte
		polyToMsg(msgOut[:], &msgPoly)
		if !bytes.Equal(buf[:paramsSymBytes], msgOut[:]) {
			t.Fatal("polyFromMsg->polyToMsg round-trip mismatch")
		}
	})
}

func FuzzByteops(f *testing.F) {
	const montBound = int32(paramsQ) * 32768
	f.Add(make([]byte, 192), int16(0), int32(0))
	f.Add(bytes.Repeat([]byte{0xFF}, 192), int16(32767), montBound-1)
	f.Add(bytes.Repeat([]byte{0x55}, 192), int16(-29960), -montBound)

	f.Fuzz(func(t *testing.T, buf []byte, barrettIn int16, montIn int32) {
		var cbdBuf [192]byte
		copy(cbdBuf[:], buf)

		p512 := byteopsCbd(cbdBuf[:192], 2)
		for i, c := range p512 {
			if int(c) < -paramsETAK512 || int(c) > paramsETAK512 {
				t.Fatalf("byteopsCbd(k=2) coeff[%d]=%d out of [-%d, %d]", i, c, paramsETAK512, paramsETAK512)
			}
		}
		for _, k := range []int{3, 4} {
			pk := byteopsCbd(cbdBuf[:128], k)
			for i, c := range pk {
				if int(c) < -paramsETAK768K1024 || int(c) > paramsETAK768K1024 {
					t.Fatalf("byteopsCbd(k=%d) coeff[%d]=%d out of [-%d, %d]",
						k, i, c, paramsETAK768K1024, paramsETAK768K1024)
				}
			}
		}

		if barrettIn >= -29960 {
			reduced := byteopsCSubQ(byteopsBarrettReduce(barrettIn))
			if reduced < 0 || int(reduced) >= paramsQ {
				t.Fatalf("barrett+csubq(%d)=%d out of [0, %d)", barrettIn, reduced, paramsQ)
			}
			if (int(reduced)-int(barrettIn))%paramsQ != 0 {
				t.Fatalf("barrett+csubq(%d)=%d not congruent mod %d", barrettIn, reduced, paramsQ)
			}
		}

		if montIn >= -montBound && montIn < montBound {
			mr := byteopsMontgomeryReduce(montIn)
			if int(mr) <= -paramsQ || int(mr) >= paramsQ {
				t.Fatalf("byteopsMontgomeryReduce(%d)=%d out of (-%d, %d)", montIn, mr, paramsQ, paramsQ)
			}
			if (int64(mr)*65536-int64(montIn))%int64(paramsQ) != 0 {
				t.Fatalf("byteopsMontgomeryReduce(%d)=%d failed modular congruence", montIn, mr)
			}
		}
	})
}
