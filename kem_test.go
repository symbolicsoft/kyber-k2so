/* SPDX-FileCopyrightText: © 2020-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"crypto/subtle"
	"testing"
)

func TestSelf512(t *testing.T) {
	for i := 0; i < 1000; i++ {
		privateKey, publicKey, err := KemKeypair512()
		if err != nil {
			t.Error(err)
		}
		ciphertext, ssA, err := KemEncrypt512(publicKey)
		if err != nil {
			t.Error(err)
		}
		ssB, err := KemDecrypt512(ciphertext, privateKey)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(ssA[:], ssB[:]) == 0 {
			t.Errorf("ML-KEM-512 self-test failed at iteration %d", i)
		}
	}
}

func TestSelf768(t *testing.T) {
	for i := 0; i < 1000; i++ {
		privateKey, publicKey, err := KemKeypair768()
		if err != nil {
			t.Error(err)
		}
		ciphertext, ssA, err := KemEncrypt768(publicKey)
		if err != nil {
			t.Error(err)
		}
		ssB, err := KemDecrypt768(ciphertext, privateKey)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(ssA[:], ssB[:]) == 0 {
			t.Errorf("ML-KEM-768 self-test failed at iteration %d", i)
		}
	}
}

func TestSelf1024(t *testing.T) {
	for i := 0; i < 1000; i++ {
		privateKey, publicKey, err := KemKeypair1024()
		if err != nil {
			t.Error(err)
		}
		ciphertext, ssA, err := KemEncrypt1024(publicKey)
		if err != nil {
			t.Error(err)
		}
		ssB, err := KemDecrypt1024(ciphertext, privateKey)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(ssA[:], ssB[:]) == 0 {
			t.Errorf("ML-KEM-1024 self-test failed at iteration %d", i)
		}
	}
}

// Benchmark test keys - generated once at startup
var benchKey512sk, benchKey512pk, _ = KemKeypair512()
var benchKey768sk, benchKey768pk, _ = KemKeypair768()
var benchKey1024sk, benchKey1024pk, _ = KemKeypair1024()
var benchCt512, _, _ = KemEncrypt512(benchKey512pk)
var benchCt768, _, _ = KemEncrypt768(benchKey768pk)
var benchCt1024, _, _ = KemEncrypt1024(benchKey1024pk)

func BenchmarkKemKeypair512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _, err := KemKeypair512()
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkKemKeypair768(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _, err := KemKeypair768()
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkKemKeypair1024(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _, err := KemKeypair1024()
		if err != nil {
			b.Error(err)
		}
	}
}

func BenchmarkKemEncrypt512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _, _ = KemEncrypt512(benchKey512pk)
	}
}

func BenchmarkKemEncrypt768(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _, _ = KemEncrypt768(benchKey768pk)
	}
}

func BenchmarkKemEncrypt1024(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _, _ = KemEncrypt1024(benchKey1024pk)
	}
}

func BenchmarkKemDecrypt512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = KemDecrypt512(benchCt512, benchKey512sk)
	}
}

func BenchmarkKemDecrypt768(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = KemDecrypt768(benchCt768, benchKey768sk)
	}
}

func BenchmarkKemDecrypt1024(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = KemDecrypt1024(benchCt1024, benchKey1024sk)
	}
}
