/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"crypto/subtle"
	"encoding/hex"
	"io/ioutil"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type kemTest512 struct {
	privateKey   [Kyber512SKBytes]byte
	publicKey    [Kyber512PKBytes]byte
	ciphertext   [Kyber512CTBytes]byte
	sharedSecret [KyberSSBytes]byte
}

type kemTest768 struct {
	privateKey   [Kyber768SKBytes]byte
	publicKey    [Kyber768PKBytes]byte
	ciphertext   [Kyber768CTBytes]byte
	sharedSecret [KyberSSBytes]byte
}

type kemTest1024 struct {
	privateKey   [Kyber1024SKBytes]byte
	publicKey    [Kyber1024PKBytes]byte
	ciphertext   [Kyber1024CTBytes]byte
	sharedSecret [KyberSSBytes]byte
}

var kemTests512, kemTests768, kemTests1024 = func() ([100]kemTest512, [100]kemTest768, [100]kemTest1024) {
	var kt512 [100]kemTest512
	var kt768 [100]kemTest768
	var kt1024 [100]kemTest1024
	rsps := [3]string{
		"PQCkemKAT_1632.rsp",
		"PQCkemKAT_2400.rsp",
		"PQCkemKAT_3168.rsp",
	}
	for r, rsp := range rsps {
		katPath := filepath.Join("assets", rsp)
		katBytes, err := ioutil.ReadFile(katPath)
		if err != nil {
			log.Fatal(err)
		}
		kat := string(katBytes)
		rPk := regexp.MustCompile(`pk = [A-F0-9]+\n`)
		rSk := regexp.MustCompile(`sk = [A-F0-9]+\n`)
		rCt := regexp.MustCompile(`ct = [A-F0-9]+\n`)
		rSs := regexp.MustCompile(`ss = [A-F0-9]+\n`)
		allPk := rPk.FindAllString(kat, -1)
		allSk := rSk.FindAllString(kat, -1)
		allCt := rCt.FindAllString(kat, -1)
		allSs := rSs.FindAllString(kat, -1)
		if len(allPk) != 100 {
			log.Fatal("not all public key test vectors were read")
		}
		if len(allSk) != 100 {
			log.Fatal("not all private key test vectors were read")
		}
		if len(allCt) != 100 {
			log.Fatal("not all ciphertext test vectors were read")
		}
		if len(allSs) != 100 {
			log.Fatal("not all shared secret test vectors were read")
		}
		for i := 0; i < len(allPk); i++ {
			switch r {
			case 0:
				var privateKey [Kyber512SKBytes]byte
				var publicKey [Kyber512PKBytes]byte
				var ciphertext [Kyber512CTBytes]byte
				var sharedSecret [KyberSSBytes]byte
				sk, err := hex.DecodeString(strings.TrimSuffix(allSk[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				pk, err := hex.DecodeString(strings.TrimSuffix(allPk[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				ct, err := hex.DecodeString(strings.TrimSuffix(allCt[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				ss, err := hex.DecodeString(strings.TrimSuffix(allSs[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				copy(privateKey[:], sk)
				copy(publicKey[:], pk)
				copy(ciphertext[:], ct)
				copy(sharedSecret[:], ss)
				kt512[i] = kemTest512{
					privateKey:   privateKey,
					publicKey:    publicKey,
					ciphertext:   ciphertext,
					sharedSecret: sharedSecret,
				}
			case 1:
				var privateKey [Kyber768SKBytes]byte
				var publicKey [Kyber768PKBytes]byte
				var ciphertext [Kyber768CTBytes]byte
				var sharedSecret [KyberSSBytes]byte
				sk, err := hex.DecodeString(strings.TrimSuffix(allSk[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				pk, err := hex.DecodeString(strings.TrimSuffix(allPk[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				ct, err := hex.DecodeString(strings.TrimSuffix(allCt[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				ss, err := hex.DecodeString(strings.TrimSuffix(allSs[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				copy(privateKey[:], sk)
				copy(publicKey[:], pk)
				copy(ciphertext[:], ct)
				copy(sharedSecret[:], ss)
				kt768[i] = kemTest768{
					privateKey:   privateKey,
					publicKey:    publicKey,
					ciphertext:   ciphertext,
					sharedSecret: sharedSecret,
				}
			case 2:
				var privateKey [Kyber1024SKBytes]byte
				var publicKey [Kyber1024PKBytes]byte
				var ciphertext [Kyber1024CTBytes]byte
				var sharedSecret [KyberSSBytes]byte
				sk, err := hex.DecodeString(strings.TrimSuffix(allSk[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				pk, err := hex.DecodeString(strings.TrimSuffix(allPk[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				ct, err := hex.DecodeString(strings.TrimSuffix(allCt[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				ss, err := hex.DecodeString(strings.TrimSuffix(allSs[i][5:], "\n"))
				if err != nil {
					log.Fatal(err)
				}
				copy(privateKey[:], sk)
				copy(publicKey[:], pk)
				copy(ciphertext[:], ct)
				copy(sharedSecret[:], ss)
				kt1024[i] = kemTest1024{
					privateKey:   privateKey,
					publicKey:    publicKey,
					ciphertext:   ciphertext,
					sharedSecret: sharedSecret,
				}
			}
		}
	}
	return kt512, kt768, kt1024
}()

func TestVectors512(t *testing.T) {
	for i, test := range kemTests512 {
		ssB, err := KemDecrypt512(test.ciphertext, test.privateKey)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(test.sharedSecret[:], ssB[:]) == 0 {
			t.Errorf("kyber-512 test vector %d failed", i)
		}
	}
}

func TestVectors768(t *testing.T) {
	for i, test := range kemTests768 {
		ssB, err := KemDecrypt768(test.ciphertext, test.privateKey)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(test.sharedSecret[:], ssB[:]) == 0 {
			t.Errorf("kyber-768 test vector %d failed", i)
		}
	}
}

func TestVectors1024(t *testing.T) {
	for i, test := range kemTests1024 {
		ssB, err := KemDecrypt1024(test.ciphertext, test.privateKey)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(test.sharedSecret[:], ssB[:]) == 0 {
			t.Errorf("kyber-1024 test vector %d failed", i)
		}
	}
}

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
			t.Errorf("kyber-512 self-test failed at iteration %d", i)
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
			t.Errorf("kyber-768 self-test failed at iteration %d", i)
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
			t.Errorf("kyber-1024 self-test failed at iteration %d", i)
		}
	}
}

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
		KemEncrypt512(kemTests512[n%99].publicKey)
	}
}

func BenchmarkKemEncrypt768(b *testing.B) {
	for n := 0; n < b.N; n++ {
		KemEncrypt768(kemTests768[n%99].publicKey)
	}
}

func BenchmarkKemEncrypt1024(b *testing.B) {
	for n := 0; n < b.N; n++ {
		KemEncrypt1024(kemTests1024[n%99].publicKey)
	}
}

func BenchmarkKemDecrypt512(b *testing.B) {
	for n := 0; n < b.N; n++ {
		KemDecrypt512(
			kemTests512[n%99].ciphertext,
			kemTests512[n%99].privateKey,
		)
	}
}

func BenchmarkKemDecrypt768(b *testing.B) {
	for n := 0; n < b.N; n++ {
		KemDecrypt768(
			kemTests768[n%99].ciphertext,
			kemTests768[n%99].privateKey,
		)
	}
}

func BenchmarkKemDecrypt1024(b *testing.B) {
	for n := 0; n < b.N; n++ {
		KemDecrypt1024(
			kemTests1024[n%99].ciphertext,
			kemTests1024[n%99].privateKey,
		)
	}
}
