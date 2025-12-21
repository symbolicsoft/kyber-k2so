/* SPDX-FileCopyrightText: © 2020-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

// Package kyberk2so provides a clean implementation of ML-KEM (FIPS 203),
// a module-lattice-based key encapsulation mechanism (KEM) whose security
// is based on the hardness of solving the learning-with-errors (LWE) problem
// over module lattices.
package kyberk2so

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"
)

// KemKeypair512 returns an ML-KEM-512 private key
// and a corresponding ML-KEM-512 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair512() ([Kyber512SKBytes]byte, [Kyber512PKBytes]byte, error) {
	const paramsK = 2
	var privateKeyFixedLength [Kyber512SKBytes]byte
	var publicKeyFixedLength [Kyber512PKBytes]byte
	indcpaPrivateKey, indcpaPublicKey, err := indcpaKeypair(paramsK)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	pkh := sha3.Sum256(indcpaPublicKey)
	rnd := make([]byte, paramsSymBytes)
	_, err = rand.Read(rnd)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	privateKey := append(indcpaPrivateKey, indcpaPublicKey...)
	privateKey = append(privateKey, pkh[:]...)
	privateKey = append(privateKey, rnd...)
	copy(privateKeyFixedLength[:], privateKey)
	copy(publicKeyFixedLength[:], indcpaPublicKey)
	return privateKeyFixedLength, publicKeyFixedLength, nil
}

// KemKeypair768 returns an ML-KEM-768 private key
// and a corresponding ML-KEM-768 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair768() ([Kyber768SKBytes]byte, [Kyber768PKBytes]byte, error) {
	const paramsK int = 3
	var privateKeyFixedLength [Kyber768SKBytes]byte
	var publicKeyFixedLength [Kyber768PKBytes]byte
	indcpaPrivateKey, indcpaPublicKey, err := indcpaKeypair(paramsK)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	pkh := sha3.Sum256(indcpaPublicKey)
	rnd := make([]byte, paramsSymBytes)
	_, err = rand.Read(rnd)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	privateKey := append(indcpaPrivateKey, indcpaPublicKey...)
	privateKey = append(privateKey, pkh[:]...)
	privateKey = append(privateKey, rnd...)
	copy(privateKeyFixedLength[:], privateKey)
	copy(publicKeyFixedLength[:], indcpaPublicKey)
	return privateKeyFixedLength, publicKeyFixedLength, nil
}

// KemKeypair1024 returns an ML-KEM-1024 private key
// and a corresponding ML-KEM-1024 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair1024() ([Kyber1024SKBytes]byte, [Kyber1024PKBytes]byte, error) {
	const paramsK int = 4
	var privateKeyFixedLength [Kyber1024SKBytes]byte
	var publicKeyFixedLength [Kyber1024PKBytes]byte
	indcpaPrivateKey, indcpaPublicKey, err := indcpaKeypair(paramsK)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	pkh := sha3.Sum256(indcpaPublicKey)
	rnd := make([]byte, paramsSymBytes)
	_, err = rand.Read(rnd)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	privateKey := append(indcpaPrivateKey, indcpaPublicKey...)
	privateKey = append(privateKey, pkh[:]...)
	privateKey = append(privateKey, rnd...)
	copy(privateKeyFixedLength[:], privateKey)
	copy(publicKeyFixedLength[:], indcpaPublicKey)
	return privateKeyFixedLength, publicKeyFixedLength, nil
}

// KemEncrypt512 takes a public key (from KemKeypair512) as input
// and returns a ciphertext and a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemEncrypt512(publicKey [Kyber512PKBytes]byte) (
	[Kyber512CTBytes]byte, [KyberSSBytes]byte, error,
) {
	const paramsK int = 2
	var ciphertextFixedLength [Kyber512CTBytes]byte
	var sharedSecretFixedLength [KyberSSBytes]byte
	m := make([]byte, paramsSymBytes)
	_, err := rand.Read(m)
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	pkh := sha3.Sum256(publicKey[:])
	kr := sha3.Sum512(append(m, pkh[:]...))
	ciphertext, err := indcpaEncrypt(m, publicKey[:], kr[paramsSymBytes:], paramsK)
	copy(ciphertextFixedLength[:], ciphertext)
	copy(sharedSecretFixedLength[:], kr[:paramsSymBytes])
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemEncrypt768 takes a public key (from KemKeypair768) as input and
// returns a ciphertext and a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemEncrypt768(publicKey [Kyber768PKBytes]byte) (
	[Kyber768CTBytes]byte, [KyberSSBytes]byte, error,
) {
	const paramsK int = 3
	var ciphertextFixedLength [Kyber768CTBytes]byte
	var sharedSecretFixedLength [KyberSSBytes]byte
	m := make([]byte, paramsSymBytes)
	_, err := rand.Read(m)
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	pkh := sha3.Sum256(publicKey[:])
	kr := sha3.Sum512(append(m, pkh[:]...))
	ciphertext, err := indcpaEncrypt(m, publicKey[:], kr[paramsSymBytes:], paramsK)
	copy(ciphertextFixedLength[:], ciphertext)
	copy(sharedSecretFixedLength[:], kr[:paramsSymBytes])
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemEncrypt1024 takes a public key (from KemKeypair1024) as input
// and returns a ciphertext and a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemEncrypt1024(publicKey [Kyber1024PKBytes]byte) (
	[Kyber1024CTBytes]byte, [KyberSSBytes]byte, error,
) {
	const paramsK int = 4
	var ciphertextFixedLength [Kyber1024CTBytes]byte
	var sharedSecretFixedLength [KyberSSBytes]byte
	m := make([]byte, paramsSymBytes)
	_, err := rand.Read(m)
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	pkh := sha3.Sum256(publicKey[:])
	kr := sha3.Sum512(append(m, pkh[:]...))
	ciphertext, err := indcpaEncrypt(m, publicKey[:], kr[paramsSymBytes:], paramsK)
	copy(ciphertextFixedLength[:], ciphertext)
	copy(sharedSecretFixedLength[:], kr[:paramsSymBytes])
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemDecrypt512 takes a ciphertext (from KeyEncrypt512),
// a private key (from KemKeypair512) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemDecrypt512(
	ciphertext [Kyber512CTBytes]byte,
	privateKey [Kyber512SKBytes]byte,
) ([KyberSSBytes]byte, error) {
	const paramsK int = 2
	var sharedSecretFixedLength [KyberSSBytes]byte
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK512]
	pki := paramsIndcpaSecretKeyBytesK512 + paramsIndcpaPublicKeyBytesK512
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK512:pki]
	hStart := pki
	h := privateKey[hStart : hStart+paramsSymBytes]
	z := privateKey[Kyber512SKBytes-paramsSymBytes:]
	mPrime := indcpaDecrypt(ciphertext[:], indcpaPrivateKey, paramsK)
	kr := sha3.Sum512(append(mPrime, h...))
	kPrime := kr[:paramsSymBytes]
	rPrime := kr[paramsSymBytes:]
	kBar := make([]byte, KyberSSBytes)
	sha3.ShakeSum256(kBar, append(z, ciphertext[:]...))
	cmp, err := indcpaEncrypt(mPrime, publicKey, rPrime, paramsK)
	fail := byte(subtle.ConstantTimeCompare(ciphertext[:], cmp) - 1)
	for i := 0; i < KyberSSBytes; i++ {
		sharedSecretFixedLength[i] = kPrime[i] ^ (fail & (kPrime[i] ^ kBar[i]))
	}
	return sharedSecretFixedLength, err
}

// KemDecrypt768 takes a ciphertext (from KeyEncrypt768),
// a private key (from KemKeypair768) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemDecrypt768(
	ciphertext [Kyber768CTBytes]byte,
	privateKey [Kyber768SKBytes]byte,
) ([KyberSSBytes]byte, error) {
	const paramsK int = 3
	var sharedSecretFixedLength [KyberSSBytes]byte
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK768]
	pki := paramsIndcpaSecretKeyBytesK768 + paramsIndcpaPublicKeyBytesK768
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK768:pki]
	hStart := pki
	h := privateKey[hStart : hStart+paramsSymBytes]
	z := privateKey[Kyber768SKBytes-paramsSymBytes:]
	mPrime := indcpaDecrypt(ciphertext[:], indcpaPrivateKey, paramsK)
	kr := sha3.Sum512(append(mPrime, h...))
	kPrime := kr[:paramsSymBytes]
	rPrime := kr[paramsSymBytes:]
	kBar := make([]byte, KyberSSBytes)
	sha3.ShakeSum256(kBar, append(z, ciphertext[:]...))
	cmp, err := indcpaEncrypt(mPrime, publicKey, rPrime, paramsK)
	fail := byte(subtle.ConstantTimeCompare(ciphertext[:], cmp) - 1)
	for i := 0; i < KyberSSBytes; i++ {
		sharedSecretFixedLength[i] = kPrime[i] ^ (fail & (kPrime[i] ^ kBar[i]))
	}
	return sharedSecretFixedLength, err
}

// KemDecrypt1024 takes a ciphertext (from KeyEncrypt1024),
// a private key (from KemKeypair1024) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemDecrypt1024(
	ciphertext [Kyber1024CTBytes]byte,
	privateKey [Kyber1024SKBytes]byte,
) ([KyberSSBytes]byte, error) {
	const paramsK int = 4
	var sharedSecretFixedLength [KyberSSBytes]byte
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK1024]
	pki := paramsIndcpaSecretKeyBytesK1024 + paramsIndcpaPublicKeyBytesK1024
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK1024:pki]
	hStart := pki
	h := privateKey[hStart : hStart+paramsSymBytes]
	z := privateKey[Kyber1024SKBytes-paramsSymBytes:]
	mPrime := indcpaDecrypt(ciphertext[:], indcpaPrivateKey, paramsK)
	kr := sha3.Sum512(append(mPrime, h...))
	kPrime := kr[:paramsSymBytes]
	rPrime := kr[paramsSymBytes:]
	kBar := make([]byte, KyberSSBytes)
	sha3.ShakeSum256(kBar, append(z, ciphertext[:]...))
	cmp, err := indcpaEncrypt(mPrime, publicKey, rPrime, paramsK)
	fail := byte(subtle.ConstantTimeCompare(ciphertext[:], cmp) - 1)
	for i := 0; i < KyberSSBytes; i++ {
		sharedSecretFixedLength[i] = kPrime[i] ^ (fail & (kPrime[i] ^ kBar[i]))
	}
	return sharedSecretFixedLength, err
}
