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
	"errors"

	"golang.org/x/crypto/sha3"
)

var (
	// ErrInvalidEncapsulationKey is returned when an encapsulation key
	// fails the modulus check per FIPS 203 §7.2.
	ErrInvalidEncapsulationKey = errors.New("kyberk2so: invalid encapsulation key")

	// ErrInvalidDecapsulationKey is returned when a decapsulation key
	// fails the hash check per FIPS 203 §7.3.
	ErrInvalidDecapsulationKey = errors.New("kyberk2so: invalid decapsulation key")
)

// KemKeypair512 returns an ML-KEM-512 private key
// and a corresponding ML-KEM-512 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair512() ([Kyber512SKBytes]byte, [Kyber512PKBytes]byte, error) {
	const paramsK = 2
	var privateKeyFixedLength [Kyber512SKBytes]byte
	var publicKeyFixedLength [Kyber512PKBytes]byte
	err := indcpaKeypair(
		privateKeyFixedLength[:paramsIndcpaSecretKeyBytesK512],
		publicKeyFixedLength[:],
		paramsK,
	)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	pkh := sha3.Sum256(publicKeyFixedLength[:])
	skStart := paramsIndcpaSecretKeyBytesK512
	skStart += copy(privateKeyFixedLength[skStart:], publicKeyFixedLength[:])
	skStart += copy(privateKeyFixedLength[skStart:], pkh[:])
	_, err = rand.Read(privateKeyFixedLength[skStart:])
	if err != nil {
		byteopsZeroBytes(privateKeyFixedLength[:])
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	return privateKeyFixedLength, publicKeyFixedLength, nil
}

// KemKeypair768 returns an ML-KEM-768 private key
// and a corresponding ML-KEM-768 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair768() ([Kyber768SKBytes]byte, [Kyber768PKBytes]byte, error) {
	const paramsK = 3
	var privateKeyFixedLength [Kyber768SKBytes]byte
	var publicKeyFixedLength [Kyber768PKBytes]byte
	err := indcpaKeypair(
		privateKeyFixedLength[:paramsIndcpaSecretKeyBytesK768],
		publicKeyFixedLength[:],
		paramsK,
	)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	pkh := sha3.Sum256(publicKeyFixedLength[:])
	skStart := paramsIndcpaSecretKeyBytesK768
	skStart += copy(privateKeyFixedLength[skStart:], publicKeyFixedLength[:])
	skStart += copy(privateKeyFixedLength[skStart:], pkh[:])
	_, err = rand.Read(privateKeyFixedLength[skStart:])
	if err != nil {
		byteopsZeroBytes(privateKeyFixedLength[:])
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	return privateKeyFixedLength, publicKeyFixedLength, nil
}

// KemKeypair1024 returns an ML-KEM-1024 private key
// and a corresponding ML-KEM-1024 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair1024() ([Kyber1024SKBytes]byte, [Kyber1024PKBytes]byte, error) {
	const paramsK = 4
	var privateKeyFixedLength [Kyber1024SKBytes]byte
	var publicKeyFixedLength [Kyber1024PKBytes]byte
	err := indcpaKeypair(
		privateKeyFixedLength[:paramsIndcpaSecretKeyBytesK1024],
		publicKeyFixedLength[:],
		paramsK,
	)
	if err != nil {
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	pkh := sha3.Sum256(publicKeyFixedLength[:])
	skStart := paramsIndcpaSecretKeyBytesK1024
	skStart += copy(privateKeyFixedLength[skStart:], publicKeyFixedLength[:])
	skStart += copy(privateKeyFixedLength[skStart:], pkh[:])
	_, err = rand.Read(privateKeyFixedLength[skStart:])
	if err != nil {
		byteopsZeroBytes(privateKeyFixedLength[:])
		return privateKeyFixedLength, publicKeyFixedLength, err
	}
	return privateKeyFixedLength, publicKeyFixedLength, nil
}

// KemEncrypt512 takes a public key (from KemKeypair512) as input
// and returns a ciphertext and a 32-byte shared secret.
// Per FIPS 203 §7.2, the encapsulation key is validated before use.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system or if the key is invalid.
func KemEncrypt512(publicKey [Kyber512PKBytes]byte) (
	[Kyber512CTBytes]byte, [KyberSSBytes]byte, error,
) {
	const paramsK = 2
	var ciphertextFixedLength [Kyber512CTBytes]byte
	var sharedSecretFixedLength [KyberSSBytes]byte
	if !polyvecBytesValid(publicKey[:paramsK*paramsPolyBytes], paramsK) {
		return ciphertextFixedLength, sharedSecretFixedLength, ErrInvalidEncapsulationKey
	}
	var m [paramsSymBytes]byte
	_, err := rand.Read(m[:])
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	pkh := sha3.Sum256(publicKey[:])
	var krInput [64]byte
	copy(krInput[:32], m[:])
	copy(krInput[32:], pkh[:])
	kr := sha3.Sum512(krInput[:])
	err = indcpaEncrypt(ciphertextFixedLength[:], m[:], publicKey[:], kr[paramsSymBytes:], paramsK)
	copy(sharedSecretFixedLength[:], kr[:paramsSymBytes])
	byteopsZeroBytes(m[:])
	byteopsZeroBytes(krInput[:])
	byteopsZeroBytes(kr[:])
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemEncrypt768 takes a public key (from KemKeypair768) as input and
// returns a ciphertext and a 32-byte shared secret.
// Per FIPS 203 §7.2, the encapsulation key is validated before use.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system or if the key is invalid.
func KemEncrypt768(publicKey [Kyber768PKBytes]byte) (
	[Kyber768CTBytes]byte, [KyberSSBytes]byte, error,
) {
	const paramsK = 3
	var ciphertextFixedLength [Kyber768CTBytes]byte
	var sharedSecretFixedLength [KyberSSBytes]byte
	if !polyvecBytesValid(publicKey[:paramsK*paramsPolyBytes], paramsK) {
		return ciphertextFixedLength, sharedSecretFixedLength, ErrInvalidEncapsulationKey
	}
	var m [paramsSymBytes]byte
	_, err := rand.Read(m[:])
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	pkh := sha3.Sum256(publicKey[:])
	var krInput [64]byte
	copy(krInput[:32], m[:])
	copy(krInput[32:], pkh[:])
	kr := sha3.Sum512(krInput[:])
	err = indcpaEncrypt(ciphertextFixedLength[:], m[:], publicKey[:], kr[paramsSymBytes:], paramsK)
	copy(sharedSecretFixedLength[:], kr[:paramsSymBytes])
	byteopsZeroBytes(m[:])
	byteopsZeroBytes(krInput[:])
	byteopsZeroBytes(kr[:])
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemEncrypt1024 takes a public key (from KemKeypair1024) as input
// and returns a ciphertext and a 32-byte shared secret.
// Per FIPS 203 §7.2, the encapsulation key is validated before use.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system or if the key is invalid.
func KemEncrypt1024(publicKey [Kyber1024PKBytes]byte) (
	[Kyber1024CTBytes]byte, [KyberSSBytes]byte, error,
) {
	const paramsK = 4
	var ciphertextFixedLength [Kyber1024CTBytes]byte
	var sharedSecretFixedLength [KyberSSBytes]byte
	if !polyvecBytesValid(publicKey[:paramsK*paramsPolyBytes], paramsK) {
		return ciphertextFixedLength, sharedSecretFixedLength, ErrInvalidEncapsulationKey
	}
	var m [paramsSymBytes]byte
	_, err := rand.Read(m[:])
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	pkh := sha3.Sum256(publicKey[:])
	var krInput [64]byte
	copy(krInput[:32], m[:])
	copy(krInput[32:], pkh[:])
	kr := sha3.Sum512(krInput[:])
	err = indcpaEncrypt(ciphertextFixedLength[:], m[:], publicKey[:], kr[paramsSymBytes:], paramsK)
	copy(sharedSecretFixedLength[:], kr[:paramsSymBytes])
	byteopsZeroBytes(m[:])
	byteopsZeroBytes(krInput[:])
	byteopsZeroBytes(kr[:])
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// kemDecapsInputCheck validates a decapsulation key per FIPS 203 §7.3.
// It verifies that H(dk[384k:768k+32]) == dk[768k+32:768k+64].
func kemDecapsInputCheck(dk []byte, paramsK int) bool {
	ekStart := paramsK * paramsPolyBytes
	ekEnd := ekStart + paramsK*paramsPolyBytes + paramsSymBytes
	hStart := ekEnd
	hEnd := hStart + paramsSymBytes
	computed := sha3.Sum256(dk[ekStart:ekEnd])
	return subtle.ConstantTimeCompare(computed[:], dk[hStart:hEnd]) == 1
}

// KemDecrypt512 takes a ciphertext (from KemEncrypt512),
// a private key (from KemKeypair512) and returns a 32-byte shared secret.
// Per FIPS 203 §7.3, the decapsulation key hash is validated before use.
func KemDecrypt512(
	ciphertext [Kyber512CTBytes]byte,
	privateKey [Kyber512SKBytes]byte,
) ([KyberSSBytes]byte, error) {
	const paramsK = 2
	var sharedSecretFixedLength [KyberSSBytes]byte
	if !kemDecapsInputCheck(privateKey[:], paramsK) {
		return sharedSecretFixedLength, ErrInvalidDecapsulationKey
	}
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK512]
	pki := paramsIndcpaSecretKeyBytesK512 + paramsIndcpaPublicKeyBytesK512
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK512:pki]
	h := privateKey[pki : pki+paramsSymBytes]
	z := privateKey[Kyber512SKBytes-paramsSymBytes:]
	var mPrime [paramsSymBytes]byte
	indcpaDecrypt(mPrime[:], ciphertext[:], indcpaPrivateKey, paramsK)
	var krInput [64]byte
	copy(krInput[:32], mPrime[:])
	copy(krInput[32:], h)
	kr := sha3.Sum512(krInput[:])
	var kBar [KyberSSBytes]byte
	var jInput [paramsSymBytes + Kyber512CTBytes]byte
	copy(jInput[:paramsSymBytes], z)
	copy(jInput[paramsSymBytes:], ciphertext[:])
	sha3.ShakeSum256(kBar[:], jInput[:])
	var cmp [Kyber512CTBytes]byte
	err := indcpaEncrypt(cmp[:], mPrime[:], publicKey, kr[paramsSymBytes:], paramsK)
	fail := byte(subtle.ConstantTimeCompare(ciphertext[:], cmp[:]) - 1)
	for i := 0; i < KyberSSBytes; i++ {
		sharedSecretFixedLength[i] = kr[i] ^ (fail & (kr[i] ^ kBar[i]))
	}
	byteopsZeroBytes(mPrime[:])
	byteopsZeroBytes(krInput[:])
	byteopsZeroBytes(kr[:])
	byteopsZeroBytes(kBar[:])
	byteopsZeroBytes(jInput[:])
	byteopsZeroBytes(cmp[:])
	return sharedSecretFixedLength, err
}

// KemDecrypt768 takes a ciphertext (from KemEncrypt768),
// a private key (from KemKeypair768) and returns a 32-byte shared secret.
// Per FIPS 203 §7.3, the decapsulation key hash is validated before use.
func KemDecrypt768(
	ciphertext [Kyber768CTBytes]byte,
	privateKey [Kyber768SKBytes]byte,
) ([KyberSSBytes]byte, error) {
	const paramsK = 3
	var sharedSecretFixedLength [KyberSSBytes]byte
	if !kemDecapsInputCheck(privateKey[:], paramsK) {
		return sharedSecretFixedLength, ErrInvalidDecapsulationKey
	}
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK768]
	pki := paramsIndcpaSecretKeyBytesK768 + paramsIndcpaPublicKeyBytesK768
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK768:pki]
	h := privateKey[pki : pki+paramsSymBytes]
	z := privateKey[Kyber768SKBytes-paramsSymBytes:]
	var mPrime [paramsSymBytes]byte
	indcpaDecrypt(mPrime[:], ciphertext[:], indcpaPrivateKey, paramsK)
	var krInput [64]byte
	copy(krInput[:32], mPrime[:])
	copy(krInput[32:], h)
	kr := sha3.Sum512(krInput[:])
	var kBar [KyberSSBytes]byte
	var jInput [paramsSymBytes + Kyber768CTBytes]byte
	copy(jInput[:paramsSymBytes], z)
	copy(jInput[paramsSymBytes:], ciphertext[:])
	sha3.ShakeSum256(kBar[:], jInput[:])
	var cmp [Kyber768CTBytes]byte
	err := indcpaEncrypt(cmp[:], mPrime[:], publicKey, kr[paramsSymBytes:], paramsK)
	fail := byte(subtle.ConstantTimeCompare(ciphertext[:], cmp[:]) - 1)
	for i := 0; i < KyberSSBytes; i++ {
		sharedSecretFixedLength[i] = kr[i] ^ (fail & (kr[i] ^ kBar[i]))
	}
	byteopsZeroBytes(mPrime[:])
	byteopsZeroBytes(krInput[:])
	byteopsZeroBytes(kr[:])
	byteopsZeroBytes(kBar[:])
	byteopsZeroBytes(jInput[:])
	byteopsZeroBytes(cmp[:])
	return sharedSecretFixedLength, err
}

// KemDecrypt1024 takes a ciphertext (from KemEncrypt1024),
// a private key (from KemKeypair1024) and returns a 32-byte shared secret.
// Per FIPS 203 §7.3, the decapsulation key hash is validated before use.
func KemDecrypt1024(
	ciphertext [Kyber1024CTBytes]byte,
	privateKey [Kyber1024SKBytes]byte,
) ([KyberSSBytes]byte, error) {
	const paramsK = 4
	var sharedSecretFixedLength [KyberSSBytes]byte
	if !kemDecapsInputCheck(privateKey[:], paramsK) {
		return sharedSecretFixedLength, ErrInvalidDecapsulationKey
	}
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK1024]
	pki := paramsIndcpaSecretKeyBytesK1024 + paramsIndcpaPublicKeyBytesK1024
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK1024:pki]
	h := privateKey[pki : pki+paramsSymBytes]
	z := privateKey[Kyber1024SKBytes-paramsSymBytes:]
	var mPrime [paramsSymBytes]byte
	indcpaDecrypt(mPrime[:], ciphertext[:], indcpaPrivateKey, paramsK)
	var krInput [64]byte
	copy(krInput[:32], mPrime[:])
	copy(krInput[32:], h)
	kr := sha3.Sum512(krInput[:])
	var kBar [KyberSSBytes]byte
	var jInput [paramsSymBytes + Kyber1024CTBytes]byte
	copy(jInput[:paramsSymBytes], z)
	copy(jInput[paramsSymBytes:], ciphertext[:])
	sha3.ShakeSum256(kBar[:], jInput[:])
	var cmp [Kyber1024CTBytes]byte
	err := indcpaEncrypt(cmp[:], mPrime[:], publicKey, kr[paramsSymBytes:], paramsK)
	fail := byte(subtle.ConstantTimeCompare(ciphertext[:], cmp[:]) - 1)
	for i := 0; i < KyberSSBytes; i++ {
		sharedSecretFixedLength[i] = kr[i] ^ (fail & (kr[i] ^ kBar[i]))
	}
	byteopsZeroBytes(mPrime[:])
	byteopsZeroBytes(krInput[:])
	byteopsZeroBytes(kr[:])
	byteopsZeroBytes(kBar[:])
	byteopsZeroBytes(jInput[:])
	byteopsZeroBytes(cmp[:])
	return sharedSecretFixedLength, err
}
