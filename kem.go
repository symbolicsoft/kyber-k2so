/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

// Package kyberk2so providesis a clean implementation of the Kyber IND-CCA2-secure
// key encapsulation mechanism (KEM), whose security is based on the hardness of
// solving the learning-with-errors (LWE) problem over module lattices.
package kyberk2so

import (
	"crypto/rand"
	"crypto/subtle"

	"golang.org/x/crypto/sha3"
)

// KemKeypair512 returns a Kyber-512 private key
// and a corresponding Kyber-512 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair512() ([paramsSecretKeyBytesK2]byte, [paramsPublicKeyBytesK2]byte, error) {
	const paramsK = 2
	var privateKeyFixedLength [paramsSecretKeyBytesK2]byte
	var publicKeyFixedLength [paramsPublicKeyBytesK2]byte
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

// KemKeypair768 returns a Kyber-768 private key
// and a corresponding Kyber-768 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair768() ([paramsSecretKeyBytesK3]byte, [paramsPublicKeyBytesK3]byte, error) {
	const paramsK int = 3
	var privateKeyFixedLength [paramsSecretKeyBytesK3]byte
	var publicKeyFixedLength [paramsPublicKeyBytesK3]byte
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

// KemKeypair1024 returns a Kyber-1024 private key
// and a corresponding Kyber-1024 public key.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemKeypair1024() ([paramsSecretKeyBytesK4]byte, [paramsPublicKeyBytesK4]byte, error) {
	const paramsK int = 4
	var privateKeyFixedLength [paramsSecretKeyBytesK4]byte
	var publicKeyFixedLength [paramsPublicKeyBytesK4]byte
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
func KemEncrypt512(publicKey [paramsPublicKeyBytesK2]byte) (
	[paramsIndcpaBytesK2]byte, [paramsSSBytes]byte, error,
) {
	const paramsK int = 2
	var ciphertextFixedLength [paramsIndcpaBytesK2]byte
	var sharedSecretFixedLength [paramsSSBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	buf := make([]byte, 2*paramsSymBytes)
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	buf1 := sha3.Sum256(buf[:paramsSymBytes])
	buf2 := sha3.Sum256(publicKey[:])
	kr := sha3.Sum512(append(buf1[:], buf2[:]...))
	ciphertext, err := indcpaEncrypt(buf1[:], publicKey[:], kr[paramsSymBytes:], paramsK)
	krc := sha3.Sum256(ciphertext)
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krc[:]...))
	copy(ciphertextFixedLength[:], ciphertext)
	copy(sharedSecretFixedLength[:], sharedSecret)
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemEncrypt768 takes a public key (from KemKeypair768) as input and
// returns a ciphertext and a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemEncrypt768(publicKey [paramsPublicKeyBytesK3]byte) (
	[paramsIndcpaBytesK3]byte, [paramsSSBytes]byte, error,
) {
	const paramsK int = 3
	var ciphertextFixedLength [paramsIndcpaBytesK3]byte
	var sharedSecretFixedLength [paramsSSBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	buf := make([]byte, 2*paramsSymBytes)
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	buf1 := sha3.Sum256(buf[:paramsSymBytes])
	buf2 := sha3.Sum256(publicKey[:])
	kr := sha3.Sum512(append(buf1[:], buf2[:]...))
	ciphertext, err := indcpaEncrypt(buf1[:], publicKey[:], kr[paramsSymBytes:], paramsK)
	krc := sha3.Sum256(ciphertext)
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krc[:]...))
	copy(ciphertextFixedLength[:], ciphertext)
	copy(sharedSecretFixedLength[:], sharedSecret)
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemEncrypt1024 takes a public key (from KemKeypair1024) as input
// and returns a ciphertext and a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemEncrypt1024(publicKey [paramsPublicKeyBytesK4]byte) (
	[paramsIndcpaBytesK4]byte, [paramsSSBytes]byte, error,
) {
	const paramsK int = 4
	var ciphertextFixedLength [paramsIndcpaBytesK4]byte
	var sharedSecretFixedLength [paramsSSBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	buf := make([]byte, 2*paramsSymBytes)
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	buf1 := sha3.Sum256(buf[:paramsSymBytes])
	buf2 := sha3.Sum256(publicKey[:])
	kr := sha3.Sum512(append(buf1[:], buf2[:]...))
	ciphertext, err := indcpaEncrypt(buf1[:], publicKey[:], kr[paramsSymBytes:], paramsK)
	krc := sha3.Sum256(ciphertext)
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krc[:]...))
	copy(ciphertextFixedLength[:], ciphertext)
	copy(sharedSecretFixedLength[:], sharedSecret)
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemDecrypt512 takes a ciphertext (from KeyEncrypt512),
// a private key (from KemKeypair512) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemDecrypt512(
	ciphertext [paramsIndcpaBytesK2]byte,
	privateKey [paramsSecretKeyBytesK2]byte,
) ([paramsSymBytes]byte, error) {
	const paramsK int = 2
	var sharedSecretFixedLength [paramsSSBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK2]
	pki := paramsIndcpaSecretKeyBytesK2 + paramsIndcpaPublicKeyBytesK2
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK2:pki]
	buf := indcpaDecrypt(ciphertext[:], indcpaPrivateKey, paramsK)
	ski := paramsSecretKeyBytesK2 - 2*paramsSymBytes
	kr := sha3.Sum512(append(buf, privateKey[ski:ski+paramsSymBytes]...))
	cmp, err := indcpaEncrypt(buf, publicKey, kr[paramsSymBytes:], paramsK)
	fail := byte(1 - subtle.ConstantTimeCompare(ciphertext[:], cmp))
	krh := sha3.Sum256(ciphertext[:])
	for i := 0; i < paramsSymBytes; i++ {
		skx := privateKey[:paramsSecretKeyBytesK2-paramsSymBytes+i]
		kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]))
	}
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krh[:]...))
	copy(sharedSecretFixedLength[:], sharedSecret)
	return sharedSecretFixedLength, err
}

// KemDecrypt768 takes a ciphertext (from KeyEncrypt768),
// a private key (from KemKeypair768) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemDecrypt768(
	ciphertext [paramsIndcpaBytesK3]byte,
	privateKey [paramsSecretKeyBytesK3]byte,
) ([paramsSymBytes]byte, error) {
	const paramsK int = 3
	var sharedSecretFixedLength [paramsSSBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK3]
	pki := paramsIndcpaSecretKeyBytesK3 + paramsIndcpaPublicKeyBytesK3
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK3:pki]
	buf := indcpaDecrypt(ciphertext[:], indcpaPrivateKey, paramsK)
	ski := paramsSecretKeyBytesK3 - 2*paramsSymBytes
	kr := sha3.Sum512(append(buf, privateKey[ski:ski+paramsSymBytes]...))
	cmp, err := indcpaEncrypt(buf, publicKey, kr[paramsSymBytes:], paramsK)
	fail := byte(1 - subtle.ConstantTimeCompare(ciphertext[:], cmp))
	krh := sha3.Sum256(ciphertext[:])
	for i := 0; i < paramsSymBytes; i++ {
		skx := privateKey[:paramsSecretKeyBytesK3-paramsSymBytes+i]
		kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]))
	}
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krh[:]...))
	copy(sharedSecretFixedLength[:], sharedSecret)
	return sharedSecretFixedLength, err
}

// KemDecrypt1024 takes a ciphertext (from KeyEncrypt1024),
// a private key (from KemKeypair1024) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient
// randomness could be obtained from the system.
func KemDecrypt1024(
	ciphertext [paramsIndcpaBytesK4]byte,
	privateKey [paramsSecretKeyBytesK4]byte,
) ([paramsSymBytes]byte, error) {
	const paramsK int = 4
	var sharedSecretFixedLength [paramsSSBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytesK4]
	pki := paramsIndcpaSecretKeyBytesK4 + paramsIndcpaPublicKeyBytesK4
	publicKey := privateKey[paramsIndcpaSecretKeyBytesK4:pki]
	buf := indcpaDecrypt(ciphertext[:], indcpaPrivateKey, paramsK)
	ski := paramsSecretKeyBytesK4 - 2*paramsSymBytes
	kr := sha3.Sum512(append(buf, privateKey[ski:ski+paramsSymBytes]...))
	cmp, err := indcpaEncrypt(buf, publicKey, kr[paramsSymBytes:], paramsK)
	fail := byte(1 - subtle.ConstantTimeCompare(ciphertext[:], cmp))
	krh := sha3.Sum256(ciphertext[:])
	for i := 0; i < paramsSymBytes; i++ {
		skx := privateKey[:paramsSecretKeyBytesK4-paramsSymBytes+i]
		kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]))
	}
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krh[:]...))
	copy(sharedSecretFixedLength[:], sharedSecret)
	return sharedSecretFixedLength, err
}
