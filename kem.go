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

// KemKeypair returns a Kyber-768 private key and a corresponding Kyber-768 public key.
// An accompanying error is returned if no sufficient randomness could be obtained from the system.
func KemKeypair() ([paramsSecretKeyBytes]byte, [paramsPublicKeyBytes]byte, error) {
	var privateKeyFixedLength [paramsSecretKeyBytes]byte
	var publicKeyFixedLength [paramsPublicKeyBytes]byte
	indcpaPrivateKey, indcpaPublicKey, err := indcpaKeypair()
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

// KemEncrypt takes a public key (from KemKeypair) as input and returns a ciphertext and a 32-byte shared secret.
// An accompanying error is returned if no sufficient randomness could be obtained from the system.
func KemEncrypt(publicKey [paramsPublicKeyBytes]byte) ([paramsIndcpaBytes]byte, [paramsSymBytes]byte, error) {
	var ciphertextFixedLength [paramsIndcpaBytes]byte
	var sharedSecretFixedLength [paramsSymBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	buf := make([]byte, 2*paramsSymBytes)
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return ciphertextFixedLength, sharedSecretFixedLength, err
	}
	buf1 := sha3.Sum256(buf[:paramsSymBytes])
	buf2 := sha3.Sum256(publicKey[:])
	kr := sha3.Sum512(append(buf1[:], buf2[:]...))
	ciphertext, err := indcpaEncrypt(buf1[:], publicKey[:], kr[paramsSymBytes:])
	krc := sha3.Sum256(ciphertext)
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krc[:]...))
	copy(ciphertextFixedLength[:], ciphertext)
	copy(sharedSecretFixedLength[:], sharedSecret)
	return ciphertextFixedLength, sharedSecretFixedLength, err
}

// KemDecrypt takes a ciphertext (from KeyEncrypt), a private key (from KemKeypair) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient randomness could be obtained from the system.
func KemDecrypt(
	ciphertext [paramsIndcpaBytes]byte,
	privateKey [paramsSecretKeyBytes]byte,
) ([paramsSymBytes]byte, error) {
	var sharedSecretFixedLength [paramsSymBytes]byte
	sharedSecret := make([]byte, paramsSymBytes)
	indcpaPrivateKey := privateKey[:paramsIndcpaSecretKeyBytes]
	pki := paramsIndcpaSecretKeyBytes + paramsIndcpaPublicKeyBytes
	publicKey := privateKey[paramsIndcpaSecretKeyBytes:pki]
	buf := indcpaDecrypt(ciphertext[:], indcpaPrivateKey)
	ski := paramsSecretKeyBytes - 2*paramsSymBytes
	kr := sha3.Sum512(append(buf, privateKey[ski:ski+paramsSymBytes]...))
	cmp, err := indcpaEncrypt(buf, publicKey, kr[paramsSymBytes:])
	fail := byte(1 - subtle.ConstantTimeCompare(ciphertext[:], cmp))
	krh := sha3.Sum256(ciphertext[:])
	for i := 0; i < paramsSymBytes; i++ {
		skx := privateKey[:paramsSecretKeyBytes-paramsSymBytes+i]
		kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]))
	}
	sha3.ShakeSum256(sharedSecret, append(kr[:paramsSymBytes], krh[:]...))
	copy(sharedSecretFixedLength[:], sharedSecret)
	return sharedSecretFixedLength, err
}
