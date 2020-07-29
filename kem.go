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
func KemKeypair() ([]byte, []byte, error) {
	indcpaPrivateKey, indcpaPublicKey, err := indcpaKeypair()
	if err != nil {
		return []byte{}, []byte{}, err
	}
	pkh := sha3.Sum256(indcpaPublicKey)
	rnd := make([]byte, params.symbytes)
	_, err = rand.Read(rnd)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	privateKey := append(indcpaPrivateKey, indcpaPublicKey...)
	privateKey = append(privateKey, pkh[:]...)
	privateKey = append(privateKey, rnd...)
	return privateKey, indcpaPublicKey, nil
}

// KemEncrypt takes a public key (from KemKeypair) as input and returns a ciphertext and a 32-byte shared secret.
// An accompanying error is returned if no sufficient randomness could be obtained from the system.
func KemEncrypt(publicKey []byte) ([]byte, []byte, error) {
	sharedSecret := make([]byte, params.symbytes)
	buf := make([]byte, 2*params.symbytes)
	_, err := rand.Read(buf[:params.symbytes])
	if err != nil {
		return []byte{}, []byte{}, err
	}
	buf1 := sha3.Sum256(buf[:params.symbytes])
	buf2 := sha3.Sum256(publicKey)
	kr := sha3.Sum512(append(buf1[:], buf2[:]...))
	ciphertext, err := indcpaEncrypt(buf1[:], publicKey, kr[params.symbytes:])
	krc := sha3.Sum256(ciphertext)
	sha3.ShakeSum256(sharedSecret, append(kr[:params.symbytes], krc[:]...))
	return ciphertext, sharedSecret, err
}

// KemDecrypt takes a ciphertext (from KeyEncrypt), a private key (from KemKeypair) and returns a 32-byte shared secret.
// An accompanying error is returned if no sufficient randomness could be obtained from the system.
func KemDecrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	sharedSecret := make([]byte, params.symbytes)
	indcpaPrivateKey := privateKey[:params.indcpasecretkeybytes]
	pki := params.indcpasecretkeybytes + params.indcpapublickeybytes
	publicKey := privateKey[params.indcpasecretkeybytes:pki]
	buf := indcpaDecrypt(ciphertext, indcpaPrivateKey)
	ski := params.secretkeybytes - 2*params.symbytes
	kr := sha3.Sum512(append(buf, privateKey[ski:ski+params.symbytes]...))
	cmp, err := indcpaEncrypt(buf, publicKey, kr[params.symbytes:])
	fail := byte(1 - subtle.ConstantTimeCompare(ciphertext, cmp))
	krh := sha3.Sum256(ciphertext)
	for i := 0; i < params.symbytes; i++ {
		skx := privateKey[:params.secretkeybytes-params.symbytes+i]
		kr[i] = kr[i] ^ (fail & (kr[i] ^ skx[i]))
	}
	sha3.ShakeSum256(sharedSecret, append(kr[:params.symbytes], krh[:]...))
	return sharedSecret, err
}
