/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

const paramsN int = 256
const paramsQ int = 3329
const paramsQinv int = 62209
const paramsETA int = 2
const paramsSymBytes int = 32
const paramsPolyBytes int = 384
const paramsPolyvecBytesK2 int = 2 * paramsPolyBytes
const paramsPolyvecBytesK3 int = 3 * paramsPolyBytes
const paramsPolyvecBytesK4 int = 4 * paramsPolyBytes
const paramsPolyCompressedBytesK2 int = 96
const paramsPolyCompressedBytesK3 int = 128
const paramsPolyCompressedBytesK4 int = 160
const paramsPolyvecCompressedBytesK2 int = 2 * 320
const paramsPolyvecCompressedBytesK3 int = 3 * 320
const paramsPolyvecCompressedBytesK4 int = 4 * 352
const paramsIndcpaPublicKeyBytesK2 int = paramsPolyvecBytesK2 + paramsSymBytes
const paramsIndcpaPublicKeyBytesK3 int = paramsPolyvecBytesK3 + paramsSymBytes
const paramsIndcpaPublicKeyBytesK4 int = paramsPolyvecBytesK4 + paramsSymBytes
const paramsIndcpaSecretKeyBytesK2 int = 2 * paramsPolyBytes
const paramsIndcpaSecretKeyBytesK3 int = 3 * paramsPolyBytes
const paramsIndcpaSecretKeyBytesK4 int = 4 * paramsPolyBytes

// Kyber512SKBytes is a constant representing the byte length of private keys in Kyber-512.
const Kyber512SKBytes int = paramsPolyvecBytesK2 + ((paramsPolyvecBytesK2 + paramsSymBytes) + 2*paramsSymBytes)

// Kyber768SKBytes is a constant representing the byte length of private keys in Kyber-768.
const Kyber768SKBytes int = paramsPolyvecBytesK3 + ((paramsPolyvecBytesK3 + paramsSymBytes) + 2*paramsSymBytes)

// Kyber1024SKBytes is a constant representing the byte length of private keys in Kyber-1024.
const Kyber1024SKBytes int = paramsPolyvecBytesK4 + ((paramsPolyvecBytesK4 + paramsSymBytes) + 2*paramsSymBytes)

// Kyber512PKBytes is a constant representing the byte length of public keys in Kyber-512.
const Kyber512PKBytes int = paramsPolyvecBytesK2 + paramsSymBytes

// Kyber768PKBytes is a constant representing the byte length of public keys in Kyber-768.
const Kyber768PKBytes int = paramsPolyvecBytesK3 + paramsSymBytes

// Kyber1024PKBytes is a constant representing the byte length of public keys in Kyber-1024.
const Kyber1024PKBytes int = paramsPolyvecBytesK4 + paramsSymBytes

// Kyber512CTBytes is a constant representing the byte length of ciphertexts in Kyber-512.
const Kyber512CTBytes int = paramsPolyvecCompressedBytesK2 + paramsPolyCompressedBytesK2

// Kyber768CTBytes is a constant representing the byte length of ciphertexts in Kyber-768.
const Kyber768CTBytes int = paramsPolyvecCompressedBytesK3 + paramsPolyCompressedBytesK3

// Kyber1024CTBytes is a constant representing the byte length of ciphertexts in Kyber-1024.
const Kyber1024CTBytes int = paramsPolyvecCompressedBytesK4 + paramsPolyCompressedBytesK4

// KyberSSBytes is a constant representing the byte length of shared secrets in Kyber.
const KyberSSBytes int = 32
