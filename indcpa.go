/* SPDX-FileCopyrightText: © 2020-2026 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

// indcpaPackPublicKey serializes the public key as a concatenation of the
// serialized vector of polynomials of the public key, and the public seed
// used to generate the matrix `A`.
func indcpaPackPublicKey(publicKey polyvec, seed []byte, paramsK int) []byte {
	return append(polyvecToBytes(publicKey, paramsK), seed...)
}

// indcpaUnpackPublicKey de-serializes the public key from a byte array
// and represents the approximate inverse of indcpaPackPublicKey.
func indcpaUnpackPublicKey(packedPublicKey []byte, paramsK int) (polyvec, []byte) {
	switch paramsK {
	case 2:
		publicKeyPolyvec := polyvecFromBytes(packedPublicKey[:paramsPolyvecBytesK512], paramsK)
		seed := packedPublicKey[paramsPolyvecBytesK512:]
		return publicKeyPolyvec, seed
	case 3:
		publicKeyPolyvec := polyvecFromBytes(packedPublicKey[:paramsPolyvecBytesK768], paramsK)
		seed := packedPublicKey[paramsPolyvecBytesK768:]
		return publicKeyPolyvec, seed
	default:
		publicKeyPolyvec := polyvecFromBytes(packedPublicKey[:paramsPolyvecBytesK1024], paramsK)
		seed := packedPublicKey[paramsPolyvecBytesK1024:]
		return publicKeyPolyvec, seed
	}
}

// indcpaPackPrivateKey serializes the private key.
func indcpaPackPrivateKey(privateKey polyvec, paramsK int) []byte {
	return polyvecToBytes(privateKey, paramsK)
}

// indcpaUnpackPrivateKey de-serializes the private key and represents
// the inverse of indcpaPackPrivateKey.
func indcpaUnpackPrivateKey(packedPrivateKey []byte, paramsK int) polyvec {
	return polyvecFromBytes(packedPrivateKey, paramsK)
}

// indcpaPackCiphertext serializes the ciphertext as a concatenation of
// the compressed and serialized vector of polynomials `b` and the
// compressed and serialized polynomial `v`.
func indcpaPackCiphertext(b polyvec, v poly, paramsK int) []byte {
	return append(polyvecCompress(b, paramsK), polyCompress(v, paramsK)...)
}

// indcpaUnpackCiphertext de-serializes and decompresses the ciphertext
// from a byte array, and represents the approximate inverse of
// indcpaPackCiphertext.
func indcpaUnpackCiphertext(c []byte, paramsK int) (polyvec, poly) {
	switch paramsK {
	case 2:
		b := polyvecDecompress(c[:paramsPolyvecCompressedBytesK512], paramsK)
		v := polyDecompress(c[paramsPolyvecCompressedBytesK512:], paramsK)
		return b, v
	case 3:
		b := polyvecDecompress(c[:paramsPolyvecCompressedBytesK768], paramsK)
		v := polyDecompress(c[paramsPolyvecCompressedBytesK768:], paramsK)
		return b, v
	default:
		b := polyvecDecompress(c[:paramsPolyvecCompressedBytesK1024], paramsK)
		v := polyDecompress(c[paramsPolyvecCompressedBytesK1024:], paramsK)
		return b, v
	}
}

// indcpaRejUniform runs rejection sampling on uniform random bytes
// to generate uniform random integers modulo `Q`.
func indcpaRejUniform(buf []byte, bufl int, l int) (poly, int) {
	var r poly
	var d1 uint16
	var d2 uint16
	i := 0
	j := 0
	for i < l && j+3 <= bufl {
		d1 = (uint16((buf[j])>>0) | (uint16(buf[j+1]) << 8)) & 0xFFF
		d2 = (uint16((buf[j+1])>>4) | (uint16(buf[j+2]) << 4)) & 0xFFF
		j += 3
		if d1 < uint16(paramsQ) {
			r[i] = int16(d1)
			i++
		}
		if i < l && d2 < uint16(paramsQ) {
			r[i] = int16(d2)
			i++
		}
	}
	return r, i
}

// indcpaGenMatrix deterministically generates a matrix `A` (or the transpose of `A`)
// from a seed. Entries of the matrix are polynomials that look uniformly random.
// Performs rejection sampling on the output of an extendable-output function (XOF).
func indcpaGenMatrix(seed []byte, transposed bool, paramsK int) ([]polyvec, error) {
	r := make([]polyvec, paramsK)
	var buf [672]byte
	var xofInput [34]byte
	copy(xofInput[:32], seed)
	xof := sha3.NewShake128()
	ctr := 0
	for i := 0; i < paramsK; i++ {
		r[i] = polyvecNew(paramsK)
		for j := 0; j < paramsK; j++ {
			xof.Reset()
			if transposed {
				xofInput[32] = byte(i)
				xofInput[33] = byte(j)
			} else {
				xofInput[32] = byte(j)
				xofInput[33] = byte(i)
			}
			_, err := xof.Write(xofInput[:])
			if err != nil {
				return nil, err
			}
			_, err = xof.Read(buf[:])
			if err != nil {
				return nil, err
			}
			r[i][j], ctr = indcpaRejUniform(buf[:504], 504, paramsN)
			// Retry with remaining buffer bytes if needed
			// Bound iterations as a safety measure (probability of needing >1 iteration is ~10^-82)
			for iterations := 0; ctr < paramsN && iterations < 100; iterations++ {
				missing, ctrn := indcpaRejUniform(buf[504:], 168, paramsN-ctr)
				for k := ctr; k < paramsN; k++ {
					r[i][j][k] = missing[k-ctr]
				}
				ctr += ctrn
			}
		}
	}
	return r, nil
}

// indcpaPrf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
func indcpaPrf(l int, key []byte, nonce byte) []byte {
	hash := make([]byte, l)
	var prfInput [33]byte
	copy(prfInput[:32], key)
	prfInput[32] = nonce
	sha3.ShakeSum256(hash, prfInput[:])
	return hash
}

// indcpaKeypair generates public and private keys for the CPA-secure
// public-key encryption scheme underlying Kyber.
func indcpaKeypair(paramsK int) ([]byte, []byte, error) {
	skpv := polyvecNew(paramsK)
	pkpv := polyvecNew(paramsK)
	e := polyvecNew(paramsK)
	var buf [64]byte
	var hashInput [33]byte
	h := sha3.New512()
	_, err := rand.Read(hashInput[:paramsSymBytes])
	if err != nil {
		return nil, nil, err
	}
	hashInput[32] = byte(paramsK)
	_, err = h.Write(hashInput[:])
	if err != nil {
		return nil, nil, err
	}
	h.Sum(buf[:0])
	var publicSeed [paramsSymBytes]byte
	var noiseSeed [paramsSymBytes]byte
	copy(publicSeed[:], buf[:paramsSymBytes])
	copy(noiseSeed[:], buf[paramsSymBytes:])
	a, err := indcpaGenMatrix(publicSeed[:], false, paramsK)
	if err != nil {
		return nil, nil, err
	}
	var nonce byte
	for i := 0; i < paramsK; i++ {
		skpv[i] = polyGetNoise(noiseSeed[:], nonce, paramsK)
		nonce++
	}
	for i := 0; i < paramsK; i++ {
		e[i] = polyGetNoise(noiseSeed[:], nonce, paramsK)
		nonce++
	}
	polyvecNtt(skpv, paramsK)
	polyvecReduce(skpv, paramsK)
	polyvecNtt(e, paramsK)
	for i := 0; i < paramsK; i++ {
		pkpv[i] = polyToMont(polyvecPointWiseAccMontgomery(a[i], skpv, paramsK))
	}
	polyvecAdd(pkpv, e, paramsK)
	polyvecReduce(pkpv, paramsK)
	return indcpaPackPrivateKey(skpv, paramsK), indcpaPackPublicKey(pkpv, publicSeed[:], paramsK), nil
}

// indcpaEncrypt is the encryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
func indcpaEncrypt(m []byte, publicKey []byte, coins []byte, paramsK int) ([]byte, error) {
	sp := polyvecNew(paramsK)
	ep := polyvecNew(paramsK)
	bp := polyvecNew(paramsK)
	publicKeyPolyvec, seed := indcpaUnpackPublicKey(publicKey, paramsK)
	k := polyFromMsg(m)
	at, err := indcpaGenMatrix(seed[:paramsSymBytes], true, paramsK)
	if err != nil {
		return []byte{}, err
	}
	for i := 0; i < paramsK; i++ {
		sp[i] = polyGetNoise(coins, byte(i), paramsK)
		ep[i] = polyGetNoise(coins, byte(i+paramsK), 3)
	}
	epp := polyGetNoise(coins, byte(paramsK*2), 3)
	polyvecNtt(sp, paramsK)
	polyvecReduce(sp, paramsK)
	for i := 0; i < paramsK; i++ {
		bp[i] = polyvecPointWiseAccMontgomery(at[i], sp, paramsK)
	}
	v := polyvecPointWiseAccMontgomery(publicKeyPolyvec, sp, paramsK)
	polyvecInvNttToMont(bp, paramsK)
	v = polyInvNttToMont(v)
	polyvecAdd(bp, ep, paramsK)
	v = polyAdd(polyAdd(v, epp), k)
	polyvecReduce(bp, paramsK)
	return indcpaPackCiphertext(bp, polyReduce(v), paramsK), nil
}

// indcpaDecrypt is the decryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
func indcpaDecrypt(c []byte, privateKey []byte, paramsK int) []byte {
	bp, v := indcpaUnpackCiphertext(c, paramsK)
	privateKeyPolyvec := indcpaUnpackPrivateKey(privateKey, paramsK)
	polyvecNtt(bp, paramsK)
	mp := polyvecPointWiseAccMontgomery(privateKeyPolyvec, bp, paramsK)
	mp = polyInvNttToMont(mp)
	mp = polySub(v, mp)
	mp = polyReduce(mp)
	return polyToMsg(mp)
}
