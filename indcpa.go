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
func indcpaPackPublicKey(dst []byte, publicKey *polyvec, seed []byte, paramsK int) {
	polyvecToBytes(dst, publicKey, paramsK)
	copy(dst[paramsK*paramsPolyBytes:], seed)
}

// indcpaUnpackPublicKey de-serializes the public key from a byte array
// and represents the approximate inverse of indcpaPackPublicKey.
func indcpaUnpackPublicKey(packedPublicKey []byte, paramsK int) (polyvec, []byte) {
	polyvecBytesSize := paramsK * paramsPolyBytes
	pk := polyvecFromBytes(packedPublicKey[:polyvecBytesSize], paramsK)
	return pk, packedPublicKey[polyvecBytesSize:]
}

// indcpaPackPrivateKey serializes the private key.
func indcpaPackPrivateKey(dst []byte, privateKey *polyvec, paramsK int) {
	polyvecToBytes(dst, privateKey, paramsK)
}

// indcpaUnpackPrivateKey de-serializes the private key and represents
// the inverse of indcpaPackPrivateKey.
func indcpaUnpackPrivateKey(packedPrivateKey []byte, paramsK int) polyvec {
	return polyvecFromBytes(packedPrivateKey, paramsK)
}

// indcpaPackCiphertext serializes the ciphertext as a concatenation of
// the compressed and serialized vector of polynomials `b` and the
// compressed and serialized polynomial `v`.
func indcpaPackCiphertext(dst []byte, b *polyvec, v *poly, paramsK int) {
	var polyvecCompressedSize int
	switch paramsK {
	case 2:
		polyvecCompressedSize = paramsPolyvecCompressedBytesK512
	case 3:
		polyvecCompressedSize = paramsPolyvecCompressedBytesK768
	default:
		polyvecCompressedSize = paramsPolyvecCompressedBytesK1024
	}
	polyvecCompress(dst[:polyvecCompressedSize], b, paramsK)
	polyCompress(dst[polyvecCompressedSize:], v, paramsK)
}

// indcpaUnpackCiphertext de-serializes and decompresses the ciphertext
// from a byte array, and represents the approximate inverse of
// indcpaPackCiphertext.
func indcpaUnpackCiphertext(c []byte, paramsK int) (polyvec, poly) {
	var polyvecCompressedSize int
	switch paramsK {
	case 2:
		polyvecCompressedSize = paramsPolyvecCompressedBytesK512
	case 3:
		polyvecCompressedSize = paramsPolyvecCompressedBytesK768
	default:
		polyvecCompressedSize = paramsPolyvecCompressedBytesK1024
	}
	b := polyvecDecompress(c[:polyvecCompressedSize], paramsK)
	v := polyDecompress(c[polyvecCompressedSize:], paramsK)
	return b, v
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
// Per FIPS 203 Appendix B, the rejection sampling loop is unbounded as the
// probability of exceeding 280 iterations is less than 2^-261.
func indcpaGenMatrix(seed []byte, transposed bool, paramsK int) ([4]polyvec, error) {
	var a [4]polyvec
	var buf [504]byte
	var extra [168]byte
	var xofInput [34]byte
	copy(xofInput[:32], seed)
	xof := sha3.NewShake128()
	ctr := 0
	for i := 0; i < paramsK; i++ {
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
				return a, err
			}
			_, err = xof.Read(buf[:])
			if err != nil {
				return a, err
			}
			a[i][j], ctr = indcpaRejUniform(buf[:], 504, paramsN)
			for ctr < paramsN {
				_, err = xof.Read(extra[:])
				if err != nil {
					return a, err
				}
				missing, ctrn := indcpaRejUniform(extra[:], 168, paramsN-ctr)
				for k := ctr; k < ctr+ctrn; k++ {
					a[i][j][k] = missing[k-ctr]
				}
				ctr += ctrn
			}
		}
	}
	return a, nil
}

// indcpaPrf provides a pseudo-random function (PRF) which returns
// a byte array of length `l`, using the provided key and nonce
// to instantiate the PRF's underlying hash function.
func indcpaPrf(dst []byte, prf sha3.ShakeHash, key []byte, nonce byte) {
	var prfInput [33]byte
	copy(prfInput[:32], key)
	prfInput[32] = nonce
	prf.Reset()
	_, _ = prf.Write(prfInput[:])
       	_, _ = prf.Read(dst)
byteopsZeroBytes(prfInput[:]) // <--- The only change needed
}

// indcpaKeypair generates public and private keys for the CPA-secure
// public-key encryption scheme underlying Kyber.
func indcpaKeypair(sk, pk []byte, paramsK int) error {
	var skpv, pkpv, e polyvec
	var buf [64]byte
	var hashInput [33]byte
	h := sha3.New512()
	_, err := rand.Read(hashInput[:paramsSymBytes])
	if err != nil {
		return err
	}
	hashInput[32] = byte(paramsK)
	_, err = h.Write(hashInput[:])
	if err != nil {
		return err
	}
	h.Sum(buf[:0])
	var publicSeed [paramsSymBytes]byte
	var noiseSeed [paramsSymBytes]byte
	copy(publicSeed[:], buf[:paramsSymBytes])
	copy(noiseSeed[:], buf[paramsSymBytes:])
	a, err := indcpaGenMatrix(publicSeed[:], false, paramsK)
	if err != nil {
		return err
	}
	prf := sha3.NewShake256()
	var nonce byte
	for i := 0; i < paramsK; i++ {
		skpv[i] = polyGetNoise(prf, noiseSeed[:], nonce, paramsK)
		nonce++
	}
	for i := 0; i < paramsK; i++ {
		e[i] = polyGetNoise(prf, noiseSeed[:], nonce, paramsK)
		nonce++
	}
	skpv = polyvecNtt(&skpv, paramsK)
	skpv = polyvecReduce(&skpv, paramsK)
	e = polyvecNtt(&e, paramsK)
	for i := 0; i < paramsK; i++ {
		t := polyvecPointWiseAccMontgomery(&a[i], &skpv, paramsK)
		pkpv[i] = polyToMont(&t)
	}
	pkpv = polyvecAdd(&pkpv, &e, paramsK)
	pkpv = polyvecReduceFull(&pkpv, paramsK)
	skpv = polyvecReduceFull(&skpv, paramsK)
	indcpaPackPrivateKey(sk, &skpv, paramsK)
	indcpaPackPublicKey(pk, &pkpv, publicSeed[:], paramsK)
	byteopsZeroBytes(buf[:])
	byteopsZeroBytes(hashInput[:])
	byteopsZeroBytes(noiseSeed[:])
	byteopsZeroPolyvec(&skpv)
	byteopsZeroPolyvec(&e)
	return nil
}

// indcpaEncrypt is the encryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
func indcpaEncrypt(ct, m, publicKey, coins []byte, paramsK int) error {
	var sp, ep, bp polyvec
	publicKeyPolyvec, seed := indcpaUnpackPublicKey(publicKey, paramsK)
	k := polyFromMsg(m)
	at, err := indcpaGenMatrix(seed[:paramsSymBytes], true, paramsK)
	if err != nil {
		return err
	}
	prf := sha3.NewShake256()
	for i := 0; i < paramsK; i++ {
		sp[i] = polyGetNoise(prf, coins, byte(i), paramsK)
		ep[i] = polyGetNoise(prf, coins, byte(i+paramsK), 3)
	}
	epp := polyGetNoise(prf, coins, byte(paramsK*2), 3)
	sp = polyvecNtt(&sp, paramsK)
	sp = polyvecReduce(&sp, paramsK)
	for i := 0; i < paramsK; i++ {
		bp[i] = polyvecPointWiseAccMontgomery(&at[i], &sp, paramsK)
	}
	v := polyvecPointWiseAccMontgomery(&publicKeyPolyvec, &sp, paramsK)
	bp = polyvecInvNttToMont(&bp, paramsK)
	v = polyInvNttToMont(&v)
	bp = polyvecAdd(&bp, &ep, paramsK)
	v = polyAdd(&v, &epp)
	v = polyAdd(&v, &k)
	bp = polyvecReduceFull(&bp, paramsK)
	v = polyReduceFull(&v)
	indcpaPackCiphertext(ct, &bp, &v, paramsK)
	byteopsZeroPolyvec(&sp)
	byteopsZeroPolyvec(&ep)
	byteopsZeroPolyvec(&bp)
	byteopsZeroPoly(&k)
	byteopsZeroPoly(&epp)
	byteopsZeroPoly(&v)
	return nil
}

// indcpaDecrypt is the decryption function of the CPA-secure
// public-key encryption scheme underlying Kyber.
func indcpaDecrypt(msg, c, privateKey []byte, paramsK int) {
	bp, v := indcpaUnpackCiphertext(c, paramsK)
	privateKeyPolyvec := indcpaUnpackPrivateKey(privateKey, paramsK)
	bp = polyvecNtt(&bp, paramsK)
	mp := polyvecPointWiseAccMontgomery(&privateKeyPolyvec, &bp, paramsK)
	mp = polyInvNttToMont(&mp)
	mp = polySub(&v, &mp)
	mp = polyReduceFull(&mp)
	polyToMsg(msg, &mp)
	byteopsZeroPolyvec(&bp)
	byteopsZeroPoly(&v)
	byteopsZeroPolyvec(&privateKeyPolyvec)
	byteopsZeroPoly(&mp)
}
