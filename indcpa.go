/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

func indcpaPackPublicKey(publicKey polyvec, seed []byte, paramsK int) []byte {
	return append(polyvecToBytes(publicKey, paramsK), seed...)
}

func indcpaUnpackPublicKey(packedPublicKey []byte, paramsK int) (polyvec, []byte) {
	switch paramsK {
	case 2:
		publicKeyPolyvec := polyvecFromBytes(packedPublicKey[:paramsPolyvecBytesK2], paramsK)
		seed := packedPublicKey[paramsPolyvecBytesK2:]
		return publicKeyPolyvec, seed
	case 3:
		publicKeyPolyvec := polyvecFromBytes(packedPublicKey[:paramsPolyvecBytesK3], paramsK)
		seed := packedPublicKey[paramsPolyvecBytesK3:]
		return publicKeyPolyvec, seed
	default:
		publicKeyPolyvec := polyvecFromBytes(packedPublicKey[:paramsPolyvecBytesK4], paramsK)
		seed := packedPublicKey[paramsPolyvecBytesK4:]
		return publicKeyPolyvec, seed
	}
}

func indcpaPackPrivateKey(privateKey polyvec, paramsK int) []byte {
	return polyvecToBytes(privateKey, paramsK)
}

func indcpaUnpackPrivateKey(packedPrivateKey []byte, paramsK int) polyvec {
	return polyvecFromBytes(packedPrivateKey, paramsK)
}

func indcpaPackCiphertext(b polyvec, v poly, paramsK int) []byte {
	return append(polyvecCompress(b, paramsK), polyCompress(v, paramsK)...)
}

func indcpaUnpackCiphertext(c []byte, paramsK int) (polyvec, poly) {
	switch paramsK {
	case 2:
		b := polyvecDecompress(c[:paramsPolyvecCompressedBytesK2], paramsK)
		v := polyDecompress(c[paramsPolyvecCompressedBytesK2:], paramsK)
		return b, v
	case 3:
		b := polyvecDecompress(c[:paramsPolyvecCompressedBytesK3], paramsK)
		v := polyDecompress(c[paramsPolyvecCompressedBytesK3:], paramsK)
		return b, v
	default:
		b := polyvecDecompress(c[:paramsPolyvecCompressedBytesK4], paramsK)
		v := polyDecompress(c[paramsPolyvecCompressedBytesK4:], paramsK)
		return b, v
	}
}

func indcpaRejUniform(buf []byte, bufl int) (poly, int) {
	var r poly
	var val uint16
	ctr := 0
	pos := 0
	for ctr < paramsN && pos+2 <= bufl {
		val = uint16(buf[pos]) | (uint16(buf[pos+1]) << 8)
		pos = pos + 2
		if val < uint16(19*paramsQ) {
			val = val - ((val >> 12) * uint16(paramsQ))
			r[ctr] = int16(val)
			ctr = ctr + 1
		}
	}
	return r, ctr
}

func indcpaGenMatrix(seed []byte, transposed bool, paramsK int) ([]polyvec, error) {
	r := make([]polyvec, paramsK)
	buf := make([]byte, 4*168)
	xof := sha3.NewShake128()
	ctr := 0
	for i := 0; i < paramsK; i++ {
		r[i] = polyvecNew(paramsK)
		for j := 0; j < paramsK; j++ {
			transposon := []byte{byte(j), byte(i)}
			if transposed {
				transposon = []byte{byte(i), byte(j)}
			}
			xof.Reset()
			_, err := xof.Write(append(seed, transposon...))
			if err != nil {
				return []polyvec{}, err
			}
			_, err = xof.Read(buf)
			if err != nil {
				return []polyvec{}, err
			}
			r[i][j], ctr = indcpaRejUniform(buf, len(buf))
			for ctr < paramsN {
				bufn := make([]byte, 168)
				_, err = xof.Read(bufn)
				if err != nil {
					return []polyvec{}, err
				}
				missing, ctrn := indcpaRejUniform(bufn, 168)
				for k := ctr; k < paramsN-ctr; k++ {
					r[i][j][k] = missing[paramsN-ctr+k]
				}
				ctr = ctr + ctrn
			}
		}
	}
	return r, nil
}

func indcpaPrf(l int, key []byte, nonce byte) []byte {
	hash := make([]byte, l)
	sha3.ShakeSum256(hash, append(key, nonce))
	return hash
}

func indcpaKeypair(paramsK int) ([]byte, []byte, error) {
	skpv := polyvecNew(paramsK)
	pkpv := polyvecNew(paramsK)
	e := polyvecNew(paramsK)
	buf := make([]byte, 2*paramsSymBytes)
	h := sha3.New512()
	_, err := rand.Read(buf[:paramsSymBytes])
	if err != nil {
		return []byte{}, []byte{}, err
	}
	_, err = h.Write(buf[:paramsSymBytes])
	if err != nil {
		return []byte{}, []byte{}, err
	}
	buf = buf[:0]
	buf = h.Sum(buf)
	publicSeed, noiseSeed := buf[:paramsSymBytes], buf[paramsSymBytes:]
	a, err := indcpaGenMatrix(publicSeed, false, paramsK)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	var nonce byte
	for i := 0; i < paramsK; i++ {
		skpv[i] = polyGetNoise(noiseSeed, nonce)
		nonce = nonce + 1
	}
	for i := 0; i < paramsK; i++ {
		e[i] = polyGetNoise(noiseSeed, nonce)
		nonce = nonce + 1
	}
	polyvecNtt(skpv, paramsK)
	polyvecNtt(e, paramsK)
	for i := 0; i < paramsK; i++ {
		pkpv[i] = polyToMont(polyvecPointWiseAccMontgomery(a[i], skpv, paramsK))
	}
	polyvecAdd(pkpv, e, paramsK)
	polyvecReduce(pkpv, paramsK)
	return indcpaPackPrivateKey(skpv, paramsK), indcpaPackPublicKey(pkpv, publicSeed, paramsK), nil
}

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
		sp[i] = polyGetNoise(coins, byte(i))
		ep[i] = polyGetNoise(coins, byte(i+paramsK))
	}
	epp := polyGetNoise(coins, byte(paramsK*2))
	polyvecNtt(sp, paramsK)
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
