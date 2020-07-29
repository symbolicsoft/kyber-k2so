/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"crypto/rand"

	"golang.org/x/crypto/sha3"
)

func indcpaPackPublicKey(publicKey polyvec, seed []byte) []byte {
	return append(polyvecToBytes(publicKey), seed...)
}

func indcpaUnpackPublicKey(packedPublicKey []byte) (polyvec, []byte) {
	publicKeyPolyvec := polyvecFromBytes(packedPublicKey[:paramsPolyvecBytes])
	seed := packedPublicKey[paramsPolyvecBytes:]
	return publicKeyPolyvec, seed
}

func indcpaPackPrivateKey(privateKey polyvec) []byte {
	return polyvecToBytes(privateKey)
}

func indcpaUnpackPrivateKey(packedPrivateKey []byte) polyvec {
	return polyvecFromBytes(packedPrivateKey)
}

func indcpaPackCiphertext(b polyvec, v poly) []byte {
	return append(polyvecCompress(b), polyCompress(v)...)
}

func indcpaUnpackCiphertext(c []byte) (polyvec, poly) {
	b := polyvecDecompress(c[:paramsPolyvecCompressedBytes])
	v := polyDecompress(c[paramsPolyvecCompressedBytes:])
	return b, v
}

func indcpaRejUniform(l int, buf []byte, bufl int) ([]int16, int) {
	r := make([]int16, l)
	var val uint16
	ctr := 0
	pos := 0
	for ctr < l && pos+2 <= bufl {
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

func indcpaGenMatrix(seed []byte, transposed bool) ([]polyvec, error) {
	r := make([]polyvec, paramsK)
	buf := make([]byte, 4*168)
	xof := sha3.NewShake128()
	ctr := 0
	for i := 0; i < paramsK; i++ {
		r[i] = polyvecNew()
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
			r[i].vec[j].coeffs, ctr = indcpaRejUniform(paramsN, buf, len(buf))
			for ctr < paramsN {
				bufn := make([]byte, 168)
				_, err = xof.Read(bufn)
				if err != nil {
					return []polyvec{}, err
				}
				missing, ctrn := indcpaRejUniform(paramsN-ctr, bufn, 168)
				r[i].vec[j].coeffs = append(
					r[i].vec[j].coeffs[:ctr],
					missing[:paramsN-ctr]...,
				)
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

func indcpaKeypair() ([]byte, []byte, error) {
	skpv := polyvecNew()
	pkpv := polyvecNew()
	e := polyvecNew()
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
	a, err := indcpaGenMatrix(publicSeed, false)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	var nonce byte
	for i := 0; i < paramsK; i++ {
		skpv.vec[i] = polyGetNoise(noiseSeed, nonce)
		nonce = nonce + 1
	}
	for i := 0; i < paramsK; i++ {
		e.vec[i] = polyGetNoise(noiseSeed, nonce)
		nonce = nonce + 1
	}
	skpv = polyvecNtt(skpv)
	e = polyvecNtt(e)
	for i := 0; i < paramsK; i++ {
		pkpv.vec[i] = polyvecPointWiseAccMontgomery(a[i], skpv)
		pkpv.vec[i] = polyToMont(pkpv.vec[i])
	}
	pkpv = polyvecAdd(pkpv, e)
	pkpv = polyvecReduce(pkpv)
	return indcpaPackPrivateKey(skpv), indcpaPackPublicKey(pkpv, publicSeed), nil
}

func indcpaEncrypt(m []byte, publicKey []byte, coins []byte) ([]byte, error) {
	sp := polyvecNew()
	ep := polyvecNew()
	bp := polyvecNew()
	nonce := byte(0)
	publicKeyPolyvec, seed := indcpaUnpackPublicKey(publicKey)
	k := polyFromMsg(m)
	at, err := indcpaGenMatrix(seed[:paramsSymBytes], true)
	if err != nil {
		return []byte{}, err
	}
	for i := 0; i < paramsK; i++ {
		sp.vec[i] = polyGetNoise(coins, nonce)
		nonce = nonce + 1
	}
	for i := 0; i < paramsK; i++ {
		ep.vec[i] = polyGetNoise(coins, nonce)
		nonce = nonce + 1
	}
	epp := polyGetNoise(coins, nonce)
	sp = polyvecNtt(sp)
	for i := 0; i < paramsK; i++ {
		bp.vec[i] = polyvecPointWiseAccMontgomery(at[i], sp)
	}
	v := polyvecPointWiseAccMontgomery(publicKeyPolyvec, sp)
	bp = polyvecInvNttToMont(bp)
	v = polyInvNttToMont(v)
	bp = polyvecAdd(bp, ep)
	v = polyAdd(v, epp)
	v = polyAdd(v, k)
	bp = polyvecReduce(bp)
	v = polyReduce(v)
	return indcpaPackCiphertext(bp, v), nil
}

func indcpaDecrypt(c []byte, privateKey []byte) []byte {
	bp, v := indcpaUnpackCiphertext(c)
	privateKeyPolyvec := indcpaUnpackPrivateKey(privateKey)
	bp = polyvecNtt(bp)
	mp := polyvecPointWiseAccMontgomery(privateKeyPolyvec, bp)
	mp = polyInvNttToMont(mp)
	mp = polySub(v, mp)
	mp = polyReduce(mp)
	return polyToMsg(mp)
}
