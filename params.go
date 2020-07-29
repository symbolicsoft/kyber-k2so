/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

const paramsK int = 3
const paramsN int = 256
const paramsQ int = 3329
const paramsETA int = 2
const paramsPolyBytes int = 384
const paramsPolyCompressedBytes int = 128
const paramsQinv int = 62209
const paramsSymBytes int = 32
const paramsPolyvecBytes int = paramsK * paramsPolyBytes
const paramsPolyvecCompressedBytes int = paramsK * 320
const paramsSecretKeyBytes int = paramsPolyvecBytes + ((paramsPolyvecBytes + paramsSymBytes) + 2*paramsSymBytes)
const paramsPublicKeyBytes int = paramsPolyvecBytes + paramsSymBytes
const paramsIndcpaSecretKeyBytes int = paramsK * paramsPolyBytes
const paramsIndcpaPublicKeyBytes int = paramsPolyvecBytes + paramsSymBytes
const paramsIndcpaBytes int = paramsPolyvecCompressedBytes + paramsPolyCompressedBytes
