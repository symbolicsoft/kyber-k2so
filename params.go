/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

const paramsN int = 256
const paramsQ int = 3329
const paramsETA int = 2
const paramsSymBytes int = 32
const paramsSSBytes int = 32
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
const paramsIndcpaBytesK2 int = paramsPolyvecCompressedBytesK2 + paramsPolyCompressedBytesK2
const paramsIndcpaBytesK3 int = paramsPolyvecCompressedBytesK3 + paramsPolyCompressedBytesK3
const paramsIndcpaBytesK4 int = paramsPolyvecCompressedBytesK4 + paramsPolyCompressedBytesK4
const paramsPublicKeyBytesK2 int = paramsPolyvecBytesK2 + paramsSymBytes
const paramsPublicKeyBytesK3 int = paramsPolyvecBytesK3 + paramsSymBytes
const paramsPublicKeyBytesK4 int = paramsPolyvecBytesK4 + paramsSymBytes
const paramsSecretKeyBytesK2 int = paramsPolyvecBytesK2 + ((paramsPolyvecBytesK2 + paramsSymBytes) + 2*paramsSymBytes)
const paramsSecretKeyBytesK3 int = paramsPolyvecBytesK3 + ((paramsPolyvecBytesK3 + paramsSymBytes) + 2*paramsSymBytes)
const paramsSecretKeyBytesK4 int = paramsPolyvecBytesK4 + ((paramsPolyvecBytesK4 + paramsSymBytes) + 2*paramsSymBytes)
const paramsQinv int = 62209
