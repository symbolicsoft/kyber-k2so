/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

type paramsStruct struct {
	k                      int
	n                      int
	q                      int
	eta                    int
	polybytes              int
	polycompressedbytes    int
	polyvecbytes           int
	polyveccompressedbytes int
	qinv                   int
	symbytes               int
	secretkeybytes         int
	publickeybytes         int
	indcpasecretkeybytes   int
	indcpapublickeybytes   int
	indcpabytes            int
}

var params paramsStruct = paramsStruct{
	k:                      3,
	n:                      256,
	q:                      3329,
	eta:                    2,
	polybytes:              384,
	polycompressedbytes:    128,
	polyvecbytes:           (3 * 384),
	polyveccompressedbytes: (3 * 320),
	qinv:                   62209,
	symbytes:               32,
	secretkeybytes:         ((3 * 384) + ((3 * 384) + 32) + 2*32),
	publickeybytes:         ((3 * 384) + 32),
	indcpasecretkeybytes:   (3 * 384),
	indcpapublickeybytes:   ((3 * 384) + 32),
	indcpabytes:            ((3 * 320) + 128),
}
