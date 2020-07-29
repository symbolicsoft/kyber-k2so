/* SPDX-FileCopyrightText: © 2020-2021 Nadim Kobeissi <nadim@symbolic.software>
 * SPDX-License-Identifier: MIT */

package kyberk2so

import (
	"crypto/subtle"
	"testing"
)

func TestMain(t *testing.T) {
	for i := 0; i < 30000; i++ {
		privateKeyB, publicKeyB, err := KemKeypair()
		if err != nil {
			t.Error(err)
		}
		ctA, ssA, err := KemEncrypt(publicKeyB)
		if err != nil {
			t.Error(err)
		}
		ssB, err := KemDecrypt(ctA, privateKeyB)
		if err != nil {
			t.Error(err)
		}
		if subtle.ConstantTimeCompare(ssA, ssB) == 0 {
			t.Error("shared secret failed")
		}
	}
}
