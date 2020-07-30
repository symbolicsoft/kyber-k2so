<img src="assets/kyber-k2so.png" align="right" height="300" width="300"/>

# Kyber-K2SO
[![GoDoc](https://godoc.org/github.com/symbolicsoft/kyber-k2so?status.svg)](https://pkg.go.dev/github.com/symbolicsoft/kyber-k2so?tab=overview)
[![Go Report Card](https://goreportcard.com/badge/github.com/symbolicsoft/kyber-k2so)](https://goreportcard.com/report/github.com/symbolicsoft/kyber-k2so)

**Kyber-K2SO** is a clean implementation of the [Kyber](https://pq-crystals.org/kyber) IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one of the candidate algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography).

Kyber-K2SO implements only Kyber-768, and does not provide Kyber-512, Kyber-1024, or the _"90s Kyber"_ variants, because there does not appear to be a convincing reason to ever do so.

## Security Disclaimer
🚨 This library is offered as-is, and without a guarantee. Therefore, it is expected that changes in the code, repository, and API occur in the future. It is recommended to take caution before using this library in a production application since part of its content is experimental.

# Features & Usage
Keeping in mind the Security Disclaimer above, Kyber-K2SO appears to be appropriate for use in any environment supported by Go: client-side application, server-side applications and more. All operations take no more than a few milliseconds on regular computing hardware.

## Features

* 🟢 **Purely functional, easy to read code.** Code readability and predictability is prioritized over performance.
* 🟢 **Smallest codebase.** Kyber-K2SO is to our knowledge the smallest implementation of Kyber Version 2, and is 4.3 times smaller than the reference implementation.
* 🟢 **Simple API.** `KemKeypair()` to generate a private key and a public key, `KemEncrypt(publicKey)` generate and encrypt a shared secret, and `KemDecrypt(ciphertext, privateKey)` to decrypt the shared secret.
* 🟢 **Good performance.** Kyber-K2SO is more than fast enough for regular usage in any environment supported by the Go programming language.
* 🟢 **Constant time (probably).** As far as we can tell, decryption appears to perform in constant time. Further analysis is encouraged.

## Using Kyber-K2SO
```bash
go get -u github.com/symbolicsoft/kyber-k2so
```

```go
package main

import (
	"github.com/symbolicsoft/kyber-k2so"
)

func main() {
	privateKey, publicKey, _ := kyberk2so.KemKeypair()
	ciphertext, ssA, _ := kyberk2so.KemEncrypt(publicKey)
	ssB, _ := kyberk2so.KemDecrypt(ciphertext, privateKey)
}
```

Yes, it's that simple!

## Running Tests
```bash
> go test

PASS
ok      github.com/symbolicsoft/kyber-k2so      3.114s
```

## Running Benchmarks
```bash
> go test -bench=.

goos: linux
goarch: amd64
pkg: github.com/symbolicsoft/kyber-k2so
BenchmarkKemKeypair-8           1000000000               0.000144 ns/op
BenchmarkKemEncrypt-8           1000000000               0.000158 ns/op
BenchmarkKemDecrypt-8           1000000000               0.000179 ns/op
```

# About Kyber-K2SO
Kyber-K2SO is published by [Symbolic Software](https://symbolic.software) under the MIT License. It is written by [Nadim Kobeissi](https://nadim.computer).

We thank [Peter Schwabe](https://cryptojedi.org/peter) for his feedback during the development of Kyber-K2SO.