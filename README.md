# Kyber-K2SO

<img src="assets/kyber-k2so.png" align="right" height="200" width="200"/>

[![Kyber-K2SO](https://github.com/symbolicsoft/kyber-k2so/workflows/Kyber-K2SO/badge.svg)](https://github.com/symbolicsoft/kyber-k2so/actions)
[![GoDoc](https://godoc.org/github.com/symbolicsoft/kyber-k2so?status.svg)](https://pkg.go.dev/github.com/symbolicsoft/kyber-k2so?tab=overview)
[![Go Report Card](https://goreportcard.com/badge/github.com/symbolicsoft/kyber-k2so)](https://goreportcard.com/report/github.com/symbolicsoft/kyber-k2so)
![GitHub](https://img.shields.io/github/license/symbolicsoft/kyber-k2so)

**Kyber-K2SO** is a clean implementation of the [Kyber](https://pq-crystals.org/kyber) IND-CCA2-secure key encapsulation mechanism (KEM), whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices. Kyber is one of the candidate algorithms submitted to the [NIST post-quantum cryptography project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography).

## Security Disclaimer

🚨 Extensive effort has been undertaken in order to ensure the correctness, interoperability, safety and reliability of this library. Furthermore, it is unlikely that the API will change in the future. While this library is likely ready for production use, it is offered as-is, and without a guarantee.

## Features & Usage

Keeping in mind the Security Disclaimer above, Kyber-K2SO appears to be appropriate for use in any environment supported by Go: client-side application, server-side applications and more. All operations take no more than a few milliseconds on regular computing hardware.

### Features

* **Small, easy to read code.** Kyber-K2SO is to our knowledge the smallest implementation of Kyber Version 3.
* **Simple API.** `KemKeypair768()` to generate a private key and a public key, `KemEncrypt768(publicKey)` generate and encrypt a shared secret, and `KemDecrypt768(ciphertext, privateKey)` to decrypt the shared secret. Aside from Kyber-768, Kyber-512 and Kyber-1024 are also offered.
* **Good performance.** Kyber-K2SO is more than fast enough for regular usage in any environment supported by the Go programming language.
* **Constant time (probably).** As far as we can tell, decryption appears to perform in constant time. Further analysis is encouraged.

### Using Kyber-K2SO

```bash
go get -u github.com/symbolicsoft/kyber-k2so
```

```go
package main

import (
	kyberk2so "github.com/symbolicsoft/kyber-k2so"
)

func main() {
	privateKey, publicKey, _ := kyberk2so.KemKeypair768()
	ciphertext, ssA, _ := kyberk2so.KemEncrypt768(publicKey)
	ssB, _ := kyberk2so.KemDecrypt768(ciphertext, privateKey)
}
```

Replace `768` with `512` or `1024` in the above function names in order to call Kyber-512 or Kyber-1024 instead of Kyber-768.

### Running Tests

```bash
> go test -v

=== RUN   TestVectors512
--- PASS: TestVectors512 (0.01s)
=== RUN   TestVectors768
--- PASS: TestVectors768 (0.01s)
=== RUN   TestVectors1024
--- PASS: TestVectors1024 (0.01s)
=== RUN   TestSelf512
--- PASS: TestSelf512 (0.19s)
=== RUN   TestSelf768
--- PASS: TestSelf768 (0.30s)
=== RUN   TestSelf1024
--- PASS: TestSelf1024 (0.46s)
PASS
ok  	github.com/symbolicsoft/kyber-k2so	1.140s
```

### Running Benchmarks

```bash
> go test -bench=.

goos: linux
goarch: amd64
pkg: github.com/symbolicsoft/kyber-k2so
BenchmarkKemKeypair512-8    	   28116	     41519 ns/op
BenchmarkKemKeypair768-8    	   15864	     74150 ns/op
BenchmarkKemKeypair1024-8   	   10000	    105946 ns/op
BenchmarkKemEncrypt512-8    	   21409	     56336 ns/op
BenchmarkKemEncrypt768-8    	   13629	     87541 ns/op
BenchmarkKemEncrypt1024-8   	    9987	    131054 ns/op
BenchmarkKemDecrypt512-8    	   17650	     65348 ns/op
BenchmarkKemDecrypt768-8    	   12352	     99300 ns/op
BenchmarkKemDecrypt1024-8   	    8913	    140804 ns/op
PASS
ok  	github.com/symbolicsoft/kyber-k2so	16.180s
```

## About Kyber-K2SO

Kyber-K2SO is published by [Symbolic Software](https://symbolic.software) under the MIT License.

Kyber-K2SO originally implemented Kyber version 2. Kyber-K2SO was subsequently updated in version 0.1.0 to implement Kyber version 3 thanks to work contributed by [Anton Tutoveanu](https://github.com/antontutoveanu) in March 2021.

We thank [Peter Schwabe](https://cryptojedi.org/peter) for his feedback during the development of this implementation.
