# Kyber-K2SO

<img src="assets/kyber-k2so.png" align="right" height="200" width="200"/>

[![Kyber-K2SO](https://github.com/symbolicsoft/kyber-k2so/workflows/Kyber-K2SO/badge.svg)](https://github.com/symbolicsoft/kyber-k2so/actions)
[![GoDoc](https://godoc.org/github.com/symbolicsoft/kyber-k2so?status.svg)](https://pkg.go.dev/github.com/symbolicsoft/kyber-k2so?tab=overview)
[![Go Report Card](https://goreportcard.com/badge/github.com/symbolicsoft/kyber-k2so)](https://goreportcard.com/report/github.com/symbolicsoft/kyber-k2so)
![GitHub](https://img.shields.io/github/license/symbolicsoft/kyber-k2so)

**[Kyber-K2SO](https://github.com/symbolicsoft/kyber-k2so)** is Symbolic Software's clean implementation of [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) (FIPS 203), the Module-Lattice-Based Key-Encapsulation Mechanism standardized by NIST. ML-KEM is an IND-CCA2-secure key encapsulation mechanism (KEM) whose security is based on the hardness of solving the learning-with-errors (LWE) problem over module lattices.

## Security Disclaimer

🚨 Extensive effort has been undertaken in order to ensure the correctness, interoperability, safety and reliability of this library. Furthermore, it is unlikely that the API will change in the future. While this library is likely ready for production use, it is offered as-is, and without a guarantee.

## Features & Usage

Keeping in mind the Security Disclaimer above, Kyber-K2SO appears to be appropriate for use in any environment supported by Go: client-side application, server-side applications and more. All operations take no more than a few milliseconds on regular computing hardware.

### Features

* **Small, easy to read code.** Kyber-K2SO is to our knowledge the smallest implementation of ML-KEM (FIPS 203).
* **Simple API.** `KemKeypair768()` to generate a private key and a public key, `KemEncrypt768(publicKey)` generate and encrypt a shared secret, and `KemDecrypt768(ciphertext, privateKey)` to decrypt the shared secret. Aside from ML-KEM-768, ML-KEM-512 and ML-KEM-1024 are also offered.
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

Replace `768` with `512` or `1024` in the above function names in order to call ML-KEM-512 or ML-KEM-1024 instead of ML-KEM-768.

### Running Tests

```bash
> go test -v

=== RUN   TestSelf512
--- PASS: TestSelf512 (0.09s)
=== RUN   TestSelf768
--- PASS: TestSelf768 (0.14s)
=== RUN   TestSelf1024
--- PASS: TestSelf1024 (0.21s)
=== RUN   TestMLKEM512Vector
--- PASS: TestMLKEM512Vector (0.00s)
=== RUN   TestMLKEM768Vector
--- PASS: TestMLKEM768Vector (0.00s)
=== RUN   TestMLKEM1024Vector
--- PASS: TestMLKEM1024Vector (0.00s)
PASS
ok      github.com/symbolicsoft/kyber-k2so      0.431s
```

### Running Benchmarks

```bash
> go test -bench=.

goos: linux
goarch: amd64
pkg: github.com/symbolicsoft/kyber-k2so
cpu: Intel(R) Core(TM) Ultra 9 275HX
BenchmarkKemKeypair512-24          52944             22653 ns/op
BenchmarkKemKeypair768-24          29696             40083 ns/op
BenchmarkKemKeypair1024-24         19209             60778 ns/op
BenchmarkKemEncrypt512-24          48856             23307 ns/op
BenchmarkKemEncrypt768-24          32428             39273 ns/op
BenchmarkKemEncrypt1024-24         19483             57528 ns/op
BenchmarkKemDecrypt512-24          36138             33402 ns/op
BenchmarkKemDecrypt768-24          25008             47869 ns/op
BenchmarkKemDecrypt1024-24         17690             67303 ns/op
PASS
ok      github.com/symbolicsoft/kyber-k2so      15.135s
```

## About Kyber-K2SO

Kyber-K2SO is published by [Symbolic Software](https://symbolic.software) under the MIT License.
