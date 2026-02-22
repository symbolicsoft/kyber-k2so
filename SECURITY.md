# Security Policy

## Supported Versions

Only the latest release on the `main` branch is supported. Users should always update to the latest version.

## Reporting a Vulnerability

If you discover a security vulnerability in Kyber-K2SO, you are welcome to report it by opening a [GitHub issue](https://github.com/symbolicsoft/kyber-k2so/issues) or submitting a [pull request](https://github.com/symbolicsoft/kyber-k2so/pulls) with a fix. There is no requirement for coordinated or private disclosure — use whichever method you prefer.

Please include:

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue, or a proof of concept if applicable.
- The affected variant(s) (ML-KEM-512, ML-KEM-768, ML-KEM-1024) if relevant.

## Security Considerations

Kyber-K2SO is a cryptographic library implementing [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final). The following security measures are in place:

- **Constant-time decryption (probably):** Decryption uses `crypto/subtle.ConstantTimeCompare` for ciphertext comparison and conditional selection to avoid timing side channels. Further analysis is encouraged.
- **Zeroization:** Best-effort zeroization of secret and intermediate values (keys, seeds, shared secrets) is performed after use.
- **Secure randomness:** All random number generation uses Go's `crypto/rand`.
- **FIPS 203 test vectors:** Official test vectors from [C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/ML-KEM) are used to validate correctness and interoperability.

### Known Limitations

- **Best-effort zeroization:** Go does not guarantee that the compiler or garbage collector will not copy or retain sensitive values in memory. Zeroization is performed on a best-effort basis.
- **No formal verification:** The implementation has not been formally verified. It prioritizes readability and correctness through testing and code review.
- **Side-channel analysis:** While efforts have been made toward constant-time operation, a comprehensive side-channel analysis has not been performed. Users with strong side-channel requirements should evaluate accordingly.

## Disclaimer

Extensive effort has been undertaken to ensure the correctness, interoperability, safety and reliability of this library. While it is likely ready for production use, it is offered as-is and without a guarantee. See the [MIT License](LICENSE) for details.
