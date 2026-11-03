# Interoperability

This page lists only peers that were run against go-pki-est code, with where the evidence lives.
The library's own tests run the client against its own router, which proves the two halves agree
but not that they follow other implementations.

## Cisco libest 3.2.0

[certrally](https://github.com/misiektoja/certrally) is a command line tool whose `est` commands
are built on `est.Client`. It always sets `AllowCertificateChain`. Its tests run against the
example server of [Cisco libest](https://github.com/cisco/libest) 3.2.0, built from tag `r3.2.0`
(commit `4ca02c6d`) on Ubuntu 20.04 with OpenSSL 1.1.1. Only the client side of go-pki-est is
exercised.

### Checked in CI

The `Cisco libest` job of the certrally integration workflow runs on pushes and pull requests to
certrally's `dev` and `main` branches, weekly and on demand. certrally currently pins go-pki-est
v1.4.0. Every request uses a new ECDSA P-256 key, certrally's default. The steps are in
[libest_test.go](https://github.com/misiektoja/certrally/blob/main/test/integration/libest/libest_test.go).

| Client operation | Result |
| --- | --- |
| `CACerts` with an explicit anchor | Works |
| `CACerts` with `InsecureSkipVerify` and a fingerprint check | Works |
| `CSRAttrs` | Works |
| `Enroll` with a password | Works |
| `Reenroll` with the client certificate against a server started with `-o` | Works |
| `Reenroll` with a password and no client certificate | Works |
| `Enroll` over TLS-SRP with a 2048-bit group | Works |
| `Enroll` with `SigningKey` against a server started with `-t` | Works |
| `Enroll` without `SigningKey` against a server started with `-t` | The server answers 401 `Proof of Possession Mismatch` |
| `ServerKeyGen` | Fails. The server declares a `Content-Length` shorter than its multipart response, so the client reads `unexpected EOF` |

### Manual notes

certrally's [Tested servers](https://misiektoja.github.io/certrally/interop/) page also records
manual runs against the same server. They were written when certrally used go-pki-est v1.3.1 and
CI does not repeat them:

* `Enroll` worked with ECDSA P-384, RSA 2048 and Ed25519 keys.
* ML-DSA and composite ML-DSA requests get 400, because OpenSSL 1.1.1 does not know the
  algorithms.
* The `passwd.srpv` file that comes with libest uses a 1536-bit group, which the client refuses by
  default. Use a verifier with at least 2048 bits or lower `SRPMinGroupBits`.
* A server started with `-h` asks for HTTP Digest authentication. The client signs in with Basic
  only and gets 401.
* A server started with `-m` answers enrollments with 202 and `Retry-After: 3600`.

### Accommodations in go-pki-est

The router's 401 challenge uses the header name `WWW-Authenticate` exactly, because libest
compares header names with case. The client sends requests with a `Content-Length`, because the
libest server cannot read a chunked body.

## Not tested

No other EST server or client has been run against go-pki-est with recorded results. This includes
the `estserver` router with libest's client, Bouncy Castle, OpenSSL-based clients and commercial
EST servers. The source carries workarounds for Bouncy Castle, such as the 401 challenge without a
body, but no test runs Bouncy Castle.

To report a result, open an issue with the peer, its version, the operations you ran and sanitized
evidence, as [CONTRIBUTING.md](https://github.com/misiektoja/go-pki-est/blob/main/CONTRIBUTING.md)
asks.
