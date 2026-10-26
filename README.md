# go-pki-est

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pki-est?style=flat-square&color=blue)](https://github.com/misiektoja/go-pki-est/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pki-est.svg)](https://pkg.go.dev/github.com/misiektoja/go-pki-est)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-pki-est/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-est/actions/workflows/test.yml)
[![Supply chain](https://github.com/misiektoja/go-pki-est/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-est/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-pki-est&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pki-est)

Go library for **Enrollment over Secure Transport (EST)**, the certificate enrollment protocol
defined in [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030). It provides:

* an EST client library
* an `http.Handler` that serves EST in front of your CA (`NewRouter` and the `CA` interface)
* `estclient`, a command line client built on the library
* `estserver`, a server with a mock CA for testing and development

## Contents

* [Install](#install)
* [Quickstart](#quickstart)
* [Features](#features)
* [Credits](#credits)
* [Support and contributing](#support-and-contributing)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-pki-est
```

The package name is `est`. Requires Go 1.27.3 or newer.

The command line tools install with:

```bash
go install github.com/misiektoja/go-pki-est/cmd/estclient@latest
```

```bash
go install github.com/misiektoja/go-pki-est/cmd/estserver@latest
```

### Verifying a release

Each [GitHub release](https://github.com/misiektoja/go-pki-est/releases) carries the complete
source tree as ZIP and tar archives, a CycloneDX SBOM, their SHA-256 checksums and a signed
provenance bundle. Check a downloaded file against the checksums and confirm that the release
workflow of this repository built it:

```bash
shasum -a 256 -c go-pki-est-v1.3.1_SHA256SUMS.txt
```

```bash
gh attestation verify go-pki-est-v1.3.1-source.tar.gz --repo misiektoja/go-pki-est
```

To verify offline, add `--bundle go-pki-est-v1.3.1.intoto.jsonl`.

## Quickstart

### Starting the server

When started with no configuration file, the EST server listens on `localhost:8443` and generates
a random, transient Certificate Authority (CA) which can be used for testing. The CA issues a
certificate to anyone, so serve other hosts only through `listen_address` in a configuration file:

    user@host:$ estserver &
    [1] 62405

`estserver -sampleconfig` prints a sample configuration file.

### Getting the CA certificates

Because we're using a random, transient CA, we must retrieve the CA certificates
in insecure mode to establish an explicit trust anchor for subsequent EST
operations. Since we only need the root CA certificate to establish a trust
anchor, we use the `-rootout` flag:

    user@host:$ estclient cacerts -server localhost:8443 -insecure -rootout -out anchor.pem

We will also obtain and store the full CA certificates chain, since we'll use
it shortly to demonstrate reenrollment. Since we now have an explicit trust
anchor, we can use it instead of the `-insecure` option. Since we're storing
the full chain, we don't use the `-rootout` option here:

    user@host:$ estclient cacerts -server localhost:8443 -explicit anchor.pem -out cacerts.pem

### Enrolling with an existing private key

First we generate a new private key, here using openssl:

    user@host:$ openssl genrsa 4096 > key.pem
    Generating RSA private key, 4096 bit long modulus
    .................+++
    .............+++
    e is 65537 (0x10001)

Then we generate a PKCS#10 certificate signing request, and enroll using the
explicit trust anchor we previously obtained:

    user@host:$ estclient csr -key key.pem -cn 'John Doe' -emails 'john@doe.com' -out csr.pem
    user@host:$ estclient enroll -server localhost:8443 -explicit anchor.pem -csr csr.pem -out cert.pem

Using a configuration file, we can enroll with a private key resident on a
hardware module, such as a hardware security module (HSM) or a Trusted Platform
Module 2.0 (TPM) device. `estclient sampleconfig` prints a sample configuration file.

### Enforcing proof of possession

[RFC 7030 section 3.5](https://www.rfc-editor.org/rfc/rfc7030#section-3.5) binds the request to
the TLS session by putting the `tls-unique` value in the CSR's challenge password. To add it, pass
the key that signs the CSR so the client can sign the request again:

    user@host:$ estclient enroll -server localhost:8443 -explicit anchor.pem -csr csr.pem -signingkey key.pem -out cert.pem

* `tls-unique` exists only in TLS 1.2.
* `-key` and `-signingkey` can differ. `-key` authenticates the TLS connection, as in an initial
  enrollment. `-signingkey` signs the CSR and belongs to the key being enrolled.
* The bundled test server does not check the challenge password. A CA implementation that needs the
  binding must check it.

### Enrolling with a server-generated private key

If we're unable or unwilling to create our own private key, the EST server can
generate one for us, and return it along with our certificate:

    user@host:$ estclient serverkeygen -server localhost:8443 -explicit anchor.pem -cn 'Jane Doe' -out cert.pem -keyout key.pem

Note that we can omit the `-csr` option when enrolling and the EST client can
dynamically generate a CSR for us using fields passed at the command line and
the private key we specified, or an automatically-generated ephemeral private
key if we are requesting server-side private key generation.

### Reenrolling

Whichever way we generated our private key, we can now use it to reenroll.

To reenroll a previously obtained certificate, we must use it to authenticate
ourselves during the TLS handshake with the EST server. Since our random,
transient CA uses an intermediate CA certificate, we must provide a chain of
certificates to the EST client, or the TLS handshake may fail.

Although providing the root CA certificate is optional for a TLS handshake,
the simplest option is to provide the certificate we received along with the
full chain of CA certificates which we previously obtained. To do this, we
can just append those CA certificates to the certificate we received, and
use that chain to reenroll:

    user@host:$ cat cert.pem cacerts.pem >> certs.pem
    user@host:$ estclient reenroll -server localhost:8443 -explicit anchor.pem -key key.pem -certs certs.pem -out newcert.pem

Note that when we omit the `-csr` option when reenrolling, the EST client
automatically generates a CSR for us by copying the subject field and subject
alternative name extension from the certificate we're renewing.

## Features

| Operation | Coverage |
| --- | --- |
| `/cacerts` | CA certificate distribution |
| `/simpleenroll` and `/simplereenroll` | Enrollment and reenrollment with a PKCS#10 request |
| `/serverkeygen` | Server-generated private keys, returned with or without additional encryption |
| `/csrattrs` | CSR attributes |
| `/tpmenroll` | Non-standard enrollment of TPM 2.0 keys with the credential protocol in Part 1, section 24 of the TPM 2.0 Library specification |
| `/fullcmc` | Not implemented |

Every operation accepts the optional additional path segment. The server can require HTTP Basic
authentication on top of TLS client certificates. Following RFC 8951, receivers ignore the
`Content-Transfer-Encoding` header and accept whitespace in base64.

`/serverkeygen` returns any PKCS#8 key the CA provides, including ML-KEM. It ignores the request
signature, because RFC 7030 section 4.4.1 tells the server to.

### Embedding the server

`NewRouter` returns an `http.Handler` that serves EST next to the host application's own
endpoints. These [`ServerConfig`](https://pkg.go.dev/github.com/misiektoja/go-pki-est#ServerConfig)
fields hand decisions to the host:

* `CheckBasicAuth` checks every enrollment request, also one without a password, so the host can
  accept a client certificate instead. It can answer 401, 403 or 429 with `Retry-After`.
* `CheckBearerToken` checks the token of an `Authorization: Bearer` header (RFC 6750) in place of
  `CheckBasicAuth`. Without it a bearer token is not checked and does not sign a client in.
* `CheckCSRSignature` verifies CSR signatures that `crypto/x509` cannot, such as composite ML-DSA.
* `VerifyClientCertificate` checks the client certificate of a renewal in place of the check
  against `/cacerts`, for certificates `crypto/x509` cannot verify, such as those an SLH-DSA CA
  signed. The Subject and SubjectAltName comparison still runs first.
* `Refusals` reports requests refused before they reach the CA, for audit records or rate limits.
* `PasswordRenewal` lets `/simplereenroll` accept a password `CheckBasicAuth` accepted or a bearer
  token `CheckBearerToken` accepted instead of a client certificate, as RFC 7030 section 2.3
  allows. It is off by default.
* `OmitTransferEncoding` drops the `Content-Transfer-Encoding` header for clients that reject it.
* `OmitStrictTransportSecurity` drops the `Strict-Transport-Security` header, so the host can send
  its own value or none.
* `MaxRequestBody` raises the 64 KiB request limit for CSRs of large post-quantum keys. An
  SLH-DSA-SHA2-256f CSR is about 67 KB in base64. Keep it below 4 MiB, because `/tpmenroll`
  decodes a PKCS#7 part recursively and a structure nested about 10 MB deep ends the process.

The additional path segment of a request may be at most 255 bytes. A longer one answers 414. The
server keeps the CA certificates of at most 1024 segments for client certificate checks.

**TLS-SRP** (RFC 5054) signs a client in with a username and password during the TLS handshake,
as libest does with `--srp`. A host that terminates TLS-SRP passes the username to the router with
`WithSRPUsername`. `CheckBasicAuth` and the CA read it with `SRPUsernameFromContext`.
`/simplereenroll` then accepts the request without a client certificate. As with
`PasswordRenewal`, the CA receives a nil certificate and decides which certificate is renewed. It
must choose it by the signed-in identity, not by the CSR subject. The server also leaves
revocation checks to the CA. `estserver` serves TLS-SRP and the client signs in with it through
[go-tls-srp](https://github.com/misiektoja/go-tls-srp).

### Embedding the client

These [`Client`](https://pkg.go.dev/github.com/misiektoja/go-pki-est#Client) fields let an
application watch and relax the client:

* `WrapTransport` wraps the HTTP transport of every request, for example to record a protocol
  trace with each request and response.
* `OnConnect` receives the TLS connection of each operation after the handshake, for example to
  show the TLS version, cipher suite and server certificate.
* `AllowCertificateChain` accepts an enrollment response that carries the CA chain next to the
  issued certificate. RFC 7030 section 4.2.3 allows only the issued certificate, so the client
  refuses such a response by default.
* `SRPUsername` and `SRPPassword` sign in with **TLS-SRP** instead of a certificate check of the
  server, as RFC 7030 section 3.3.3 allows. The password authenticates both sides, so the trust
  anchors and client certificates are not used. TLS-SRP runs over TLS 1.2, so the `tls-unique`
  challenge password works. `SRPMinGroupBits` sets the smallest SRP group the client accepts.
  The default is 2048 bits.
* `Proxy` chooses the proxy for the connection to the EST server, like `http.Transport.Proxy`.
  When it is nil, the `HTTPS_PROXY` and `NO_PROXY` environment variables apply. The client
  tunnels through an `http` or `https` proxy with `CONNECT`, so TLS-SRP, `OnConnect` and the
  `tls-unique` value work as without a proxy. Credentials in the proxy URL are sent as Basic
  `Proxy-Authorization`.
* `BearerToken` signs in with an HTTP bearer token (RFC 6750), sent as `Authorization: Bearer`
  on every request. `Username` and `Password` take precedence.
* `MaxResponseBody` raises the 1 MiB limit on a response body, for a chain of large post-quantum
  CA certificates.

The client does not follow redirects. A 3xx answer is returned as an error with its status.

### Post-quantum algorithms

**ML-DSA** (FIPS 204, RFC 9881) works for enrollment, renewal and `/serverkeygen` in the library
and in `estclient`. The tests use ML-DSA-65. Limits:

* An ML-DSA client certificate needs TLS 1.3, which has no `tls-unique` value. The client then
  leaves out the proof of possession challenge password.
* **Composite ML-DSA** requests need `CheckCSRSignature`, and the client cannot create them. No
  TLS library presents a composite client certificate, so composite certificates renew with
  `PasswordRenewal` or TLS-SRP.
* **ML-KEM** keys cannot sign a CSR, so they can only come from `/serverkeygen`.
* **SLH-DSA** (FIPS 205, RFC 9909) requests need `CheckCSRSignature`, and the client cannot
  create them. The SHA2-256f and SHAKE-256f sets also need a larger `MaxRequestBody`. TLS has no
  standard signature scheme for SLH-DSA keys, so these certificates renew with `PasswordRenewal`
  or TLS-SRP.
* A certificate that an **SLH-DSA or composite ML-DSA CA** signed renews over TLS only with
  `VerifyClientCertificate`, because `crypto/x509` cannot verify it. The listener must then request
  the client certificate without verifying it, with `tls.RequestClientCert`.

## Credits

This project began as a fork of [globalsign/est](https://github.com/globalsign/est) by
[GMO GlobalSign](https://www.globalsign.com/). The protocol implementation, both command line tools
and the test server come from that project. The first fixes made here were offered upstream in
[globalsign/est#59](https://github.com/globalsign/est/pull/59) to
[globalsign/est#66](https://github.com/globalsign/est/pull/66).

This fork is maintained separately so fixes and new features ship in its own releases without
waiting for upstream review. Changes that suit upstream are still offered there. [NOTICE](NOTICE)
records the attribution.

## Support and contributing

[SUPPORT.md](SUPPORT.md) says where to ask questions and what to include in a bug report. Report
vulnerabilities privately as [SECURITY.md](SECURITY.md) describes. The
[Contributing Guide](CONTRIBUTING.md) lists the development checks and the
[Code of conduct](CODE_OF_CONDUCT.md) applies to every project space.
[CHANGELOG.md](CHANGELOG.md) records the changes in each release and
[DEPENDENCIES.md](DEPENDENCIES.md) lists the third-party modules and their licenses.

## License

MIT License. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
