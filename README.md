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
* [Scope](#scope)
* [Getting started](#getting-started)
* [Documentation](#documentation)
* [Limitations](#limitations)
* [Credits](#credits)
* [Support](#support)
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

## Scope

| Standard | Coverage | Enabled by |
| --- | --- | --- |
| RFC 7030 EST | `/cacerts`, `/csrattrs`, `/simpleenroll`, `/simplereenroll` and `/serverkeygen`, with or without an additional path segment | Always |
| RFC 7030 section 3.5 | `tls-unique` proof of possession over TLS 1.2 | `Client.SigningKey`. The CA checks the value |
| RFC 7030 section 2.3 | Renewal with a password or token instead of the certificate | `ServerConfig.PasswordRenewal` |
| RFC 7030 section 3.3.3 and RFC 5054 | TLS-SRP sign-in without certificates | `Client.SRPUsername` and a [go-tls-srp](https://github.com/misiektoja/go-tls-srp) listener |
| RFC 6750 | Bearer tokens | `Client.BearerToken` and `ServerConfig.CheckBearerToken` |
| RFC 8951 | Whitespace in base64 and the `Content-Transfer-Encoding` header ignored | Always |
| TPM 2.0 credential protection | `/tpmenroll`, an operation outside RFC 7030 | `CA.TPMEnroll` |

ML-DSA keys work for enrollment, renewal over TLS 1.3 and server-generated keys. Composite ML-DSA
and SLH-DSA requests need a signature hook, because Go cannot verify them. `/fullcmc` is not
implemented.

## Getting started

Enroll a key with an EST server that asks for a password:

```go
client := &est.Client{
	Host:           "est.example.com:8443",
	ExplicitAnchor: anchor, // *x509.CertPool with the root of the EST server
	Username:       "device-1",
	Password:       "one-time-secret",
}
cert, err := client.Enroll(ctx, csr) // csr is a parsed *x509.CertificateRequest
if err != nil {
	log.Fatal(err)
}
```

To serve EST, implement the `CA` interface and pass it to `est.NewRouter`, which returns an
`http.Handler` for your TLS server.

[Getting started](https://misiektoja.github.io/go-pki-est/getting-started/) runs `estserver` and
enrolls, renews and gets a server-generated key with `estclient`, then shows the same from Go.

## Documentation

Full documentation is at [misiektoja.github.io/go-pki-est](https://misiektoja.github.io/go-pki-est/).

* [Getting started](https://misiektoja.github.io/go-pki-est/getting-started/)
* [Support matrix](https://misiektoja.github.io/go-pki-est/support-matrix/)
* [Architecture](https://misiektoja.github.io/go-pki-est/architecture/)
* [Enrollment and renewal](https://misiektoja.github.io/go-pki-est/client/enrollment/) and [Signing in](https://misiektoja.github.io/go-pki-est/client/authentication/)
* [Embedding the server](https://misiektoja.github.io/go-pki-est/server/embedding/) and [The CA interface](https://misiektoja.github.io/go-pki-est/server/ca/)
* [Server authentication](https://misiektoja.github.io/go-pki-est/server/authentication/) and [TLS-SRP](https://misiektoja.github.io/go-pki-est/server/tls-srp/)
* [Post-quantum algorithms](https://misiektoja.github.io/go-pki-est/post-quantum/)
* [estclient](https://misiektoja.github.io/go-pki-est/tools/estclient/) and [estserver](https://misiektoja.github.io/go-pki-est/tools/estserver/)
* [Troubleshooting](https://misiektoja.github.io/go-pki-est/operations/troubleshooting/)
* [Security model](https://misiektoja.github.io/go-pki-est/security/security-model/) and [Verifying a release](https://misiektoja.github.io/go-pki-est/security/verifying-releases/)

The package documentation on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-est)
describes every exported type.

## Limitations

* No `/fullcmc` and no CMS error responses.
* The router does not check the `tls-unique` value or revocation. The CA does.
* TLS 1.3 has no `tls-unique` value, so ML-DSA renewals carry no binding.
* Composite ML-DSA and SLH-DSA need host hooks and cannot renew over TLS.
* `estserver` issues to anyone and is for testing only.

[Known limitations](https://misiektoja.github.io/go-pki-est/known-limitations/) explains each gap.

## Credits

This project began as a fork of [globalsign/est](https://github.com/globalsign/est) by
[GMO GlobalSign](https://www.globalsign.com/). The protocol implementation, both command line tools
and the test server come from that project. The first fixes made here were offered upstream in
[globalsign/est#59](https://github.com/globalsign/est/pull/59) to
[globalsign/est#66](https://github.com/globalsign/est/pull/66).

This fork is maintained separately so fixes and new features ship in its own releases without
waiting for upstream review. Changes that suit upstream are still offered there.
[NOTICE](NOTICE) records the attribution.

## Support

[SUPPORT.md](SUPPORT.md) says where to ask questions and what to include in a bug report. Check
[Troubleshooting](https://misiektoja.github.io/go-pki-est/operations/troubleshooting/) first.
Report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes. The
[Contributing Guide](CONTRIBUTING.md) lists the development checks and the
[Code of conduct](CODE_OF_CONDUCT.md) applies to every project space.
[CHANGELOG.md](CHANGELOG.md) records the changes in each release and
[DEPENDENCIES.md](DEPENDENCIES.md) lists the third-party modules and their licenses.

## License

MIT License. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
