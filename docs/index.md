# go-pki-est

[![GitHub Release](https://img.shields.io/github/v/release/misiektoja/go-pki-est?style=flat-square&color=blue)](https://github.com/misiektoja/go-pki-est/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pki-est.svg)](https://pkg.go.dev/github.com/misiektoja/go-pki-est)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](https://github.com/misiektoja/go-pki-est/blob/main/LICENSE)
[![Tests](https://github.com/misiektoja/go-pki-est/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-est/actions/workflows/test.yml)
[![Supply chain](https://github.com/misiektoja/go-pki-est/actions/workflows/supply-chain.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-est/actions/workflows/supply-chain.yml)
[![OpenSSF Scorecard](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fapi.scorecard.dev%2Fprojects%2Fgithub.com%2Fmisiektoja%2Fgo-pki-est&query=%24.score&label=openssf%20scorecard&style=flat-square)](https://scorecard.dev/viewer/?uri=github.com/misiektoja/go-pki-est)

go-pki-est is a Go library for **Enrollment over Secure Transport (EST)**, the certificate
enrollment protocol of [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030). It contains:

* an EST **client** for Go programs, `est.Client`
* an EST **server** as an `http.Handler` in front of your CA, built by `est.NewRouter` from your
  implementation of the `CA` interface
* `estclient`, a command line client built on the library
* `estserver`, a test server with a mock CA for development

Clients sign in with TLS client certificates, HTTP Basic, bearer tokens or TLS-SRP passwords.
Certificates can carry post-quantum ML-DSA keys. The [support matrix](support-matrix.md) lists
what is covered.

## Install

```bash
go get github.com/misiektoja/go-pki-est
```

The module needs Go 1.27.3 or newer. The package is imported as `est`. The command line tools
install with:

```bash
go install github.com/misiektoja/go-pki-est/cmd/estclient@latest
```

```bash
go install github.com/misiektoja/go-pki-est/cmd/estserver@latest
```

## Start here

**[Getting started](getting-started.md)** starts `estserver`, enrolls and renews with `estclient`
and then does the same from Go.

## Where to go next

| I want to | Page |
| --- | --- |
| Know which operations, algorithms and peers are covered | [Support matrix](support-matrix.md) |
| Understand how the client, the router and my CA fit together | [Architecture](architecture.md) |
| Enroll, renew or get a server-generated key from Go | [Enrollment and renewal](client/enrollment.md) |
| Sign in with a certificate, a password, a token or TLS-SRP | [Signing in](client/authentication.md) |
| Use a proxy, trace requests or raise limits | [Connections and hooks](client/connections.md) |
| Serve EST in front of my CA | [Embedding the server](server/embedding.md) and [The CA interface](server/ca.md) |
| Decide who may enroll and renew | [Server authentication](server/authentication.md) |
| Use ML-DSA, SLH-DSA, composite ML-DSA or ML-KEM keys | [Post-quantum algorithms](post-quantum.md) |
| Look up a command line flag or configuration key | [estclient](tools/estclient.md) and [estserver](tools/estserver.md) |
| Look up a field | [Client fields](reference/client.md) and [ServerConfig fields](reference/server-config.md) |
| Fix something that does not work | [Troubleshooting](operations/troubleshooting.md) |
| See which servers the client was tested with | [Interoperability](interoperability.md) |
| Understand what is not implemented | [Known limitations](known-limitations.md) |
| Check a downloaded release | [Verifying a release](security/verifying-releases.md) |
| Look up a type or function | [Package documentation](https://pkg.go.dev/github.com/misiektoja/go-pki-est) |
| See what changed in a release | [Changelog](https://github.com/misiektoja/go-pki-est/blob/main/CHANGELOG.md) |
| Ask for help or report a problem | [Support](https://github.com/misiektoja/go-pki-est/blob/main/SUPPORT.md) |

## Design and security

* [Security model](security/security-model.md) - what the library checks and what remains with the host
* [Errors](reference/errors.md) - the statuses and messages the server sends and how the client reports them
* [Compatibility policy](reference/compatibility.md) - what may change between releases

## Contributing

* [Development](development/development.md), [Testing](development/testing.md) and [Release process](development/release-process.md)
* Source and issues: [github.com/misiektoja/go-pki-est](https://github.com/misiektoja/go-pki-est)

## Credits

This project began as a fork of [globalsign/est](https://github.com/globalsign/est) by
[GMO GlobalSign](https://www.globalsign.com/). The protocol implementation, both command line tools
and the test server come from that project. The first fixes made here were offered upstream in
[globalsign/est#59](https://github.com/globalsign/est/pull/59) to
[globalsign/est#66](https://github.com/globalsign/est/pull/66). This fork is maintained separately
so fixes and new features ship in its own releases. Changes that suit upstream are still offered
there. [NOTICE](https://github.com/misiektoja/go-pki-est/blob/main/NOTICE) records the attribution.

## Related projects

Other PKI projects from the same maintainer:

* [certrally](https://misiektoja.github.io/certrally/): a command line client for certificate enrollment over CMP, EST and SCEP
* [cmp-issuer](https://misiektoja.github.io/cmp-issuer/): a cert-manager external issuer for CMP servers
* [go-acme-server](https://misiektoja.github.io/go-acme-server/): an embeddable ACME server library for Go (RFC 8555)
* [go-pki-cmp](https://misiektoja.github.io/go-pki-cmp/): a Go library for the Certificate Management Protocol (CMP) with a client and a server
* [go-pki-scep](https://misiektoja.github.io/go-pki-scep/): a Go library for SCEP (RFC 8894) with a client and a server handler
* [go-pkcs7](https://misiektoja.github.io/go-pkcs7/): a Go library for PKCS #7 and CMS (RFC 5652) signed and enveloped data
* [go-composite-mldsa](https://misiektoja.github.io/go-composite-mldsa/): a Go library for post-quantum composite ML-DSA signatures
* [go-tls-srp](https://github.com/misiektoja/go-tls-srp): TLS 1.2 with SRP password authentication (RFC 5054) for Go
