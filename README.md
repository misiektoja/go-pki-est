# go-pki-est

[![Go Reference](https://pkg.go.dev/badge/github.com/misiektoja/go-pki-est.svg)](https://pkg.go.dev/github.com/misiektoja/go-pki-est)
[![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)
[![Tests](https://github.com/misiektoja/go-pki-est/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/misiektoja/go-pki-est/actions/workflows/go.yml)

Go library for **Enrollment over Secure Transport (EST)**, the certificate enrollment protocol
defined in [RFC 7030](https://www.rfc-editor.org/rfc/rfc7030). It provides:

* an EST client library
* an `http.Handler` that serves EST in front of your CA (`NewRouter` and the `CA` interface)
* `estclient`, a command line client built on the library
* `estserver`, a server with a mock CA for testing and development

## Contents

* [Install](#install)
* [Scope](#scope)
* [Quickstart](#quickstart)
* [Credits](#credits)
* [Support and contributing](#support-and-contributing)
* [License](#license)

## Install

```bash
go get github.com/misiektoja/go-pki-est
```

The package name is `est`. Requires Go 1.27.1 or newer.

The command line tools install with:

```bash
go install github.com/misiektoja/go-pki-est/cmd/estclient@latest
```

```bash
go install github.com/misiektoja/go-pki-est/cmd/estserver@latest
```

## Scope

| Operation | Coverage |
| --- | --- |
| `/cacerts` | CA certificate distribution |
| `/simpleenroll` and `/simplereenroll` | Enrollment and reenrollment with a PKCS#10 request |
| `/serverkeygen` | Server-generated private keys, returned with or without additional encryption |
| `/csrattrs` | CSR attributes |
| `/tpmenroll` | Non-standard enrollment of TPM 2.0 keys with the credential protocol in Part 1, section 24 of the TPM 2.0 Library specification |
| `/fullcmc` | Not implemented |

Every operation accepts the optional additional path segment. The server can require HTTP Basic
authentication on top of TLS client certificates. RFC 8951 is only partly applied: messages still
carry the `Content-Transfer-Encoding` header.

## Quickstart

### Starting the server

When started with no configuration file, the EST server listens on port 8443 on every interface and
generates a random, transient Certificate Authority (CA) which can be used for testing:

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

Report vulnerabilities privately as [SECURITY.md](SECURITY.md) describes. The
[Contributing Guide](CONTRIBUTING.md) lists the development checks. [CHANGELOG.md](CHANGELOG.md)
records the changes in each release.

## License

MIT License. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
