# Post-quantum algorithms

What works depends on what Go's `crypto/x509` and `crypto/tls` support. Go 1.27 has ML-DSA
(FIPS 204) in `crypto/mldsa` and accepts it in certificates, requests and TLS 1.3. It has no
SLH-DSA (FIPS 205) and no composite ML-DSA. The library hands those algorithms to hooks that the
host fills with another implementation.

| Algorithm | Enroll | Renew with the certificate over TLS | `/serverkeygen` |
| --- | --- | --- | --- |
| ML-DSA-44, ML-DSA-65, ML-DSA-87 | Yes | Yes, over TLS 1.3 | Yes |
| Composite ML-DSA | With `CheckCSRSignature` | No, use password renewal or TLS-SRP | Yes, as PKCS #8 |
| SLH-DSA | With `CheckCSRSignature` | No, use password renewal or TLS-SRP | Yes, as PKCS #8 |
| ML-KEM | No, it cannot sign a request | No | Yes, as PKCS #8 |

The tests and examples use ML-DSA-65. The other rows follow from the code paths described below.

## ML-DSA

An ML-DSA request enrolls like any other. The renewal presents the ML-DSA certificate, which
`crypto/tls` accepts only in TLS 1.3:

```go
--8<-- "example_test.go:mldsa"
```

`ExampleClient_mldsa` in `example_test.go` prints:

```text
enrolled: device-8 with *mldsa.PublicKey
renewing over TLS 1.3
renewed: device-8
```

* **No `tls-unique` binding.** TLS 1.3 has no `tls-unique` value, so the client leaves the
  challenge password out of the request even when `SigningKey` is set. A server that requires the
  binding refuses ML-DSA renewals over TLS.
* **The listener must allow TLS 1.3**, which `crypto/tls` does by default.
* `estclient` enrolls and renews with an ML-DSA key in a PKCS #8 PEM file given with `-key`.

## Composite ML-DSA and SLH-DSA

### Requests

`crypto/x509` parses these requests but cannot verify their signatures, so the router answers 400
`unsupported PKCS10 certificate signing request signature algorithm` by default. Set
`CheckCSRSignature` to verify them with another implementation:

* Return nil to accept the request. The CA receives it with a nil `PublicKey`, because
  `crypto/x509` does not know the key type. The CA reads the key from `RawSubjectPublicKeyInfo`.
* Return an `est.Error` to send its status. Any other error answers 400
  `invalid PKCS10 certificate signing request signature`.

`/serverkeygen` never calls the hook, because RFC 7030 section 4.4.1 tells the server to ignore the
request signature.

Go cannot sign these requests. Build them with another library and parse them with
`x509.ParseCertificateRequest`. `est.Client` sends the bytes of the parsed request as they are.

### Request size

An SLH-DSA-SHA2-256f signature alone is 49,856 bytes, so the request takes about 67 KB in base64.
That is over the 64 KiB default of `MaxRequestBody`. Raise it and raise the client's
`MaxResponseBody` when the CA chain uses such certificates. See
[Refusals and limits](server/refusals-and-limits.md#request-size).

### Renewal

TLS has no signature scheme that `crypto/tls` offers for composite ML-DSA or SLH-DSA keys, so a
client cannot present such a certificate in the handshake. Renew these certificates with
[password renewal](server/authentication.md#password-renewal) or [TLS-SRP](server/tls-srp.md).

### Certificates that a post-quantum CA signed

A client certificate with a classical or ML-DSA key may be signed by an SLH-DSA or composite
ML-DSA CA. `crypto/x509` cannot verify that signature, so the built-in renewal check refuses it. Set
`VerifyClientCertificate` to check the certificate with another implementation and configure the
listener with `ClientAuth: tls.RequestClientCert`. With `VerifyClientCertIfGiven` or
`RequireAndVerifyClientCert`, `crypto/tls` refuses the certificate before the router sees it.

The router still compares the request with the certificate before it calls the hook. See
[Custom certificate verification](server/authentication.md#custom-certificate-verification).

## ML-KEM

ML-KEM keys encrypt and cannot sign a request, so they come only from `/serverkeygen`. The router
recognizes PKCS #8 by its structure and sends keys that `crypto/x509` cannot parse, such as ML-KEM,
as they are. `Client.ServerKeyGen` returns the key bytes without parsing them.

`estclient serverkeygen` writes only keys that `crypto/x509` parses or encrypted PKCS #7 keys and
fails with `unrecognized private key format` for an ML-KEM key.

## Key exchange

The hybrid key exchanges `X25519MLKEM768`, `SecP256r1MLKEM768` and `SecP384r1MLKEM1024` are part
of the TLS 1.3 defaults of `crypto/tls`. `est.Client` uses those defaults. A server that leaves
`CurvePreferences` unset offers them too. `estserver` limits its curves to P-521, P-384 and P-256,
so it does not use them.
