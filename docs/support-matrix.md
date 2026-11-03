# Support matrix

What the client, the server and the command line tools implement and how it is tested.
[Known limitations](known-limitations.md) explains the gaps.

## Legend

| Status | Meaning |
| --- | --- |
| **Implemented** | Covered by the unit tests, which run the client against the server |
| **Interoperability tested** | `est.Client` was run against an independent EST server, see [Interoperability](interoperability.md). Neither `estclient` nor the server has been run against another implementation |
| **Not implemented** | Out of scope for the current release |

## Operations

| Operation | Client method | estclient command | Status |
| --- | --- | --- | --- |
| `/cacerts` (RFC 7030 section 4.1) | `CACerts` | `cacerts` | Implemented, interoperability tested |
| `/csrattrs` (section 4.5) | `CSRAttrs` | `csrattrs` | Implemented, interoperability tested |
| `/simpleenroll` (section 4.2) | `Enroll` | `enroll` | Implemented, interoperability tested |
| `/simplereenroll` (section 4.2.2) | `Reenroll` | `reenroll` | Implemented, interoperability tested |
| `/serverkeygen` (section 4.4) | `ServerKeyGen` | `serverkeygen` | Implemented. The libest 3.2.0 response is truncated, see [Interoperability](interoperability.md) |
| `/tpmenroll` (not standard) | `TPMEnroll` | `tpmenroll` | Implemented. The command needs a TPM 2.0 device and is not tested in CI |
| `/fullcmc` (section 4.3) | None | None | Not implemented |

The server serves every implemented operation at `/.well-known/est/<operation>` and, with an
additional path segment (section 3.2.2), at `/.well-known/est/<segment>/<operation>`.

## Authentication

| Method | Client | Server | Status |
| --- | --- | --- | --- |
| TLS client certificate (section 3.3.2) | `Certificates` and `PrivateKey` | Checked by your TLS listener and, for renewal, by the router | Implemented, interoperability tested |
| HTTP Basic (section 3.2.3) | `Username` and `Password` | `CheckBasicAuth` | Implemented, interoperability tested |
| Bearer token (RFC 6750) | `BearerToken` | `CheckBearerToken` | Implemented |
| TLS-SRP (section 3.3.3, RFC 5054) | `SRPUsername` and `SRPPassword` | `WithSRPUsername` from a TLS-SRP listener | Implemented, interoperability tested for `Enroll` |
| Renewal with a password or token (section 2.3) | `Reenroll` without a certificate | `PasswordRenewal` | Implemented, interoperability tested against libest with a password |
| `tls-unique` proof of possession (section 3.5) | `SigningKey`, an RSA or ECDSA key, over TLS 1.2 only | Left to the CA | Implemented, interoperability tested |
| HTTP Digest | None | None | Not implemented |

## Keys and signatures

| Key type | Enrollment request | Renewal over TLS | Server-generated |
| --- | --- | --- | --- |
| RSA, ECDSA, Ed25519 | Verified by `crypto/x509` | Yes | Any PKCS #8 key the CA returns |
| ML-DSA (FIPS 204, RFC 9881) | Verified by `crypto/x509`. The tests use ML-DSA-65 | Yes, over TLS 1.3 | Yes |
| SLH-DSA (FIPS 205, RFC 9909) | Needs `CheckCSRSignature`. `crypto/x509` cannot create the request | With `PasswordRenewal` or TLS-SRP | Yes |
| Composite ML-DSA | Needs `CheckCSRSignature`. `crypto/x509` cannot create the request | With `PasswordRenewal` or TLS-SRP | Yes |
| ML-KEM (FIPS 203) | Cannot sign a request | Not applicable | Yes |

[Post-quantum algorithms](post-quantum.md) explains each limit. A certificate that an SLH-DSA or
composite ML-DSA CA signed renews over TLS only with `VerifyClientCertificate`.

## Encoding and transport

| Behavior | Coverage |
| --- | --- |
| Base64 bodies (section 4) | Sent wrapped at 76 characters. Spaces, tabs and line breaks are accepted on receipt, as RFC 8951 section 3.1 asks |
| `Content-Transfer-Encoding` (RFC 8951) | Ignored on receipt. The server sends it unless `OmitTransferEncoding` is set |
| `Retry-After` (section 4.2.3) | The client returns it with the status as `Error.RetryAfter`, from seconds or an HTTP date. It does not wait or retry |
| Redirects (section 3.2.1) | The client returns a 3xx as an error and never follows it |
| HTTP proxies | The client tunnels through `http` and `https` proxies with `CONNECT` |
| TLS versions | The client accepts TLS 1.2 and 1.3. TLS-SRP runs over TLS 1.2 only |

## Platforms

CI builds and tests the module on Linux and macOS and builds it on Windows. The Linux job also runs
the `estclient` tests that sign with a SoftHSM key. No CI job has a TPM, so the TPM tests of
`estclient` are skipped everywhere.
