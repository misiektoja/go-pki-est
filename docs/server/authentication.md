# Authentication

The router decides who may run an operation with two optional hooks and checks renewals itself.
`/cacerts` and `/csrattrs` are always open. The hooks run for
`/simpleenroll`, `/simplereenroll`, `/serverkeygen`, `/tpmenroll` and `/healthcheck`.

## The hooks

**`CheckBearerToken`** runs for every request that carries `Authorization: Bearer <token>`. The
prefix `Bearer ` is case-sensitive, so a request with `bearer <token>` counts as one without a token.
**`CheckBasicAuth`** runs for every other request, with empty credentials when the request has no
Basic credentials. That lets it accept a client certificate instead of a password, as the router
example in [Embedding the server](embedding.md) does with `r.TLS.VerifiedChains`.

| Hook result | Response |
| --- | --- |
| `nil` | The request continues |
| An `est.Error` with a status other than 401, such as 403 or 429 | That status, its message and its `Retry-After` value |
| Any other error | 401 with a `WWW-Authenticate` challenge and no body |

Without hooks, the enrollment operations are open to every client that completes the TLS
handshake. The table shows what each combination requires:

| Hooks set | Request without credentials | Request with a bearer token | Request with Basic credentials |
| --- | --- | --- | --- |
| None | Accepted | Accepted, token ignored | Accepted, credentials ignored |
| `CheckBasicAuth` | `CheckBasicAuth` with empty credentials | `CheckBasicAuth` with empty credentials | `CheckBasicAuth` |
| `CheckBearerToken` | **Accepted** | `CheckBearerToken` | **Accepted**, credentials ignored |
| Both | `CheckBasicAuth` with empty credentials | `CheckBearerToken` | `CheckBasicAuth` |

**`CheckBearerToken` alone does not require a token.** Set `CheckBasicAuth` too and return an
error from it to refuse requests that carry no token.

TLS-SRP clients reach the same hooks. `SRPUsernameFromContext(ctx)` returns their username, see
[TLS-SRP](tls-srp.md).

## The 401 challenge

A refused request gets 401 with no body, because some clients, such as Bouncy Castle, fail when
they do not read the content of a challenge. The `WWW-Authenticate` header names the realm
`estserver@<host>` with the host of the request:

* `Basic realm="estserver@est.example.com"` when `CheckBasicAuth` is set or `CheckBearerToken` is not
* `Bearer realm="estserver@est.example.com"` when `CheckBearerToken` is set, followed by
  `, error="invalid_token"` when the request carried a token

Each challenge is a separate header line. The header name is written as `WWW-Authenticate`, the
RFC 9110 spelling, because libest compares header names case-sensitively.

## The health check

`GET /healthcheck` answers 200 with an empty body when a hook accepts the request. Unlike the EST
operations it is never open: without hooks it always answers 401. `estserver` accepts it with the
Basic user `healthcheck` and the configured password.

## Renewal checks

For `/simplereenroll` the router checks the client certificate before it calls `CA.Reenroll`:

1. **A certificate must be present**, unless the client signed in with TLS-SRP or
   [password renewal](#password-renewal) applies. Otherwise: 403
   `client certificate must be provided for /simplereenroll`.
2. **The Subject and the SubjectAltName extension of the request must equal those of the
   certificate**, byte for byte (RFC 7030 section 4.2.2). Otherwise: 403
   `Subject and SubjectAltName fields in CSR must be identical to certificate being renewed`.
3. **The certificate must verify** against the certificates `CA.CACerts` returns for the same path
   segment, at the current time and for client authentication. Otherwise: 403
   `invalid client certificate`. If `CACerts` itself fails, the request fails with that error.

The router uses the first certificate the client presented, so it works with listeners that
request a certificate without verifying it.

### Custom certificate verification

`VerifyClientCertificate` replaces step 3. Use it for certificates that `crypto/x509` cannot
verify, such as certificates an SLH-DSA or composite ML-DSA CA signed. Steps 1 and 2 still run
first. A nil error accepts the certificate, an `est.Error` is sent as is and any other error
answers 403 `invalid client certificate`. The listener must use `tls.RequestClientCert`, see
[Post-quantum algorithms](../post-quantum.md).

## Password renewal

RFC 7030 section 2.3 allows a renewal that a password signs in instead of the certificate being
renewed, for certificates that cannot authenticate TLS. `PasswordRenewal` turns this on:

```go
--8<-- "example_test.go:password-renewal-server"
```

* A renewal without a client certificate is accepted when `CheckBasicAuth` accepted Basic
  credentials with a non-empty username or `CheckBearerToken` accepted a token. A bearer token
  counts only when `CheckBearerToken` is set.
* `NewRouter` refuses `PasswordRenewal` without either hook.
* A client that does present a certificate still goes through all three renewal checks.
* **`CA.Reenroll` receives a nil certificate** and must choose the certificate to renew by the
  signed-in identity, never by the Subject of the request. The CA in
  [The CA interface](ca.md) compares the requested common name with the username.

`PasswordRenewal` is off by default.

## Proof of possession

The router does not check the `tls-unique` challenge password that a client adds with
`SigningKey`. A CA that requires the binding compares the challenge password in the request with
the `tls-unique` value of the connection, which `r.TLS.TLSUnique` holds for TLS 1.2. Over TLS-SRP
`r.TLS` is nil, so the host passes the value of the go-tls-srp connection to the CA itself, for
example in the request context.
