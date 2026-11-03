# ServerConfig

`NewRouter(&est.ServerConfig{...})` returns the EST handler. Only `CA` is required for a working
server. `NewRouter` fails when `PasswordRenewal` is set without `CheckBasicAuth` or
`CheckBearerToken` or when `MaxRequestBody` or `RateLimit` is negative. The package documentation
on [pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-est#ServerConfig) has the full
comments.

## Fields

| Field | Default | Meaning | Guide |
| --- | --- | --- | --- |
| `CA` | Required | Issues certificates and answers the EST operations | [The CA interface](../server/ca.md) |
| `Logger` | No logging | Receives one entry per request and the causes of 500 answers | [Logging](../server/embedding.md#logging) |
| `CheckBasicAuth` | None | Checks every request to the enrollment operations and `/healthcheck` that `CheckBearerToken` does not check, including bearer requests when `CheckBearerToken` is nil | [Authentication](../server/authentication.md) |
| `CheckBearerToken` | None | Checks requests with `Authorization: Bearer` | [Authentication](../server/authentication.md) |
| `PasswordRenewal` | false | Renew without a client certificate after a password or token sign-in | [Password renewal](../server/authentication.md#password-renewal) |
| `CheckCSRSignature` | `CheckSignature` of `crypto/x509` | Verifies request signatures, for algorithms `crypto/x509` lacks | [Post-quantum algorithms](../post-quantum.md) |
| `VerifyClientCertificate` | Chain check against `CA.CACerts` | Checks the client certificate of a renewal | [Custom certificate verification](../server/authentication.md#custom-certificate-verification) |
| `Refusals` | None | Receives the requests the router refuses itself | [Recording refusals](../server/refusals-and-limits.md#recording-refusals) |
| `MaxRequestBody` | 64 KiB | Largest request body in bytes. Larger bodies answer 413 | [Request size](../server/refusals-and-limits.md#request-size) |
| `RateLimit` | No limit | Requests per second for all clients together, with bursts of twice that | [Request rate](../server/refusals-and-limits.md#request-rate) |
| `Timeout` | 60 seconds | Cancels the request context after this time | [Request time](../server/refusals-and-limits.md#request-time) |
| `AllowedHosts` | Any host | `Host` names to accept. Others answer 400 | [Hosts](../server/refusals-and-limits.md#hosts) |
| `TrustProxyHeaders` | false | Set `r.RemoteAddr` from `X-Real-IP` or `X-Forwarded-For`, for the logs, the hooks and the CA | [Behind a load balancer](../server/embedding.md#behind-a-load-balancer) |
| `OmitTransferEncoding` | false | Leave out `Content-Transfer-Encoding` | [Response headers](../server/embedding.md#response-headers) |
| `OmitStrictTransportSecurity` | false | Leave out `Strict-Transport-Security: max-age=31536000` | [Response headers](../server/embedding.md#response-headers) |

## Hook signatures

```text
CheckBasicAuth(ctx context.Context, r *http.Request, aps, username, password string) error
CheckBearerToken(ctx context.Context, r *http.Request, aps, token string) error
CheckCSRSignature(csr *x509.CertificateRequest) error
VerifyClientCertificate(ctx context.Context, r *http.Request, aps string, cert *x509.Certificate) error
RecordRefusal(ctx context.Context, refusal est.Refusal) error
```

## The CA interface

```text
CACerts(ctx, aps, r) ([]*x509.Certificate, error)
CSRAttrs(ctx, aps, r) (est.CSRAttrs, error)
Enroll(ctx, csr, aps, r) (*x509.Certificate, error)
Reenroll(ctx, cert, csr, aps, r) (*x509.Certificate, error)
ServerKeyGen(ctx, csr, aps, r) (*x509.Certificate, []byte, error)
TPMEnroll(ctx, csr, ekCerts, ekPub, akPub, aps, r) (credBlob, encSeed, cred []byte, err error)
```

All methods take `ctx context.Context`, `aps string` and `r *http.Request`. See
[The CA interface](../server/ca.md) for what each must return.

## Context helpers

| Function | Use |
| --- | --- |
| `LoggerFromContext(ctx)` | The server logger inside the CA and the hooks |
| `WithSRPUsername(ctx, username)` | Passes the username of a TLS-SRP connection to the router |
| `SRPUsernameFromContext(ctx)` | The TLS-SRP username or empty |

## Fixed limits

* An additional path segment is at most 255 bytes. Longer ones answer 414.
* The renewal check keeps the `CACerts` result of at most 1024 path segments, each for 5 minutes.
