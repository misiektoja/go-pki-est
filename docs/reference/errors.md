# Errors

## The est.Error interface

```text
type Error interface {
	StatusCode() int
	Error() string
	RetryAfter() int
}
```

Both sides use it. A CA or a hook returns an `est.Error` to choose the HTTP status, the message and
the `Retry-After` value. The client returns one for every answer other than 200.

## Errors the client returns

| Error | Cause |
| --- | --- |
| An `est.Error` | The server answered with another status than 200. 202 is included, so a deferred enrollment is an error with `RetryAfter` set |
| A dial or handshake error, such as `dial tcp [::1]:8443: connect: connection refused` or `tls: failed to verify certificate: x509: certificate signed by unknown authority` | The connection, the proxy tunnel or the handshake failed. These errors are returned without a common prefix |
| `failed to execute HTTP request: ...` | Sending the request or reading the response failed after the handshake, for example when a TLS 1.3 server refuses the client certificate, which the client learns only after its handshake |
| `<n> certificates returned` | An enrollment response carried more than one certificate and `AllowCertificateChain` is not set |
| `<n> certificates returned and <m> of them issued no other` | `AllowCertificateChain` is set, but the response does not hold exactly one certificate that issued none of the others |
| `no certificate returned` | An enrollment response carried no certificate |
| `response body larger than <n> bytes` | A response went over `MaxResponseBody` |
| `MaxResponseBody must not be negative` | The client is misconfigured |
| `unsupported proxy scheme "<scheme>", want http or https` | `Proxy` returned a URL with another scheme |
| `proxy <proxy> refused the tunnel to <server>: <status>` | The proxy answered the `CONNECT` with another status than 200 |
| `srptls: ...` | A TLS-SRP handshake failed, see [Signing in](../client/authentication.md#tls-srp) |

Read the status of an `est.Error` with `errors.AsType`:

```go
--8<-- "example_test.go:error"
```

`ExampleError` in `example_test.go` prints:

```text
status: 202
retry after: 600
message: 202 waiting for approval
```

### The message of an est.Error

* A `text/plain`, JSON or problem JSON body becomes the message as sent. So does a body without a
  content type. The router sends `<status> <reason>` and a newline, so the message starts with the status.
  Trim the newline before printing it.
* An empty body gives the status text, such as `Unauthorized` for a refused sign-in.
* A body of another type gives the status text and the type, such as
  `Bad Request (application/octet-stream)`.
* Control characters other than newline and tab are escaped, such as `\x1b`, so a server cannot
  send terminal escape sequences.

`RetryAfter` returns the `Retry-After` header in seconds. An HTTP date is converted to the seconds
until that time. A missing, invalid or past value gives 0.

## Errors the server sends

Most error responses are `text/plain; charset=utf-8` with the body `<status> <reason>` and a
newline. A 401 carries no body. A 405 has an empty body. An unknown path answers 404 with the body
`404 page not found`.

| Source | Status and body |
| --- | --- |
| The router's own checks | See [Refusals and limits](../server/refusals-and-limits.md#requests-the-router-refuses) |
| `CheckBasicAuth` or `CheckBearerToken` returns an `est.Error` | Its status, message and `Retry-After`, unless the status is 401 |
| `CheckBasicAuth` or `CheckBearerToken` returns another error or an `est.Error` with 401 | 401 with a `WWW-Authenticate` challenge and no body |
| `CheckCSRSignature` or `VerifyClientCertificate` returns an `est.Error` | Its status, message and `Retry-After` |
| `CheckCSRSignature` returns another error | 400 `invalid PKCS10 certificate signing request signature`. An error that wraps `x509.ErrUnsupportedAlgorithm` gives 400 `unsupported PKCS10 certificate signing request signature algorithm` |
| `VerifyClientCertificate` returns another error | 403 `invalid client certificate` |
| The CA returns an `est.Error` | Its status, message and `Retry-After` |
| The CA returns another error or panics | 500 `internal server error`. The cause is logged, not sent |
| `CACerts` fails during the renewal check | The CA error, answered as above |
| An unknown path | 404 `404 page not found` |
| A known path with the wrong method | 405 with an `Allow` header and an empty body |

A 500 from an `est.Error` is logged as well.

## Errors from NewRouter

| Error | Cause |
| --- | --- |
| `PasswordRenewal requires CheckBasicAuth or CheckBearerToken` | `PasswordRenewal` without a hook |
| `MaxRequestBody must not be negative` | A negative `MaxRequestBody` |
| `RateLimit must not be negative` | A negative `RateLimit` |
