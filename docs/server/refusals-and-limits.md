# Refusals and limits

The router refuses some requests itself, before or instead of calling the CA. This page lists those
refusals, how to record them and the limits that protect the server.

## Requests the router refuses

| Status | Message | Cause |
| --- | --- | --- |
| 400 | `host not allowed` | The `Host` header names a host that `AllowedHosts` does not list |
| 400 | `invalid base64 encoding` | The body is not base64 |
| 400 | `malformed PKCS10 certificate signing request` | The body is not a PKCS #10 request |
| 400 | `invalid PKCS10 certificate signing request signature` | The request signature does not verify |
| 400 | `unsupported PKCS10 certificate signing request signature algorithm` | `crypto/x509` cannot verify the signature algorithm or `CheckCSRSignature` returned `x509.ErrUnsupportedAlgorithm` |
| 403 | `client certificate must be provided for /simplereenroll` | A renewal without a certificate, TLS-SRP or password renewal |
| 403 | `Subject and SubjectAltName fields in CSR must be identical to certificate being renewed` | A renewal that changes the names |
| 403 | `invalid client certificate` | The renewal certificate does not verify |
| 413 | `request body too large` | The body is larger than `MaxRequestBody` |
| 414 | `additional path segment too long` | The additional path segment is longer than 255 bytes |
| 415 | `Content-Type must be application/pkcs10` | A `POST` with another content type. `/tpmenroll` asks for `multipart/mixed` |
| 415 | `malformed or missing Content-Type header` | A `POST` without a valid `Content-Type` |
| 429 | `rate limit exceeded` | More requests than `RateLimit` allows, with `Retry-After: 1` |

`/tpmenroll` adds its own checks of the multipart body and the TPM public areas, such as 422
`public key in public area doesn't match`. See [TPM enrollment](../client/tpm.md).

The body of a refusal is the text `<status> <message>` and a newline. A request for an unknown path
answers 404 and a known path with the wrong method 405. Authentication failures answer as
[Authentication](authentication.md) describes.

## Recording refusals

`ServerConfig.Refusals` receives every refusal in the table above, so a host can count them, log
them in its own format or alert on them:

```go
--8<-- "example_test.go:refusals"
```

`ExampleRefusalRecorder` in `example_test.go` sends a renewal without a client certificate and
prints:

```text
refused simplereenroll: 403 client certificate must be provided for /simplereenroll
client: 403 client certificate must be provided for /simplereenroll
```

* `Refusal` holds the operation, such as `simpleenroll`, the additional path segment, the status,
  the message and the request. The body of the request may already have been read.
* `RecordRefusal` runs before the response is written, with a context that the client cannot
  cancel. Bound its work, because the client waits for it.
* An error from `RecordRefusal` is logged and does not change the response.
* The recorder does not receive refusals from `CheckBasicAuth` and `CheckBearerToken` or errors from
  the CA. It does receive refusals from `CheckCSRSignature` and `VerifyClientCertificate`. It never
  receives answers with status 500 or higher.

## Limits

### Request size

`MaxRequestBody` bounds the body of a `POST` request, 64 KiB by default. A larger body answers 413.
Raise it for large post-quantum requests: an SLH-DSA-SHA2-256f request takes about 67 KB in
base64. Keep it below 4 MiB, because `/tpmenroll` decodes its PKCS #7 part with a parser that
recurses once per nested structure and a body nested deep enough ends the process. `NewRouter`
refuses a negative value.

### Request rate

`RateLimit` limits all requests to the router together, in requests per second, with bursts of up
to twice that number. It is one limit for all clients, not one per client. A request over the limit
answers 429 with `Retry-After: 1`. Without `RateLimit` there is no limit. `NewRouter` refuses a
negative value.

For limits per client or per account, return an `est.Error` with status 429 and a `Retry-After`
value from a hook. A TLS-SRP server can refuse a client before the costly handshake, see
[TLS-SRP](tls-srp.md#unknown-usernames).

### Request time

`Timeout` cancels the request context after the given time, 60 seconds by default. The router does
not stop a CA that ignores the context. A CA that returns the context error answers 500, because
that error is not an `est.Error`. Return an `est.Error` with status 503 or 504 to give the client
another status.

Set the timeouts of the `http.Server` too. `ReadHeaderTimeout` limits slow clients before the
router sees the request.

### Additional path segments

A segment may be at most 255 bytes. The router keeps the `CACerts` result of at most 1024 segments
for its renewal check. Any client can add an entry through `/cacerts`, so the bound keeps random
segments from filling memory.

### Hosts

`AllowedHosts` refuses requests whose `Host` header names another host with 400
`host not allowed`. Names compare without case and without the port. IPv6 addresses may be listed
with or without brackets. Without `AllowedHosts` every host name is accepted.
