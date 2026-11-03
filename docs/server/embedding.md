# Embedding the server

`NewRouter` builds an `http.Handler` that serves EST in front of your CA. You supply the CA as an
implementation of the [`CA` interface](ca.md), decide who may enroll with the
[authentication hooks](authentication.md) and serve the handler with your own `http.Server`.

## A complete server

```go
--8<-- "example_test.go:router"
```

This is `ExampleNewRouter` in `example_test.go`, which `go test` compiles. The example CA in
[The CA interface](ca.md) stands in for yours.

* `NewRouter` fails when `PasswordRenewal` is set without `CheckBasicAuth` or `CheckBearerToken`
  or when `MaxRequestBody` or `RateLimit` is negative. Every other field has a working default.
* The router reads the client certificate from `http.Request.TLS`, so it must run on the server
  that terminates TLS. A reverse proxy in front that terminates TLS hides the certificate and
  renewals fail with 403.

## The TLS listener

The router does not configure TLS. Set up the listener for the clients you expect:

* **`ClientAuth: tls.VerifyClientCertIfGiven`** asks for a certificate without requiring one, so
  one port serves a first enrollment with a password and a renewal with a certificate.
  `RequireAndVerifyClientCert` suits deployments where every client already has a certificate.
* **`ClientCAs`** holds the roots that client certificates must chain to. Go clients, including
  `est.Client`, pick the certificate to present by these names, so a client whose certificate comes from an intermediate
  must send that intermediate, see [Renewing a certificate](../client/enrollment.md#renewing-a-certificate).
* **TLS 1.2** must stay enabled for clients that bind requests with `tls-unique`, which TLS 1.3 does
  not have.
* **`tls.RequestClientCert`** is needed with `VerifyClientCertificate`, because `crypto/tls` would
  otherwise refuse a certificate it cannot verify before the router sees it. See
  [Post-quantum algorithms](../post-quantum.md).

[TLS-SRP](tls-srp.md) needs a listener from go-tls-srp instead of `crypto/tls`.

## Endpoints

| Method and path | Request body | Response | Authentication |
| --- | --- | --- | --- |
| `GET /.well-known/est/cacerts` | None | `application/pkcs7-mime` | None |
| `GET /.well-known/est/csrattrs` | None | `application/csrattrs` | None |
| `POST /.well-known/est/simpleenroll` | `application/pkcs10` | `application/pkcs7-mime; smime-type=certs-only` | Hooks, optional without them |
| `POST /.well-known/est/simplereenroll` | `application/pkcs10` | `application/pkcs7-mime; smime-type=certs-only` | Hooks, plus the renewal checks |
| `POST /.well-known/est/serverkeygen` | `application/pkcs10` | `multipart/mixed` with the key and the certificate | Hooks, optional without them |
| `POST /.well-known/est/tpmenroll` | `multipart/mixed` | `multipart/mixed` with three parts | Hooks, optional without them |
| `GET /healthcheck` | None | 200 with an empty body | Hooks, always required |

* Every EST path also exists with an additional path segment, such as
  `/.well-known/est/devices/simpleenroll`. The CA receives the segment as `aps`. A segment longer
  than 255 bytes answers 414.
* Bodies are base64 in both directions. The router writes 76-character lines and accepts spaces,
  tabs, CR and LF in a request.
* "Optional without them" means the operation is open when neither `CheckBasicAuth` nor
  `CheckBearerToken` is set. `/healthcheck` then always answers 401.
* An unknown path answers 404. A known path with the wrong method answers 405 with an `Allow`
  header.

Mount the router so that it receives the full path, for example with
`mux.Handle("/.well-known/est/", router)` and `mux.Handle("/healthcheck", router)`. Do not strip a
prefix.

## Response headers

Every response carries:

* `Server: go-pki-est EST server v1.4.1`, with the library version
* `Strict-Transport-Security: max-age=31536000`, unless `OmitStrictTransportSecurity` is set
* `X-Content-Type-Options: nosniff`

Base64 response bodies and the parts of multipart responses also carry
`Content-Transfer-Encoding: base64`, which RFC 8951 tells receivers to ignore. Set `OmitTransferEncoding` for clients that fail when it is
present. Error responses are `text/plain; charset=utf-8`.

## Logging

`Logger` receives one entry per request, after the response, with the method, URI, protocol,
remote address, status, bytes written, time taken and request ID. Responses with status 500 are
logged at error level with their cause and so are recovered panics with their stack. The CA reads
the same logger with `LoggerFromContext(ctx)`. Without a logger nothing is logged.

The `Logger` interface has `Errorf`, `Errorw`, `Infof`, `Infow` and `With`. The request ID
comes from chi's `RequestID` middleware, which reuses an incoming `X-Request-Id` header.

## Behind a load balancer

* **`TrustProxyHeaders`** sets `r.RemoteAddr` from `X-Real-IP` or else from the first address in
  `X-Forwarded-For`, so the logs, the hooks, the refusal recorder and the CA all see that address.
  `True-Client-IP` is ignored. Enable it only when every request passes a proxy that removes
  or overwrites both headers. The proxy's own address is not checked.
* **`AllowedHosts`** refuses requests whose `Host` header names another host with 400
  `host not allowed`. Names compare without case and without the port. IPv6 addresses may be
  listed with or without brackets.

A load balancer that passes TCP through keeps client certificates working. One that terminates TLS
does not, as noted above.
