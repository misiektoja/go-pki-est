# Changelog

Notable changes to go-pki-est. Entries for 1.0.7 and earlier come from
[globalsign/est](https://github.com/globalsign/est).

## [1.4.0] - TBD

The client connects through an HTTP proxy, from the environment or a `Proxy` function of the
host, and signs in with a bearer token. It refuses redirects that could carry its credentials to
an `http` URL and bounds response bodies. The server checks bearer tokens with a new hook and
bounds the CA certificate cache, which a peer could grow without limit. `estserver` listens on
localhost by default and `estclient` does not write through symbolic links.

### Added
- **HTTP proxies.** `Client.Proxy` chooses the proxy for the connection to the EST server, like
  `http.Transport.Proxy`. When it is nil, `HTTPS_PROXY` and `NO_PROXY` apply, where no proxy was
  used before. The client tunnels through an `http` or `https` proxy with `CONNECT`, so TLS-SRP,
  `OnConnect` and the `tls-unique` value work as without a proxy. Credentials in the proxy URL
  are sent as Basic `Proxy-Authorization`.
- **Bearer tokens.** `Client.BearerToken` signs in with an HTTP bearer token (RFC 6750), sent as
  `Authorization: Bearer <token>` on every request. `Username` takes precedence. A server checks
  the token with `ServerConfig.CheckBearerToken`, which runs in place of `CheckBasicAuth` for a
  request that carries one and answers 401 with a Bearer challenge. `PasswordRenewal` also
  accepts a bearer token that hook accepted for `/simplereenroll` without a client certificate.
  Without the hook a token is not checked and does not sign a client in.
- **estclient `-proxy` and `-token`.** The example client connects through an HTTP proxy and
  signs in with a bearer token. The configuration file takes them as `proxy` and `token`.

### Changed
- **`estserver` listens on `localhost:8443` by default.** It listened on every interface with a
  mock CA that issues a certificate to anyone. Set `listen_address` in the `tls` section to serve
  other hosts.
- **`CA.Reenroll` documentation** states that the server does not check revocation and that a
  CA must choose the certificate of a login renewal by the signed-in identity, not by the CSR
  subject.

### Fixed
- **Server error messages are safe to print.** The client passed the error message of a server
  response on unchanged, so a malicious server could send terminal escape sequences that
  `estclient` printed. Control characters other than newline and tab are now escaped, such as
  `\x1b`.
- **The client refuses redirects.** It followed up to ten redirects and resent its Basic
  credentials or bearer token to an `http` URL on the same host in cleartext, without the proxy
  settings. RFC 7030 section 3.2.1 allows only redirects within the same origin and the client
  talks to the one server it was configured with, so a 3xx answer is now returned as an error
  with its status.
- **Response bodies are bounded.** The client read every response whole, so a server could make
  it allocate memory without limit. A 13 MB response of nested PKCS#7 structures ended the
  process with a stack overflow. **`Client.MaxResponseBody`** bounds a response body, including
  an error message and the parts of a multipart response. The default is 1 MiB. For the same
  reason a server's `MaxRequestBody` should stay below 4 MiB, because `/tpmenroll` decodes a
  PKCS#7 part.
- **The CA certificate cache is bounded.** The server kept the `/cacerts` result of every
  additional path segment a client named, with no limit on their number or length. When the CA
  answers unknown segments, as the mock CA does, a peer could grow the server's memory with one
  request per segment until the process died. A segment may now be at most 255 bytes and a longer
  one answers 414. The cache keeps at most 1024 segments and drops the least recently updated one
  first.
- **A negative `RateLimit` is refused.** `NewRouter` served without any rate limit for a negative
  value. It now returns an error, as it does for a negative `MaxRequestBody`.
- **`estserver` drops slow and idle connections.** A client could hold a connection and its
  handler by sending the request body slowly or hold a keep-alive connection without sending a
  request. The TLS and TLS-SRP listeners now give a request 60 seconds to arrive and close an
  idle connection after 120 seconds.
- **`estclient` does not write through symbolic links.** `-out`, `-keyout` and `-separateout`
  followed a symbolic link, so a link planted in a shared directory could send a private key or
  certificate to another file. A link is now refused with an error that names it.

## [1.3.1] - 2026-10-22

The client sends the length of every request body, so it can enroll with servers that cannot
read a chunked body, such as the Cisco libest example server.

### Fixed
- **Request bodies carry a `Content-Length`.** `Enroll`, `Reenroll`, `ServerKeyGen` and
  `TPMEnroll` sent their bodies with `Transfer-Encoding: chunked`. Servers without chunked
  request support, such as the libest 3.2.0 example server, answered with HTTP 400 or closed the
  connection.

## [1.3.0] - 2026-10-21

The client can sign in with TLS-SRP and gives the host more control: it can wrap the HTTP
transport, see each connection and accept an enrollment response that carries the CA chain. The
module now needs Go 1.27.3 and go-tls-srp v0.2.0.

### Added
- **TLS-SRP client.** `Client.SRPUsername` and `Client.SRPPassword` sign in with TLS-SRP
  (RFC 7030 section 3.3.3) instead of checking a server certificate. The password authenticates
  both sides, so the trust anchors and client certificates are not used. TLS-SRP runs over TLS
  1.2, so the `tls-unique` challenge password works. `Client.SRPMinGroupBits` sets the smallest
  SRP group the client accepts. The default is 2048 bits.
- **`Client.WrapTransport`** wraps the HTTP transport of each operation, for example to log or
  record requests and responses.
- **`Client.OnConnect`** receives each connection after its handshake, so the host can read the
  TLS version and the server certificates. For TLS-SRP it receives a `*srptls.Conn`.
- **`Client.AllowCertificateChain`** accepts an enrollment response that carries the CA chain next
  to the issued certificate. The client returns the certificate that issued none of the others.
  RFC 7030 section 4.2.3 allows only the issued certificate, so such a response is still refused
  by default.

### Changed
- **Go 1.27.3** or newer is required. It fixes GO-2026-6809 in `crypto/x509`, which the server
  reaches when it verifies client certificates.

## [1.2.0] - 2026-10-20

The request size limit can be raised for CSRs of large post-quantum keys. The host can check the
client certificate of a renewal itself and choose whether the server sends HSTS. The server router
moves to chi v5. The client no longer panics on a truncated error response.

### Added
- **`ServerConfig.MaxRequestBody`** sets the request size limit in bytes. Larger requests get 413.
  The default stays 64 KiB, which refuses CSRs of the largest SLH-DSA keys, such as
  SLH-DSA-SHA2-256f at about 67 KB in base64. `NewRouter` refuses a negative value.
- **`ServerConfig.VerifyClientCertificate`** checks the TLS client certificate of a
  `/simplereenroll` request in place of the built-in check against the `/cacerts` certificates.
  It renews certificates that `crypto/x509` cannot verify, such as those an SLH-DSA or composite
  ML-DSA CA signed. The TLS listener must then request the certificate without verifying it, for
  example with `tls.RequestClientCert`. Without the hook, renewal behaves as before.
- **`ServerConfig.OmitStrictTransportSecurity`** leaves the `Strict-Transport-Security` header out
  of responses, so the host can send its own value or none. By default the server still sends
  `max-age=31536000`.

### Changed
- **chi v5.** The server router uses `github.com/go-chi/chi/v5` v5.5.0 instead of chi v4.1.2.
  govulncheck flags v4 for an open-redirect advisory that has no v4 fix, although this module
  never called the affected middleware. A 405 response now lists the supported methods in an
  `Allow` header. Proxy address headers work as before. `True-Client-IP` is ignored.
- **`estclient -version` and `estserver -version`** report 1.2.0.

### Fixed
- **Truncated error responses.** When the body of an error response ends early, client calls
  return an `est.Error` with the HTTP status and `Retry-After` value instead of a bare read
  error. `CSRAttrs` no longer panics in that case.
- **`estclient` TPM handles.** A `persistent_handle` or `storage_handle` that does not fit in 32
  bits is refused. It was truncated to a different handle before.
- **`estserver` request headers** must arrive within 30 seconds, as on the TLS-SRP port. A client
  that never finishes its headers no longer holds a connection open.

## [1.1.0] - 2026-10-19

First release of go-pki-est, a separately maintained fork of globalsign/est v1.0.7 under a new
module path. Its version numbers continue from v1.0.7. It adds TLS-SRP logins, password renewal,
ML-DSA support and hooks for host authentication. It fixes client timeouts, password sign-in from
libest and Bouncy Castle and several server and command line defects.

### Added
- **ML-DSA** keys and certificates work for enrollment, renewal and `/serverkeygen`, in the
  library and in `estclient`. Renewal with an ML-DSA client certificate needs TLS 1.3.
- **Password renewal.** With `ServerConfig.PasswordRenewal`, `/simplereenroll` accepts a password
  instead of a client certificate, for certificates that cannot be used in TLS, such as composite
  ML-DSA. It is off by default and needs `CheckBasicAuth`.
- **TLS-SRP logins.** `WithSRPUsername` passes the username of a TLS-SRP connection to
  `CheckBasicAuth` and the CA. `/simplereenroll` accepts such a request without a client
  certificate. The `estserver` setting `tls_srp` serves a second port from an OpenSSL srpvfile.
- **Host authentication.** `CheckBasicAuth` runs for every enrollment request, also without a
  password, so a host can accept a client certificate instead. It can answer 403 or 429 with
  `Retry-After`.
- **`ServerConfig` hooks.** `CheckCSRSignature` verifies algorithms `crypto/x509` cannot.
  `Refusals` reports requests refused before they reach the CA. `OmitTransferEncoding` drops the
  `Content-Transfer-Encoding` header.

### Changed
- **Module path** is `github.com/misiektoja/go-pki-est`. The package name stays `est`. Go 1.27.2
  or newer is required.
- **Proxy address headers** `X-Real-IP` and `X-Forwarded-For` are ignored unless
  `ServerConfig.TrustProxyHeaders` or the `estserver` setting `trust_proxy_headers` is true.
  Enable it only behind a proxy that overwrites both headers.
- **`User-Agent` and `Server` headers** name go-pki-est instead of GlobalSign.
- **`estclient serverkeygen -keyout`** makes an existing key file private to its owner on Unix
  before writing.

### Fixed
- **Client timeouts** cover the TLS handshake.
- **Proof of possession over TLS 1.2.** The `tls-unique` challenge password matches RFC 7030
  section 3.5.
- **libest and Bouncy Castle** can sign in with a password. The 401 challenge is sent as
  `WWW-Authenticate` without a body.
- **Server responses.** A panic answers 500, a malformed request 400, an oversized body 413 and
  reenrollment over plain HTTP 403. Base64 bodies may contain spaces and tabs, as RFC 8951
  allows.
- **Reenrollment trust** no longer falls back to the operating system's root store.
- **`/serverkeygen`** returns keys that `crypto/x509` cannot parse, such as ML-KEM. It ignores the
  request's signature, as RFC 7030 section 4.4.1 asks.
- **`estclient` and `estserver`.** `-flag=false` works. TPM key paths resolve against the
  configuration file. `estserver` exits when it cannot listen.

## [1.0.7] - 2025-11-19
### Added
- `estclient cacerts` writes each CA certificate to its own file with `-separate` and selects
  root or intermediate certificates with `-roots` and `-intermediates`.
- The client adds the challenge password attribute when the server requires it. The new
  `SigningKey` field signs such requests.

### Changed
- Receivers ignore the `Content-Transfer-Encoding` header, following RFC 8951.
- Go 1.23 or newer is required. go-tpm is updated to v0.9.6 and golang.org/x/crypto to
  v0.35.0.
- The client sends all requests through one HTTP client.

### Fixed
- Parsing a malformed certificate returns an error instead of panicking.
- `estclient` help no longer shows a path argument for the `-rootout` switch.

## [1.0.6] - 2021-02-21
### Added
- Windows build capability.

## [1.0.5] - 2021-02-19
### Changed
- Update go-tpm package version.

## [1.0.4] - 2020-09-08
### Changed
- Update client error processing.

## [1.0.3] - 2020-08-10
### Changed
- Break all HTTP messages with a base64 Content-Transfer-Encoding into lines.

## [1.0.2] - 2020-06-03
### Changed
- Minor bug fixes and quality enhancements.

## [1.0.1] - 2020-06-02
### Added
- Travis CI integration

## [1.0.0] - 2020-05-28
### Added
- Initial release

[1.4.0]: https://github.com/misiektoja/go-pki-est/releases/tag/v1.4.0
[1.3.1]: https://github.com/misiektoja/go-pki-est/releases/tag/v1.3.1
[1.3.0]: https://github.com/misiektoja/go-pki-est/releases/tag/v1.3.0
[1.2.0]: https://github.com/misiektoja/go-pki-est/releases/tag/v1.2.0
[1.1.0]: https://github.com/misiektoja/go-pki-est/releases/tag/v1.1.0
[1.0.7]: https://github.com/globalsign/est/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/globalsign/est/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/globalsign/est/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/globalsign/est/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/globalsign/est/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/globalsign/est/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/globalsign/est/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/globalsign/est/releases/tag/v1.0.0
