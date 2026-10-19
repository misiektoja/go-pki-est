# Changelog

Notable changes to go-pki-est. Entries for 1.0.7 and earlier come from
[globalsign/est](https://github.com/globalsign/est).

## [1.2.0] - TBD

The request size limit can be raised for CSRs of large post-quantum keys. The host can check the
client certificate of a renewal itself.

### Added
- **`ServerConfig.MaxRequestBody`** sets the request size limit in bytes. Larger requests get 413.
  The default stays 64 KiB, which refuses CSRs of the largest SLH-DSA keys, such as
  SLH-DSA-SHA2-256f at about 67 KB in base64. `NewRouter` refuses a negative value.
- **`ServerConfig.VerifyClientCertificate`** checks the TLS client certificate of a
  `/simplereenroll` request in place of the built-in check against the `/cacerts` certificates.
  It renews certificates that `crypto/x509` cannot verify, such as those an SLH-DSA or composite
  ML-DSA CA signed. Without it, renewal behaves as before.

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

[1.1.0]: https://github.com/misiektoja/go-pki-est/releases/tag/v1.1.0
[1.0.7]: https://github.com/globalsign/est/compare/v1.0.6...v1.0.7
[1.0.6]: https://github.com/globalsign/est/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/globalsign/est/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/globalsign/est/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/globalsign/est/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/globalsign/est/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/globalsign/est/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/globalsign/est/releases/tag/v1.0.0
