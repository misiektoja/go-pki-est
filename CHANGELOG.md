# Changelog

Notable changes to go-pki-est. Entries for 1.0.6 and earlier come from
[globalsign/est](https://github.com/globalsign/est). Its v1.0.7 release has no entry here.

## [1.1.0] - TBD

The first release of go-pki-est, a separately maintained fork of globalsign/est v1.0.7 under a new
module path. It fixes client timeouts, the TLS 1.2 proof-of-possession password, server error
responses and several `estclient` and `estserver` defects. The server no longer trusts
client-supplied address headers unless configured to. New `ServerConfig` fields let a host
application authenticate by client certificate, verify other signature algorithms and record
refused requests.

### Added
- **Host authentication results.** `CheckBasicAuth` runs for every enrollment request, also
  without an `Authorization` header, so a host can accept a TLS client certificate. An `Error`
  with status 403 or 429 is sent as is, with its `Retry-After` value. Other errors still answer
  401 with a Basic challenge.
- **`ServerConfig.CheckCSRSignature`** replaces the PKCS#10 signature check, for algorithms
  `crypto/x509` cannot verify. A request whose algorithm the default check does not support gets
  a 400 that says so.
- **`ServerConfig.Refusals`** receives each request the server refused before asking the CA, with
  the operation, the additional path segment, the status and the reason. Authentication failures
  and CA errors are not reported.
- **`ServerConfig.OmitTransferEncoding`** leaves the `Content-Transfer-Encoding` header out of
  responses and their parts. Bodies stay base64 encoded.

### Changed
- **Module path** is `github.com/misiektoja/go-pki-est`. The package name stays `est`, so only
  import paths change.
- **Go 1.27.1** or newer is required.
- **Proxy address headers** (`X-Real-IP` and `X-Forwarded-For`) are trusted only when
  `ServerConfig.TrustProxyHeaders` or the `estserver` setting `trust_proxy_headers` is true. Both
  default to false, so the server sees the connection's peer address. Deployments that rely on
  forwarded addresses must enable the setting. Enable it only behind a proxy that removes or
  overwrites both headers.
- **`User-Agent` and `Server` headers** and the `version` output name go-pki-est instead of
  GlobalSign.
- **`estclient serverkeygen -keyout`** removes group and other read and write permissions from an
  existing output file on Unix before writing the private key. This also removes group access that
  was set on purpose. Windows ACLs are unchanged.

### Fixed
- **Client timeouts** cover connection setup, so a stalled TLS handshake no longer outlives the
  request context or `estclient -timeout`. Each operation closes its connection.
- **Proof of possession over TLS 1.2.** The `tls-unique` challenge password no longer ends with a
  line break, so it matches the value RFC 7030 section 3.5 defines. Adding it keeps the CSR's
  critical extensions and its other supported attributes.
- **Server error responses.** A recovered panic answers 500 instead of an empty 200. A `/tpmenroll`
  request with missing parts gets 400. Reenrollment over plain HTTP gets 403.
- **Request handling.** `/tpmenroll` ignores `Content-Transfer-Encoding` on its parts like the other
  operations. Base64 bodies may contain spaces and tabs as well as line breaks, as RFC 8951 asks. A
  request over the body limit gets 413 instead of 500. Bracketed IPv6 entries in `AllowedHosts`,
  such as `[::1]`, match. Multipart errors name the right part. A request over `RateLimit` gets
  `Retry-After: 1` with its 429.
- **Reenrollment trust.** When `/cacerts` holds no self-signed certificate, reenrollment client
  certificates are no longer checked against the operating system's root store. They must chain to
  a self-signed certificate in the `/cacerts` response.
- **`/serverkeygen`** returns PKCS#8 keys of algorithms `crypto/x509` cannot parse, such as ML-KEM,
  instead of failing with 500.
- **`estclient`.** Boolean flags set to false, such as `-insecure=false`, are no longer treated as
  true. TPM key paths resolve against the configuration file's directory. A missing TPM private key
  setting or HSM `key_id` reports an error instead of crashing. `serverkeygen` and `tpmenroll`
  report failures to write the key or certificate.
- **`estserver`** exits with an error when it cannot listen instead of running without a listener.
  A TLS configuration without `listen_address` keeps the default port 8443 instead of 443.

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

[1.0.6]: https://github.com/globalsign/est/compare/v1.0.5...v1.0.6
[1.0.5]: https://github.com/globalsign/est/compare/v1.0.4...v1.0.5
[1.0.4]: https://github.com/globalsign/est/compare/v1.0.3...v1.0.4
[1.0.3]: https://github.com/globalsign/est/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/globalsign/est/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/globalsign/est/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/globalsign/est/releases/tag/v1.0.0
