# Compatibility

## Versioning

The module uses semantic versioning. The library API is the exported identifiers of the root
package `est`. Other modules cannot import the packages under `internal`. Changes to the options
and configuration fields of `estclient` and `estserver` are recorded in the changelog too.

[CHANGELOG.md](https://github.com/misiektoja/go-pki-est/blob/main/CHANGELOG.md) has one section
per version and describes every change that affects callers, including any that needs a code
change.

## Upgrading

* **Structs gain fields in minor releases**, as `MaxRequestBody` did in 1.2.0. Construct `Client`,
  `ServerConfig` and `Refusal` with field names.
* Read the changelog sections between your version and the new one before upgrading. A change
  that a peer can observe, such as a new status code or header, is listed there.

## Go version

`go.mod` declares the minimum Go version, currently 1.27.3. CI builds and tests with the version in
`go.mod`. Go 1.27.3 fixes GO-2026-6809 in `crypto/x509`, which the server reaches when it verifies
client certificates.

## Moving from globalsign/est

go-pki-est continues globalsign/est v1.0.7 under a new module path. Its versions continue from
v1.0.7, so v1.1.0 is the first release here.

1. Replace the import path `github.com/globalsign/est` with `github.com/misiektoja/go-pki-est`.
   The package name stays `est`.
2. Read the changelog sections from 1.1.0 on. The changes that affect existing code:
    * Go 1.27.3 or newer is required. globalsign/est v1.0.7 declared Go 1.23.0.
    * `X-Real-IP` and `X-Forwarded-For` are ignored unless `TrustProxyHeaders` is set.
      `True-Client-IP` stays ignored, as in v1.0.7.
    * A 405 answer carries an `Allow` header that lists the supported methods.
    * `CheckBasicAuth` runs for every enrollment request, also one without credentials, so a hook
      that treated empty credentials as a mistake must accept or refuse them on purpose.
    * The `User-Agent` and `Server` headers name go-pki-est.
    * Renewals no longer fall back to the system roots when they verify client certificates.
    * The client refuses redirects and bounds response bodies.
3. `estserver` listens on `localhost:8443` by default. Set `tls.listen_address` to serve other
   hosts.

Clones of globalsign/est carry its `v1.0.x` tags, which declare the old module path. `go get`
cannot fetch those tags under the new path.
