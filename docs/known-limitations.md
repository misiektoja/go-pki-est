# Known limitations

## Protocol

* **No `/fullcmc`.** Full CMC (RFC 7030 section 4.3) is not implemented. A request answers 404.
* **No CMS error responses.** RFC 7030 section 4.2.3 allows an enrollment error as a CMC simple PKI
  response. The router sends errors as plain text and the client reads only plain text, JSON or
  empty bodies as messages.
* **No HTTP Digest authentication.** The client signs in with Basic, a bearer token, a client
  certificate or TLS-SRP. A server that asks for Digest, such as libest with `-h`, answers 401.
* **No automatic retry.** A 202 answer returns an error with `RetryAfter`. The caller schedules the
  retry.
* **Redirects are refused.** RFC 7030 allows redirects within the same origin, but the client
  follows none.

## Proof of possession

* **The router does not check the `tls-unique` challenge password.** The CA compares it with the
  connection when it wants the binding.
* **TLS 1.3 has no `tls-unique` value.** The client adds no challenge password over TLS 1.3, which
  includes every renewal with an ML-DSA certificate.

## Post-quantum algorithms

* **Composite ML-DSA and SLH-DSA** need `CheckCSRSignature` and, for client certificates that such
  a CA signed, `VerifyClientCertificate`. The library brings no implementation of either.
* **Certificates with composite ML-DSA or SLH-DSA keys cannot renew over TLS.** `crypto/tls` cannot
  present them. Use password renewal or TLS-SRP.
* **`estclient serverkeygen` cannot write ML-KEM keys.** The library returns them.

See [Post-quantum algorithms](post-quantum.md).

## Server

* **No revocation check on renewal.** The CA must refuse revoked certificates itself.
* **The rate limit is server-wide.** Limits per client belong in a hook.
* **The router must terminate TLS.** A proxy that terminates TLS in front of it hides the client
  certificate.
* **TLS-SRP needs a second listener** from go-tls-srp. It runs TLS 1.2 only.

## Command line tools

* **`estserver` is for testing.** Its mock CA issues to anyone, without authentication.
* **`estclient` has no TLS-SRP options** and no options for `AllowCertificateChain` or
  `MaxResponseBody`.
* **`estclient` cannot read `ENCRYPTED PRIVATE KEY` files.** Only keys encrypted in the legacy PEM
  format prompt for a passphrase.
* **`estclient tpmenroll` is not tested against a TPM.** No test activates a credential on a TPM
  device.

## Interoperability

Only Cisco libest 3.2.0 has been run against the client with recorded results. Its
`/serverkeygen` responses cannot be read, because the server declares a short `Content-Length`. See
[Interoperability](interoperability.md).
