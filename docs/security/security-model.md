# Security model

This page says what the library protects, what it leaves to the host and what it assumes. Report
vulnerabilities privately as
[SECURITY.md](https://github.com/misiektoja/go-pki-est/blob/main/SECURITY.md) describes.

## Roles

* **The host** runs the router behind its own TLS listener, decides who may enroll with the hooks
  and owns the CA.
* **The router** parses requests, enforces the RFC 7030 renewal rules and the limits and calls the
  CA.
* **The CA** decides what to issue.
* **The client** verifies the server, authenticates itself and parses the responses.

## What the router enforces

* **Request format.** Bodies must be base64 DER of the expected type and within `MaxRequestBody`.
  Request signatures are checked before the CA is called, except for `/serverkeygen`, which RFC
  7030 section 4.4.1 exempts.
* **Renewal identity.** A renewal over TLS must present a certificate that chains to the
  `CACerts` roots, is valid now and allows client authentication. The request must repeat its
  Subject and SubjectAltName byte for byte. The system roots are never used for this check.
* **Authentication results.** When a hook is set, a request it refuses never reaches the CA.
* **Bounded resources.** Request bodies, additional path segments and the CA certificate cache
  are bounded. `RateLimit` and `Timeout` add server-wide limits.
* **No leaked internals.** An error that is not an `est.Error` answers 500 without its text. Panics
  are recovered.

## What the host must do

* **Configure TLS.** The router sees only what `http.Request.TLS` holds. The listener chooses the
  protocol versions, the client certificate policy and `ClientCAs`.
* **Authenticate enrollments.** Without hooks every client that completes the handshake may
  enroll and use `/serverkeygen`. `CheckBearerToken` alone does not require a token, see
  [Authentication](../server/authentication.md).
* **Apply issuance policy in the CA.** The router does not check which names a request may contain,
  which key types are allowed or whether a `tls-unique` challenge password matches the connection.
* **Check revocation.** The renewal check does not consult CRLs or OCSP. A CA that revokes must
  refuse a revoked certificate in `Reenroll`.
* **Bind password renewals to the signed-in identity.** With TLS-SRP or `PasswordRenewal`,
  `Reenroll` receives a nil certificate. The CA must choose the certificate to renew from the
  username or token, never from the Subject of the request.
* **Protect stored secrets.** TLS-SRP needs only verifiers on the server, but passwords for Basic
  authentication and tokens are checked by the host's own code.
* **Set `TrustProxyHeaders` only behind a proxy that overwrites the headers.** Otherwise clients
  choose the address in the log.

## What the client enforces

* The server certificate is verified against `ExplicitAnchor`, `ImplicitAnchor` or the system
  roots, unless `InsecureSkipVerify` is set. TLS-SRP authenticates the server by the password
  instead.
* Redirects are never followed, so credentials do not go to another location.
* Response bodies are bounded by `MaxResponseBody`.
* An enrollment response must carry exactly one certificate unless `AllowCertificateChain` is set.
* Control characters in server error messages are escaped, so printing them cannot drive a
  terminal.
* TLS-SRP refuses groups below 2048 bits by default.

`estclient` adds protections for files. Private keys are written with mode 0600, an existing key
file loses group and other access before it is written and symbolic links are refused as output
paths.

## Assumptions and limits

* **`estserver` is not a production server.** Its mock CA issues to anyone and its operations need
  no authentication.
* **Proof of possession through `tls-unique` needs TLS 1.2.** TLS 1.3 has no such value, so the
  binding is absent from every TLS 1.3 connection, including all ML-DSA renewals.
* **`InsecureSkipVerify` trusts the network.** Use it only to fetch CA certificates that you then
  check out of band.
* **`MaxRequestBody` must stay below 4 MiB.** `/tpmenroll` decodes its PKCS #7 part with a
  recursive parser and a body nested deep enough ends the process.
* **Logs.** The request log holds the method, the URI, the client address and the status. The
  router does not log request bodies or credentials. The causes of 500 answers are logged as the
  CA wrote them.

## Supported versions

Only the latest release receives fixes. See
[SECURITY.md](https://github.com/misiektoja/go-pki-est/blob/main/SECURITY.md) for the severity
tiers and fix targets. [Verifying a release](verifying-releases.md) shows how to check the release
artifacts.
