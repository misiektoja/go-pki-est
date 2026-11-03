# The CA interface

The router hands every EST operation that passed its checks to a value that implements `est.CA`.
That value is your CA: it may sign in process, call a CA over the network or queue a request for
an operator.

## A minimal CA

This CA signs every request with an in-memory root. It is the CA of the examples in
`example_test.go`. Its `issue` helper, which signs with `x509.CreateCertificate`, is in the same
file:

```go
--8<-- "example_test.go:ca"
```

## What every method receives

* **`ctx`** is the request context. `LoggerFromContext(ctx)` returns the server logger and
  `SRPUsernameFromContext(ctx)` the TLS-SRP username, if any. It ends when the client disconnects
  or `ServerConfig.Timeout` passes.
* **`aps`** is the additional path segment of the request or empty. Use it to select one of several
  CAs or profiles.
* **`r`** is the HTTP request. It carries the headers, the `Host`, the Basic credentials and the TLS
  state. The router has already read the body of a `POST` request.

## Methods

### CACerts

Returns the CA certificates for `/cacerts`. The router sends them in the order returned and also
uses them to check client certificates on renewal: self-signed certificates become the trusted
roots and all others intermediates. **Include the root.** Without a self-signed certificate no
client certificate verifies and every renewal over TLS answers 403 `invalid client certificate`.
The system roots are never used for this check.

For the renewal check the router caches the result per additional path segment for 5 minutes and
for at most 1024 segments. A `/cacerts` request also replaces a cached entry older than that.

### CSRAttrs

Returns the attributes for `/csrattrs`. An empty value is sent as an empty sequence with status
200.

### Enroll

Issues a certificate for `/simpleenroll`. The request is parsed and its signature is checked
before the call. Everything else is policy for the CA: which names it allows, which key types and
whether a `tls-unique` challenge password must match the TLS session. Return exactly one
certificate.

### Reenroll

Renews a certificate for `/simplereenroll`. `cert` is the TLS client certificate being renewed. The
router has checked that the request repeats its Subject and SubjectAltName and that the
certificate chains to the `CACerts` roots, is within its validity period and allows client
authentication. With `VerifyClientCertificate` set, that hook decides instead of the chain check.

* **The router does not check revocation.** A CA that revokes certificates must refuse a revoked
  `cert` here.
* **`cert` is nil** when the client signed in with TLS-SRP or, with `PasswordRenewal`, with a
  password or bearer token. The CA must then choose the certificate to renew by the signed-in
  identity, never by the Subject of the request, which any client can name. The example above
  shows one way.
* A `ChangeSubjectName` attribute (RFC 7030 section 4.2.2) stays in the request the CA receives.
  The router does not act on it and the Subject and SubjectAltName of the request must still match
  the certificate.

### ServerKeyGen

Generates a key and issues a certificate for `/serverkeygen`. The router does not check the
request signature, as RFC 7030 section 4.4.1 requires, so use only the names of the request. Return
the key in one of two forms:

* **PKCS #8 DER** to send it unencrypted. The router recognizes PKCS #8 by its structure, so keys
  that `crypto/x509` cannot parse, such as ML-KEM, are sent as they are.
* **A CMS SignedData inside an EnvelopedData** to send it encrypted. The router sends anything that
  parses as PKCS #7 with `smime-type=server-generated-key`.

Any other bytes answer 500.

### TPMEnroll

Issues a certificate for `/tpmenroll` and returns the encrypted credential, the encrypted seed and
the certificate inside a CMS EnvelopedData encrypted with the credential. See
[TPM enrollment](../client/tpm.md). A CA that does not offer it returns an error such as 501, as
the example does.

## Errors

An error that implements `est.Error` sets the response:

| Method | Effect |
| --- | --- |
| `StatusCode()` | The HTTP status, such as 400, 403, 202 or 503 |
| `Error()` | The reason, sent as the text body `<status> <reason>` followed by a newline |
| `RetryAfter()` | The `Retry-After` header in seconds, sent when it is above 0 |

Any other error answers 500 `internal server error` and is logged with its text, so the client
never sees internal details. A 500 from an `est.Error` is logged too. A panic in the CA is
recovered, logged with its stack and answered with 500.

To defer an enrollment, for example until an operator approves it, return status 202 with a
`Retry-After` value. The client returns both to its caller, see
[Deferred and refused requests](../client/enrollment.md#deferred-and-refused-requests). The router
keeps no state, so the CA must recognize the repeated request itself, for example by its public
key.
