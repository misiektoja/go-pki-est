# Enrollment and renewal

`est.Client` runs one EST operation per method call. Each call opens its own connection, runs the
TLS handshake, sends one request and closes the connection. The context of the call bounds all of
it.

## Creating a client

Only `Host` is required. It is the `host:port` of the server, such as `est.example.com:8443`,
without a scheme or path. The listing in the next section creates a client.

* **`AdditionalPathSegment`** selects one of several CAs that the server offers (RFC 7030
  section 3.2.2). The client then calls `https://<host>/.well-known/est/<segment>/<operation>`.
* **Trust anchors** authenticate the server. `ExplicitAnchor` is used when it is set. Otherwise
  `ImplicitAnchor` is used. When neither is set, the system roots apply.
* **`InsecureSkipVerify`** accepts any server certificate. Use it only to fetch the CA
  certificates once and check them out of band, as [Getting started](../getting-started.md#step-3-get-the-ca-certificates)
  does. Every later call needs a trust anchor.

[Signing in](authentication.md) adds credentials and [Connections and hooks](connections.md)
covers proxies, limits and tracing. [Client fields](../reference/client.md) lists every field.

## Getting the CA certificates

`CACerts` returns every certificate of the `/cacerts` response in the order the server sent them.
In this listing and the ones below, `ctx` is a context with a deadline, such as one from
`context.WithTimeout`:

```go
--8<-- "example_test.go:client-enroll"
```

The same listing shows `Enroll`. It sends a PKCS #10 request, usually created with
`x509.CreateCertificateRequest` and returns the issued certificate.

RFC 7030 section 4.2.3 allows only the issued certificate in the response. Some servers add the CA
chain. The client refuses such a response unless `AllowCertificateChain` is set, see
[Connections and hooks](connections.md#accepting-a-chain-in-the-response).

## Binding the request to the TLS session

RFC 7030 section 3.5 lets the client put the `tls-unique` value of the TLS session into the
challenge password of the CSR, which proves that the requester holds the key on this connection.
Set `SigningKey` to the key that signs the CSR. The client then signs the request again with the
challenge password added, in `Enroll` and `Reenroll`.

* `SigningKey` must be an **RSA or ECDSA** key. Over TLS 1.2 another key, such as Ed25519 or
  ML-DSA, fails the call with `x509: only RSA and ECDSA keys supported`.
* `tls-unique` exists only in **TLS 1.2**. Over TLS 1.3 the client sends the request unchanged.
  TLS-SRP always runs over TLS 1.2, so the binding works there.
* The client has no setting to cap the TLS version. Against a server that offers TLS 1.3 the
  binding is never added.
* The router does **not** check the challenge password. A CA that requires the binding must
  compare it with the session itself.

## Renewing a certificate

`Reenroll` renews a certificate. The certificate being renewed authenticates the TLS connection,
so set `Certificates` and `PrivateKey`:

```go
--8<-- "example_test.go:client-reenroll"
```

* **The request must repeat the Subject and the SubjectAltName extension** of the certificate,
  byte for byte, as RFC 7030 section 4.2.2 requires. A go-pki-est server refuses any difference
  with 403. Building the request from `RawSubject` and the names of the certificate keeps both
  equal. A new key is allowed, so the same call rekeys.
* **Send the intermediates.** `Certificates` holds the client certificate first and the CA
  certificates the server needs to build the chain after it. When the server names the CAs it
  accepts, the Go TLS client presents the certificate only if one of the certificates in the list
  was issued by one of them. Otherwise it sends no certificate. `estserver` names only its root, so without the intermediate the
  client presents nothing and the server answers 403
  `client certificate must be provided for /simplereenroll`.
* Servers may also accept a renewal signed in with a password, a bearer token or TLS-SRP instead
  of the certificate. See [Signing in](authentication.md#renewal-without-the-certificate).

## Server-generated keys

`ServerKeyGen` asks the server to generate the key (RFC 7030 section 4.4). The server ignores the
key and the signature of the request and uses only its names, so a throwaway key may sign it:

```go
--8<-- "example_test.go:serverkeygen"
```

The key comes back as DER bytes in one of two forms:

* **PKCS #8** in an `application/pkcs8` part, when the server adds no encryption. Parse it with
  `x509.ParsePKCS8PrivateKey`. Keys that `crypto/x509` does not know, such as ML-KEM, are returned
  as they are.
* **CMS** in an `application/pkcs7-mime; smime-type=server-generated-key` part, when the server
  encrypts the key. The client returns the CMS bytes without decrypting them. Decrypt them with
  the key or password your CA agreed with the client.

The response must hold exactly two parts, a key and a certificate. Otherwise `ServerKeyGen` fails
with `no certificate returned`, `no private key returned` or `more than 2 parts in HTTP response`.

## CSR attributes

`CSRAttrs` returns the attributes the CA wants in a request (RFC 7030 section 4.5):

```go
--8<-- "example_test.go:csrattrs"
```

`OIDs` holds the bare object identifiers and `Attributes` the attributes with values. Values of
type OBJECT IDENTIFIER, BOOLEAN, INTEGER and most string types become `asn1.ObjectIdentifier`,
`bool`, `*big.Int` and `string`. Other values stay `asn1.RawValue`. A 204 or 404 answer means the
server has no attributes to ask for, so `CSRAttrs` returns an empty value and no error.

## Deferred and refused requests

Every status other than 200 returns an error that implements `est.Error`, including 202 Accepted,
because a deferred enrollment has no certificate yet:

```go
--8<-- "example_test.go:error"
```

`RetryAfter` comes from the `Retry-After` header, given in seconds or as an HTTP date and is 0
without one. The client never retries or polls. Repeat the same call after the delay to collect
the certificate. `Error()` returns the response body, which a go-pki-est server writes as the
status and the reason followed by a newline. [Errors](../reference/errors.md) lists them.

Errors without an HTTP status, such as a failed handshake, a refused proxy tunnel, an expired
context or a response that does not decode, do not implement `est.Error`.
