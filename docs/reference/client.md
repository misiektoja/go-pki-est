# Client

`est.Client` runs EST operations against one server. Every field is optional except `Host`. A
client may be reused and each call opens its own connection. The package documentation on
[pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-est#Client) has the full comments.

## Methods

| Method | Operation | Returns |
| --- | --- | --- |
| `CACerts(ctx)` | `GET /cacerts` | The CA certificates in the order the server sent them |
| `CSRAttrs(ctx)` | `GET /csrattrs` | The attributes, with OIDs and attributes listed separately |
| `Enroll(ctx, csr)` | `POST /simpleenroll` | The issued certificate |
| `Reenroll(ctx, csr)` | `POST /simplereenroll` | The renewed certificate |
| `ServerKeyGen(ctx, csr)` | `POST /serverkeygen` | The certificate and the key bytes, PKCS #8 or CMS |
| `TPMEnroll(ctx, csr, ekCerts, ekPub, akPub)` | `POST /tpmenroll` | The encrypted credential, the encrypted seed and the encrypted certificate |

Each method sends the request as given in `csr.Raw`, except that `SigningKey` may add a challenge
password. An answer other than 200 returns an `est.Error`, see [Errors](errors.md).

## Server and trust

| Field | Default | Meaning |
| --- | --- | --- |
| `Host` | Required | `host:port` of the server, without a path |
| `AdditionalPathSegment` | None | The label between `/.well-known/est/` and the operation |
| `ExplicitAnchor` | None | Roots that verify the server. Used alone when set |
| `ImplicitAnchor` | System roots | Roots used when `ExplicitAnchor` is nil |
| `InsecureSkipVerify` | false | Accept any server certificate. Only to fetch CA certificates for out-of-band checking |
| `HostHeader` | The host of `Host` | Overrides the HTTP `Host` header |

## Client authentication

| Field | Meaning |
| --- | --- |
| `Certificates` | The TLS client certificate first, then the intermediates the server needs |
| `PrivateKey` | The key of the client certificate. Any `crypto.Signer`, including HSM and TPM keys |
| `SigningKey` | Adds the `tls-unique` challenge password over TLS 1.2 and signs the request again with this key |
| `Username`, `Password` | HTTP Basic credentials |
| `BearerToken` | Sent as `Authorization: Bearer` when `Username` is empty |
| `SRPUsername`, `SRPPassword` | Sign in with TLS-SRP over TLS 1.2. The anchors, `InsecureSkipVerify` and `Certificates` are then not used |
| `SRPMinGroupBits` | Smallest SRP group accepted, 2048 bits by default |

See [Signing in](../client/authentication.md).

## Requests and responses

| Field | Default | Meaning |
| --- | --- | --- |
| `AdditionalHeaders` | None | Extra HTTP headers on every request |
| `Proxy` | `http.ProxyFromEnvironment` | Chooses an `http` or `https` proxy for a `CONNECT` tunnel. A nil URL connects directly |
| `DisableKeepAlives` | false | Sends `Connection: close` with every request |
| `AllowCertificateChain` | false | Accept an enrollment response that also carries CA certificates |
| `MaxResponseBody` | 1 MiB | Largest response body. A negative value fails every call |
| `WrapTransport` | None | Wraps the HTTP transport, for example to trace requests |
| `OnConnect` | None | Receives the connection after the handshake |

See [Connections and hooks](../client/connections.md).

## Fixed behavior

* The TLS connection uses the `crypto/tls` defaults, which require TLS 1.2 or newer.
* The client never follows redirects.
* It sends `User-Agent: go-pki-est EST client v1.4.0 github.com/misiektoja/go-pki-est`, with the
  library version.
* It has no timeout of its own. The context of each call bounds the proxy tunnel, the handshake
  and the request.

## CSR attributes

`CSRAttrs` holds two lists. `OIDs` has the bare object identifiers. `Attributes` has the
attributes, each with a `Type` and `Values`. Values of type OBJECT IDENTIFIER, BOOLEAN, INTEGER and most string types are decoded into
`asn1.ObjectIdentifier`, `bool`, `*big.Int` and `string`. Other values stay `asn1.RawValue`.
`Marshal` and `Unmarshal` convert to and from the DER of RFC 7030 section 4.5.2, which a CA uses to
answer `/csrattrs`.
