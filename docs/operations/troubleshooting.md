# Troubleshooting

Each entry starts with a message as `estclient` or the library reports it. The library returns the
same text without the `estclient:` prefix and the command context, such as
`failed to get certificate:`.

## Connecting

**`tls: failed to verify certificate: x509: certificate signed by unknown authority`**

The client does not trust the server certificate. Give the root that issued it with `-explicit` or
`ExplicitAnchor`. For a new server, fetch the roots once with `-insecure`, check their fingerprint
out of band and use them from then on, see [Bootstrapping](../tools/estclient.md#bootstrapping).
`estserver` without a configuration creates a new CA on every start, so an old anchor stops
working after a restart.

**`dial tcp [::1]:8443: connect: connection refused`**

Nothing listens at the address. `estserver` listens on `localhost:8443` by default and only there.
To serve other hosts, add a `tls` section with your own `certificates`, `private_key` and
`client_cas` and set its `listen_address`.

**`failed to make EST client: EST server not specified`**

`-server` is missing on the command line and in the configuration file.

**`proxy <proxy> refused the tunnel to <server>: 407 Proxy Authentication Required`**

The proxy wants credentials. Put them in the proxy URL, such as
`http://user:password@proxy.example.com:3128`. Other statuses come from the proxy's own policy.

**`unsupported proxy scheme "socks5", want http or https`**

Only `http` and `https` proxies are supported. Check `HTTPS_PROXY` when `-proxy` is not set.

## Renewing

**`403 client certificate must be provided for /simplereenroll`**

The server received no client certificate. Check that `-certs` or `Certificates` holds the
certificate **and its intermediates**. Go clients present a certificate only when its chain reaches
a CA that the server names in the handshake, which is usually the root. With the certificate alone
the client sends nothing. A TLS-SRP client or [password renewal](../server/authentication.md#password-renewal)
avoids the certificate.

**`remote error: tls: unknown certificate authority`**

The server refused the client certificate in the handshake. `net/http` logs an
`http: TLS handshake error` with `x509: certificate signed by unknown authority` to the
`ErrorLog` of the `http.Server`, standard error by default. In `estserver` this line goes to
standard error even when `log_file` is set. The listener's `ClientCAs` does not contain the root of the client certificate. In `estserver` a
`tls` section needs `client_cas` for renewals to work.

**`403 Subject and SubjectAltName fields in CSR must be identical to certificate being renewed`**

The request names something else than the certificate being renewed. Leave out `-csr` so
`estclient` copies the names from the certificate or build the request from
`cert.RawSubject` and the certificate's SubjectAltName extension.

**`403 invalid client certificate`**

The certificate does not verify against the roots and intermediates `CA.CACerts` returns, at the
current time, for client authentication. Check that `CACerts` includes the root, that the
certificate has not expired and that it allows client authentication. The router keeps the
`CACerts` result for 5 minutes, so a new root takes effect only once the cached entry is that old.
A `/cacerts` request does not refresh an entry younger than 5 minutes.

## Enrolling

**`no private key provided`**

`estclient enroll` without `-csr` needs `-key` or a key in the configuration file to sign the
generated request.

**`Unauthorized`**

A hook refused the credentials. The router sends no body, so the client reports the status text.
Check `-user` and `-pass` or `-token`. A bearer token counts only when the server sets
`CheckBearerToken`.

**`202 ...` with a `Retry-After` value**

The CA deferred the request. Send the same request again after the given number of seconds. The
library returns the value as `RetryAfter()`. `estclient` does not print it.

**`415 Content-Type must be application/pkcs10`**

A client other than `est.Client` sent the request with another content type. EST requests are
base64 DER with `Content-Type: application/pkcs10`.

**`413 request body too large`**

The request is over `MaxRequestBody`, 64 KiB by default. Large post-quantum requests, such as
SLH-DSA-SHA2-256f, need a higher value.

**`400 unsupported PKCS10 certificate signing request signature algorithm`**

`crypto/x509` cannot verify the signature, for example of a composite ML-DSA or SLH-DSA request.
Set `CheckCSRSignature`, see [Post-quantum algorithms](../post-quantum.md).

**`2 certificates returned`**

The server returned the CA chain with the certificate. Set `AllowCertificateChain` on the client.

**`response body larger than 1048576 bytes`**

A response is over `MaxResponseBody`, 1 MiB by default. Raise it for large post-quantum chains.

**`unrecognized private key format`** from `estclient serverkeygen`

The server returned a key that `crypto/x509` cannot parse, such as ML-KEM. Use the library, whose
`ServerKeyGen` returns the bytes as they are.

## TLS-SRP

**`srptls: server chose the 1536 bit SRP group, below the minimum of 2048 bits`**

The verifier uses a small group. Create it again with `-gn 2048` or larger or lower
`SRPMinGroupBits` if you accept the weaker group. The server logs
`remote error: tls: insufficient security level`.

**`srptls: unknown SRP username`**

The server does not know the user and tells the client so. A server with
`unknown_user_seed` or one that returns `SimulatedVerifier`, answers like a wrong password
instead.

**`srptls: wrong SRP password`**

The password does not match the verifier or the user is unknown and the server hides it.

## Server side

**`500 internal server error`**

The CA returned an error that is not an `est.Error` or panicked. The server log has the cause.
Return an `est.Error` from the CA to send a meaningful status.

**`400 host not allowed`**

The `Host` header names a host that `AllowedHosts` does not list. Names compare without the port.

**`429 rate limit exceeded`**

The server-wide `RateLimit` is used up. Retry after the `Retry-After` value, 1 second.

**`/healthcheck` answers 401**

The health check always needs a hook to accept the request. In `estserver` send the Basic user
`healthcheck` with the configured password, such as `curl -u healthcheck:xyzzy`.
