# TLS-SRP

RFC 7030 section 3.3.3 lets a client sign in with TLS-SRP (RFC 5054) instead of a certificate. The
client proves that it knows a password and the server proves that it holds the verifier made from
that password, so neither side needs a certificate. This suits devices that are provisioned with a
username and password and have no trust anchor yet.

The TLS-SRP stack is [go-tls-srp](https://github.com/misiektoja/go-tls-srp), a trimmed copy of
`crypto/tls` with the SRP cipher suites only. It runs TLS 1.2 without certificates, session
resumption or renegotiation.

## Serving EST over TLS-SRP

The router stays the same. Only the listener and a small handler around the router change:

```go
--8<-- "example_test.go:srp-server"
```

This is `ExampleWithSRPUsername` in `example_test.go`. The client side of the same example is in
[Signing in](../client/authentication.md#tls-srp).

* **`GetVerifier`** returns the stored verifier of the username in the ClientHello. It is the only
  required field of `srptls.Config` on the server.
* **`ConnContext` and the handler** pass the username to the router. `net/http` sets
  `Request.TLS` only for `crypto/tls` connections, so `r.TLS` stays nil and the handler reads the
  username from the go-tls-srp connection. `est.WithSRPUsername` stores it in the request context.
* **The hooks** run as for any other client. `est.SRPUsernameFromContext(ctx)` returns the
  username and `CheckBasicAuth` receives empty credentials unless the client also sent HTTP Basic
  credentials. Without hooks every client that completes the handshake may enroll.
* **Renewal** needs no client certificate. The router skips its certificate checks and
  `CA.Reenroll` receives a nil certificate. The CA must choose the certificate to renew by the
  username, never by the Subject of the request. See [The CA interface](ca.md#reenroll).
* Log entries show the scheme `https` for TLS-SRP requests, the same as for TLS.

A server can offer TLS and TLS-SRP on two ports with the same router, as `estserver` does.

## Storing verifiers

Store the group, the salt and the verifier of each user when you register the device. The server
never needs the password:

* `srptls.GroupByBits` returns one of the seven RFC 5054 groups: 1024, 1536, 2048, 3072, 4096, 6144
  or 8192 bits. Clients that use go-tls-srp, including `est.Client`, refuse groups below 2048 bits
  unless `SRPMinGroupBits` allows them.
* `srptls.NewSalt` returns a 20-byte random salt without a leading zero byte, which OpenSSL clients
  would drop.
* `srptls.NewVerifier` computes the verifier as RFC 5054 section 2.4 describes, with the username
  and password hashed as given.

`Verifier.Validate` checks a stored record against the limits of RFC 5054 and its group. Use it
when you load verifiers from storage.

### Verifiers from OpenSSL

`openssl srp` creates verifier files that OpenSSL and `estserver` read. The file must exist before
the first user is added:

```sh
touch srpvfile
openssl srp -srpvfile srpvfile -add -gn 3072 device-1
```

The command asks for the password. `-delete` marks a user as revoked with an `R` line. `estserver`
skips revoked users and reads `I` lines that define a group by its parameters, as long as the group
is one of the RFC 5054 groups. See [estserver](../tools/estserver.md#tls-srp) for the file format.

## Unknown usernames

`GetVerifier` decides what a client with an unknown username learns:

| `GetVerifier` returns | The handshake fails with | The client learns |
| --- | --- | --- |
| `srptls.ErrUnknownUsername` | An `unknown_psk_identity` alert | That the username does not exist |
| `srptls.SimulatedVerifier(seed, group, username)` | A `bad_record_mac` alert, as for a wrong password | Nothing about which usernames exist |
| `srptls.ErrAccessDenied` | An `access_denied` alert, before the costly SRP computation | That it was refused |

* **`SimulatedVerifier`** gives the same salt for the same seed and username, so repeated attempts
  look like a real user. Use a long random seed that stays the same across restarts and on every
  server that answers the same clients. Pick the group most of your users have, so the group does
  not give unknown users away.
* **`ErrAccessDenied`** suits a rate limit. The SRP computation runs in the handshake, before the
  router and its `RateLimit` see the request.
* Any other error from `GetVerifier` aborts the handshake with an `internal_error` alert.

The client reports these cases with the errors listed in
[Signing in](../client/authentication.md#tls-srp).

## Cipher suites

The server picks the first suite in `srptls.Config.CipherSuites` that the client offers. The default
is `TLS_SRP_SHA_WITH_AES_256_CBC_SHA`, then `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`.
`TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA` is used only when it is listed. The suites that also sign with
a server certificate are not implemented.

## Handshake failures

`net/http` logs handshake failures only for `crypto/tls`. Without help a failed TLS-SRP handshake
closes the connection without a log entry. The `ConnState` function in the example above checks
each connection when it closes and logs the error of a handshake that did not complete.
`estserver` does the same at info level, for example
`TLS-SRP handshake from 127.0.0.1:53110 failed: remote error: tls: insufficient security level`
when the client refused a group that was too small.

Set `ReadHeaderTimeout` on the `http.Server`. The handshake runs in the first read of the
connection, so this timeout also bounds it.
