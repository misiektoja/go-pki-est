# estserver

Application estserver is a basic EST server for testing purposes.

`trust_proxy_headers` defaults to false, so the server uses the connection's
peer address. To retain forwarded client addresses, set it to true only when
every request passes through a trusted reverse proxy that removes or
overwrites both `X-Real-IP` and `X-Forwarded-For`. The server does not check the
proxy's source address. When enabled, `X-Real-IP` takes precedence.

## TLS-SRP

The optional `tls_srp` section serves the same EST endpoints on a second port over TLS-SRP
(RFC 5054). The client signs in with a username and password in the TLS handshake, as libest's
`estclient --srp` does. The server needs no certificate. The listener accepts TLS 1.2 only,
with `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`.

* `listen_address` and `verifier_file` are required. The verifier file is an OpenSSL srpvfile.
  Revoked users are skipped. Only the groups of RFC 5054 are accepted.
* Without `unknown_user_seed`, an unknown username fails the handshake with an
  `unknown_psk_identity` alert, which tells the client that the user does not exist. With a seed,
  it fails like a wrong password. Keep the seed the same across restarts.
* A TLS-SRP login is accepted for `/simpleenroll` and `/simplereenroll`. Reenrollment needs no
  client certificate.

To add a user with the 3072-bit group:

```bash
touch srpvfile
```

```bash
openssl srp -srpvfile srpvfile -add -gn 3072 device-1
```

`openssl s_client` from OpenSSL 3.0 onward ignores `-srppass`, so test with libest, curl or
OpenSSL 1.1.1.
