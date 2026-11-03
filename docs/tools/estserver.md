# estserver

`estserver` serves EST in front of a mock CA. It is for testing clients and for development, not
for production: the mock CA issues a certificate to every client that asks.

```bash
go install github.com/misiektoja/go-pki-est/cmd/estserver@latest
```

## Usage

```text
estserver [-config <path>] [-sampleconfig] [-version] [-help]
```

Without `-config` the server needs no files:

* It creates a new mock CA in memory, a root named `Non-Production Testing Root CA <random>` and an
  intermediate that issues. Both live for 24 hours and are gone when the server stops.
* It issues itself a TLS certificate for `Testing Non-Production EST Server` with the names
  `localhost`, `127.0.0.1` and `::1`.
* It listens on `localhost:8443`, logs to standard error and accepts client certificates issued
  under its root.

It logs `Starting EST server FOR NON-PRODUCTION USE ONLY` when it starts and stops on `SIGINT`,
`SIGTERM`, `SIGQUIT` or `SIGHUP`. `-version` prints `go-pki-est EST server 1.4.0` for that release.

## Configuration file

`-sampleconfig` prints every field:

```json
{
    "mock_ca": {
        "certificates": "/path/to/CA/certificates.pem",
        "private_key": "/path/to/CA/private/key.pem"
    },
    "tls": {
        "listen_address": "localhost:8443",
        "certificates": "/path/to/server/certificates.pem",
        "private_key": "/path/to/server/private/key.pem",
        "client_cas": [
            "/path/to/first/client/CA/root/certificate.pem",
            "/path/to/second/client/CA/root/certificate.pem",
            "/path/to/third/client/CA/root/certificate.pem"
        ]
    },
    "tls_srp": {
        "listen_address": "localhost:8444",
        "verifier_file": "/path/to/srpvfile",
        "unknown_user_seed": "a long random string kept across restarts"
    },
    "allowed_hosts": [
        "localhost",
        "127.0.0.1",
        "[::1]"
    ],
    "healthcheck_password": "xyzzy",
    "rate_limit": 150,
    "timeout": 30,
    "trust_proxy_headers": false,
    "log_file": "/path/to/log.file"
}
```

Every field is optional, but a `mock_ca` or `tls` section needs both of its files. Relative paths
are relative to the current directory. Unknown keys are ignored, so a misspelled key has no
effect. The file has no options for `MaxRequestBody`, `PasswordRenewal`, `CheckBearerToken`,
`OmitTransferEncoding` or `OmitStrictTransportSecurity`, which keep their defaults.

| Field | Meaning |
| --- | --- |
| `mock_ca.certificates` | PEM file with the CA certificates. The first one issues and the file should end with the root, because clients and the renewal check need it |
| `mock_ca.private_key` | PEM file with the key of the first certificate |
| `tls.listen_address` | Address of the TLS listener, `localhost:8443` by default. It is part of the `tls` section, so serving other hosts also takes your own certificate, key and `client_cas` |
| `tls.certificates`, `tls.private_key` | PEM files with the server certificate chain and its key. Required in a `tls` section |
| `tls.client_cas` | PEM files with the roots that client certificates must chain to |
| `tls_srp` | A second listener with TLS-SRP, see [TLS-SRP](#tls-srp) |
| `allowed_hosts` | `ServerConfig.AllowedHosts`. Other `Host` headers answer 400 `host not allowed` |
| `healthcheck_password` | Password of the Basic user `healthcheck` for `/healthcheck`. Empty by default |
| `rate_limit` | `ServerConfig.RateLimit` in requests per second for all clients together. 0 means no limit |
| `timeout` | `ServerConfig.Timeout` in seconds. 0 means 60 seconds |
| `trust_proxy_headers` | `ServerConfig.TrustProxyHeaders`, false by default |
| `log_file` | Append the request log to this file, created with mode 0644. Standard error by default. Startup errors and TLS handshake errors always go to standard error |

* **A `tls` section without `client_cas` accepts no client certificate.** A renewal then fails in
  the handshake. The client reports `remote error: tls: unknown certificate authority` and the
  server prints an `http: TLS handshake error` with `x509: certificate signed by unknown authority`
  on standard error, also when `log_file` is set. Without a `tls` section the server
  trusts the root of its mock CA.
* The TLS listener requires TLS 1.2 or newer, asks for a client certificate without requiring one
  and offers the curves P-521, P-384 and P-256 only. It does not offer the hybrid ML-KEM key
  exchanges.
* The HTTP server allows 30 seconds for the request headers, 60 seconds for the whole request and
  closes idle connections after 120 seconds.
* **Every EST operation is open.** The server asks for no password and issues to any client that
  completes the handshake. Only `/healthcheck` needs the Basic user `healthcheck`. Without a
  configured password, `curl -u healthcheck:` passes it.
* `trust_proxy_headers` takes the client address for the log from `X-Real-IP` or else from
  `X-Forwarded-For`. Enable it only when every request passes a proxy that removes or overwrites
  both headers. The server does not check the address of the proxy.

## The mock CA

Every certificate the mock CA issues:

* is valid for 90 days or until its CA expires if that comes first
* has a random 128-bit serial number
* copies the subject and the subject alternative names from the request byte for byte
* allows digital signatures, server authentication and client authentication and is not a CA

A renewal is issued the same way. The mock CA does not compare it with the old certificate beyond
the checks the router makes.

### Path segments with special behavior

| Request | Behavior |
| --- | --- |
| `/.well-known/est/csrattrs/csrattrs` | Returns the example attributes of RFC 7030 section 4.5.2 |
| `/.well-known/est/pkcs7/serverkeygen` | Returns the key in a CMS SignedData inside an EnvelopedData, encrypted with the pre-shared key `pseudohistorical` |
| `/.well-known/est/triggererrors/...` | `cacerts` and `csrattrs` answer 500. An enrollment with the common name `Trigger Error Forbidden` answers 403, `Trigger Error Deferred` answers 202 with `Retry-After: 600` and `Trigger Error Unknown` answers 500 |

Without a path segment `csrattrs` returns an empty list.

### Server-generated keys

`/serverkeygen` generates an RSA key of 2048 bits. A `Bit-Size` request header of `2048`, `3072` or
`4096` selects the size. Any other value answers 400 `invalid bit size value`:

```bash
estclient serverkeygen -server localhost:8443 -explicit anchor.pem -cn device -headers 'Bit-Size:3072' -out cert.pem -keyout key.pem
```

### TPM enrollment

`/tpmenroll` issues the certificate as for `/simpleenroll` and protects it with a 16-byte AES
credential, see [TPM enrollment](../client/tpm.md).

## TLS-SRP

The `tls_srp` section serves the same endpoints on a second port over TLS-SRP (RFC 5054). The
client signs in with a username and password in the handshake and needs no trust anchor. The TLS
listener keeps running next to it.

```json
{
    "tls_srp": {
        "listen_address": "localhost:8444",
        "verifier_file": "srpvfile"
    }
}
```

* `listen_address` and `verifier_file` are required. Without them the server stops with
  `failed to start TLS-SRP listener: tls_srp needs listen_address and verifier_file`.
* The listener runs TLS 1.2 with `TLS_SRP_SHA_WITH_AES_256_CBC_SHA` and
  `TLS_SRP_SHA_WITH_AES_128_CBC_SHA`.
* A TLS-SRP client may run every operation. A renewal needs no client certificate.
* A failed handshake is logged at info level, such as
  `TLS-SRP handshake from 127.0.0.1:53110 failed: remote error: tls: insufficient security level`.

### The verifier file

The file has the format of `openssl srp`. Create it and add a user with the 3072-bit group:

```bash
touch srpvfile
```

```bash
openssl srp -srpvfile srpvfile -add -gn 3072 device-1
```

Each line has six tab-separated fields: type, verifier, salt, username, group and info.

* `V` lines are users. The group is the size of an RFC 5054 group, such as `3072` or the name of an
  `I` line.
* `R` lines are revoked users, which `openssl srp -delete` writes. The server skips them.
* `I` lines define a group by its parameters. Only the RFC 5054 groups are accepted.
* Empty lines and lines that start with `#` are ignored. A user listed twice, an unknown group or a
  malformed value stops the server with the line number.

`est.Client` and other go-tls-srp clients refuse groups below 2048 bits by default. The 1536-bit
group that some examples use fails with
`srptls: server chose the 1536 bit SRP group, below the minimum of 2048 bits`.

### Unknown users

* Without `unknown_user_seed`, an unknown username fails the handshake with an
  `unknown_psk_identity` alert. The client sees `srptls: unknown SRP username` and learns that the
  user does not exist.
* With a seed, an unknown user fails like a wrong password, with
  `srptls: wrong SRP password`. The server answers with the group most users in the file have.
  Keep the seed the same across restarts.
