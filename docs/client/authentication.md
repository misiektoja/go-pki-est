# Signing in

EST servers identify clients by a TLS client certificate, an HTTP credential or a TLS-SRP
password. The client sends whatever its fields name on every request, including `/cacerts` and
`/csrattrs`. Which ones a server requires is up to the server.

## Client certificates and hardware keys

Set `Certificates` and `PrivateKey` to present a certificate in the TLS handshake. The client
presents it only when both are set.

* `Certificates` holds the client certificate first, followed by the intermediates the server
  needs. The root may be left out.
* `PrivateKey` may be any `crypto.Signer`, so the key can stay in a hardware security module or a
  TPM. `estclient` uses this for its [HSM and TPM keys](../tools/estclient.md#hardware-keys).

The client presents it when the server asks for a certificate, as long as the server names no CAs
or one of the certificates in `Certificates` was issued by a CA it names. Otherwise it sends none.
For `Reenroll` it must be the certificate being renewed, see
[Renewing a certificate](enrollment.md#renewing-a-certificate).

## HTTP Basic

`Username` and `Password` are sent as HTTP Basic credentials (RFC 7030 section 3.2.3) when
`Username` is not empty. They suit a first enrollment, before the device holds a certificate. The
client offers only Basic. A server that asks for HTTP Digest answers 401.

## Bearer tokens

`BearerToken` is sent as `Authorization: Bearer <token>` (RFC 6750). Basic credentials take
precedence: with `Username` set, the token is not sent. A go-pki-est server checks the token only
when it sets `CheckBearerToken`. Without that hook the token signs nothing in.

The header goes to the EST server only. A proxy gets its own credentials from the proxy URL, see
[Connections and hooks](connections.md#proxies).

## Extra headers

`AdditionalHeaders` adds HTTP headers to every request, for servers that read settings from them.
`estserver`, for example, reads the key size of `/serverkeygen` from `Bit-Size`. `HostHeader`
replaces the `Host` header, which is mostly useful for tests.

## TLS-SRP

TLS-SRP (RFC 5054) signs in with a username and password during the TLS handshake, as RFC 7030
section 3.3.3 allows. The password also authenticates the server, so the client needs no trust
anchor:

```go
--8<-- "example_test.go:srp-client"
```

* `ExplicitAnchor`, `ImplicitAnchor`, `InsecureSkipVerify` and `Certificates` are not used.
* TLS-SRP runs over **TLS 1.2** with AES-CBC cipher suites. The `tls-unique` binding of
  `SigningKey` therefore works.
* The client refuses SRP groups smaller than `SRPMinGroupBits`, 2048 bits by default. libest ships
  an example verifier file with a 1536-bit group, which fails with `srptls: server chose the 1536 bit SRP group, below the minimum of 2048 bits`.
* A wrong password fails the handshake with an error that wraps `srptls.ErrWrongPassword`. An
  unknown username fails with `srptls.ErrUnknownUsername`, unless the server hides which usernames
  exist. Both errors come from [go-tls-srp](https://github.com/misiektoja/go-tls-srp).
* `OnConnect` receives a `*srptls.Conn` instead of a `*tls.Conn`.

## Renewal without the certificate

RFC 7030 section 2.3 allows a renewal that a password signs in instead of the certificate being
renewed. Leave `Certificates` empty and set the credential:

```go
--8<-- "example_test.go:password-renewal-client"
```

A go-pki-est server accepts this only with `ServerConfig.PasswordRenewal` set or over TLS-SRP. The
CA then decides which certificate is renewed and refuses a request for an identity the user does
not own, as the example shows. Use this for certificates that cannot authenticate TLS, such as
composite ML-DSA certificates.
