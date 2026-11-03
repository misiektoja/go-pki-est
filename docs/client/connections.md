# Connections and hooks

How the client reaches the server, what it accepts in a response and how a program can watch it.

## Proxies

`Proxy` chooses the proxy, like `http.Transport.Proxy`. When it is nil, `http.ProxyFromEnvironment`
applies, so `HTTPS_PROXY` and `NO_PROXY` decide. It never proxies `localhost` or a loopback
address. A function that returns nil connects directly.

```go
--8<-- "example_test.go:proxy"
```

* The client opens a `CONNECT` tunnel through the proxy and runs TLS or TLS-SRP to the EST server
  inside it. The proxy never sees the EST requests and `OnConnect` and the `tls-unique` binding
  work as on a direct connection.
* `http` and `https` proxies are supported. An `https` proxy is checked against the system roots.
  Any other scheme fails with `unsupported proxy scheme "socks5", want http or https`.
* The user and password in the proxy URL are sent as Basic `Proxy-Authorization`.
* A proxy that answers the `CONNECT` with anything but 200 fails the call with
  `proxy <proxy> refused the tunnel to <server>: <status>`.

## Watching the connection and the requests

`OnConnect` receives the connection of each operation after the handshake and before the request.
`WrapTransport` wraps the HTTP transport, so it sees every request and response:

```go
--8<-- "example_test.go:hooks"
```

`ExampleClient_hooks` in `example_test.go` prints:

```text
connected with TLS 1.3
GET /.well-known/est/cacerts 200 OK
```

* `OnConnect` receives a `*tls.Conn` or a `*srptls.Conn` with TLS-SRP. It must not read from,
  write to or close the connection.
* The wrapper must pass every request on to the transport it wraps. That transport already applies
  `MaxResponseBody`, so the wrapper sees bounded bodies.

## Response limits

The client reads at most `MaxResponseBody` bytes of a response body, 1 MiB by default. The limit
covers error messages and all parts of a multipart response. A larger body fails the call with an
error that contains `response body larger than 1048576 bytes`.

Raise the limit when responses carry large post-quantum certificates. An SLH-DSA-SHA2-256f
signature alone is 49,856 bytes, so each certificate signed with it takes about 67 KB in base64. A
negative value fails every call with `MaxResponseBody must not be negative`.

## Accepting a chain in the response

RFC 7030 section 4.2.3 allows only the issued certificate in an enrollment response. When a server
adds its CA certificates, `Enroll`, `Reenroll` and `ServerKeyGen` fail with
`<n> certificates returned`. Set `AllowCertificateChain` to accept such a response. The client then
returns the one certificate that issued none of the others, matched by name. A response in which
that is not exactly one certificate still fails.

## Redirects

The client never follows a redirect. A 3xx answer returns an `est.Error` with that status.
RFC 7030 section 3.2.1 allows only redirects within the same origin and following one would send
the credentials to another location.

## Timeouts and connection reuse

Each call takes a context, which bounds the proxy tunnel, the handshake and the request. The client
has no timeout of its own, so pass a context with a deadline.

Every call uses a new connection and closes it when it returns. `DisableKeepAlives` also sends
`Connection: close` with each request.
