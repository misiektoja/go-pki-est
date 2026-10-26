# Getting help

Start with the [README](README.md), which covers the client, the embeddable server and the limits
of the post-quantum algorithms. The package documentation on
[pkg.go.dev](https://pkg.go.dev/github.com/misiektoja/go-pki-est) describes every exported type.
The command line tools are described in [cmd/estclient](cmd/estclient/README.md) and
[cmd/estserver](cmd/estserver/README.md).

## Check your setup first

Many problems come from limits the library applies on purpose. Before asking, confirm that:

* A request larger than 64 KiB, such as the CSR of a large post-quantum key, has a server with a
  raised `ServerConfig.MaxRequestBody`.
* A bearer token reaches a server that sets `CheckBearerToken`. Without it the token does not sign
  a client in.
* An enrollment response that carries the CA chain is accepted only with
  `Client.AllowCertificateChain`.
* The client talks to the EST server directly or through a proxy. It does not follow redirects.
* An ML-DSA client certificate runs over TLS 1.3, which has no `tls-unique` value, so the client
  leaves out the proof of possession challenge password.

## Where to ask

| You want to | Go to |
| --- | --- |
| Ask a usage question or discuss an idea | [Discussions](https://github.com/misiektoja/go-pki-est/discussions) |
| Report something broken | [Bug report](https://github.com/misiektoja/go-pki-est/issues/new?template=bug_report.yml) |
| Request a capability | [Feature request](https://github.com/misiektoja/go-pki-est/issues/new?template=feature_request.yml) |
| Report a vulnerability | [Private security advisory](https://github.com/misiektoja/go-pki-est/security/advisories/new), never a public issue |
| Contribute a change | [CONTRIBUTING.md](CONTRIBUTING.md) |

## Before you post

Include the go-pki-est version, the Go version, the EST peer and its version, the operation and
whether the key lives in software, an HSM or a TPM. Attach the HTTP status and error message the
client received and the relevant server log lines.

Never post enrollment passwords, bearer tokens, private keys, full CSRs, EST messages captured from
a production system or production endpoint details. See [SECURITY.md](SECURITY.md).

## What to expect

This project is maintained in spare time, so replies are best effort with no response time
attached. Only the latest release receives fixes, as [SECURITY.md](SECURITY.md) describes, so
reproduce the problem on the current version before reporting it.
