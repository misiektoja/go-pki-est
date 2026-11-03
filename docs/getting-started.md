# Getting started

This page starts the bundled test server, enrolls a certificate with the command line client and
renews it. It then shows the same steps in Go. Everything runs on one machine.

## What you need

* Go 1.27.3 or newer
* OpenSSL, to print a fingerprint in step 3 and to generate a private key in step 4
* Port 8443 free on the local machine

## Step 1: install the tools

```bash
go install github.com/misiektoja/go-pki-est/cmd/estclient@latest
```

```bash
go install github.com/misiektoja/go-pki-est/cmd/estserver@latest
```

Both land in `$(go env GOPATH)/bin` or in `GOBIN` when it is set. That directory must be on your
`PATH`.

## Step 2: start the server

```bash
estserver &
```

Without a configuration file the server creates a new test CA in memory, a root and an
intermediate that live for 24 hours. It listens on `localhost:8443` and issues a certificate to
anyone who asks, so it is for testing only. Its log goes to standard error. The CA is gone when the
server stops. [estserver](tools/estserver.md) describes the configuration file.

## Step 3: get the CA certificates

The test CA is new, so nothing trusts it yet. Fetch its root once without checking the server
certificate and save it as the explicit trust anchor:

```bash
estclient cacerts -server localhost:8443 -insecure -roots -out anchor.pem
```

`-insecure` accepts any server, so a real deployment checks the fetched root out of band before it
trusts it, for example by comparing its fingerprint with one the CA operator published:

```bash
openssl x509 -in anchor.pem -noout -fingerprint -sha256
```

Every later command verifies the server against `anchor.pem`. Fetch the full CA chain with it,
because renewal needs the intermediate in step 6:

```bash
estclient cacerts -server localhost:8443 -explicit anchor.pem -out cacerts.pem
```

`cacerts.pem` holds the intermediate and the root.

## Step 4: enroll with your own key

Generate a key and a certificate signing request (CSR), then enroll:

```bash
openssl genrsa -out key.pem 3072
```

```bash
estclient csr -key key.pem -cn 'John Doe' -emails 'john@doe.com' -out csr.pem
```

```bash
estclient enroll -server localhost:8443 -explicit anchor.pem -csr csr.pem -out cert.pem
```

`enroll` can also build the CSR itself from `-key` and the same name flags as `csr`, so the `csr`
step is optional. The test CA copies the subject and the subject alternative names from the
request and issues a certificate that is valid until its CA expires, at most 24 hours.

## Step 5: let the server generate the key

```bash
estclient serverkeygen -server localhost:8443 -explicit anchor.pem -cn 'Jane Doe' -out jane.pem -keyout jane-key.pem
```

The server generates a 2048-bit RSA key and returns it with the certificate. `jane-key.pem` holds a
`PRIVATE KEY` block and is created readable by its owner only. Without `-csr` the client signs the
request with a temporary key, because the server ignores the key in the request.

## Step 6: renew

A renewal authenticates with the certificate being renewed in the TLS handshake. The server asks
for client certificates issued under its root, so the client must send the intermediate as well.
Put the certificate and the CA chain in one file:

```bash
cat cert.pem cacerts.pem > certs.pem
```

```bash
estclient reenroll -server localhost:8443 -explicit anchor.pem -key key.pem -certs certs.pem -out newcert.pem
```

Without `-csr` the client builds the request from the subject and the subject alternative names of
the first certificate in `-certs` and signs it with `-key`. The server refuses a renewal whose
request names anything else.

Stop the server when you are done:

```bash
kill %1
```

## The same from Go

The client is a struct with the server address and the trust anchor. Each method runs one EST
operation on its own TLS connection and takes a context, here `ctx` with a 30-second deadline:

```go
--8<-- "example_test.go:client-enroll"
```

Renewal adds the certificate being renewed and its key to the client, which presents them in the
TLS handshake:

```go
--8<-- "example_test.go:client-reenroll"
```

This code is the `ExampleClient` function in
[example_test.go](https://github.com/misiektoja/go-pki-est/blob/main/example_test.go), which runs
it against a test server with `go test -run ExampleClient`. It prints:

```text
CA: Example EST CA
enrolled: device-1 [device-1.example.com]
renewed: device-1 true
```

## Next steps

* [Enrollment and renewal](client/enrollment.md) covers every client operation.
* [Embedding the server](server/embedding.md) serves EST in front of your own CA.
* [estclient](tools/estclient.md) lists every command, flag and configuration key.
