# estclient

`estclient` is a command line EST client built on the library. It fetches CA certificates and CSR
attributes, enrolls, renews and asks the server to generate a key. It signs with keys in files, on
a PKCS #11 HSM or on a TPM 2.0 device.

```bash
go install github.com/misiektoja/go-pki-est/cmd/estclient@latest
```

[Getting started](../getting-started.md) walks through a full session against `estserver`.

## Usage

```text
estclient <command> [options]
```

| Command | Operation |
| --- | --- |
| `cacerts` | Fetch the CA certificates (RFC 7030 section 4.1) |
| `csrattrs` | Fetch the CSR attributes the CA wants (section 4.5) |
| `csr` | Generate a PKCS #10 request locally, without a server |
| `enroll` | Request a new certificate (section 4.2) |
| `reenroll` | Renew a certificate (section 4.2) |
| `serverkeygen` | Request a key and a certificate from the server (section 4.4) |
| `tpmenroll` | Request a certificate for a TPM key, see [tpmenroll](#tpmenroll) |
| `sampleconfig` | Print a sample configuration file |
| `version` | Print the version, such as `go-pki-est EST client 1.4.0` |
| `help` | Print the command list. `estclient help -common` describes the common options |

`estclient <command> -help` lists the options of a command. On failure the tool prints
`estclient: <error>` to standard error and exits with status 1. An unknown option prints the usage
of the command and exits with status 2.

## Connection options

The commands that talk to a server share these options:

| Option | Meaning |
| --- | --- |
| `-server <host:port>` | The EST server. Required, here or in the configuration file |
| `-aps <string>` | The additional path segment, such as `devices` in `/.well-known/est/devices/simpleenroll` |
| `-explicit <path>` | PEM file with the CA certificates that verify the server (RFC 7030 section 3.6.1) |
| `-implicit <path>` | PEM file used when no explicit anchor is set. Without either, the system roots apply |
| `-insecure` | Accept any server certificate. Command line only, see [Bootstrapping](#bootstrapping) |
| `-certs <path>` | PEM file with the TLS client certificate first, then the CA certificates the server needs to build the chain |
| `-key <path>` | PEM file with the private key of the client certificate or the key that signs a generated request |
| `-user <string>`, `-pass <string>` | HTTP Basic credentials |
| `-token <string>` | HTTP bearer token. `-user` takes precedence |
| `-headers <string>` | Extra HTTP headers as `Name:value` items, separated by `-separator` |
| `-hostheader <string>` | Override the HTTP `Host` header |
| `-proxy <url>` | HTTP or HTTPS proxy. Without it `HTTPS_PROXY` and `NO_PROXY` apply |
| `-timeout <duration>` | Time limit for the request, 15s by default |
| `-separator <string>` | Separator of list values, `,` by default |
| `-config <path>` | [Configuration file](#configuration-file) |
| `-out <path>` | Output file. Standard output by default. `csrattrs` always prints to standard output |

When both anchors are given, only the explicit one is used.

## Commands

### cacerts

```bash
estclient cacerts -server est.example.com:8443 -explicit anchor.pem -out cacerts.pem
```

Writes the CA certificates in PEM, in the order the server sent them. Filters:

* `-roots` keeps the self-signed certificates.
* `-intermediates` keeps all others.
* `-rootout` keeps the first self-signed certificate and fails with
  `failed to find a root certificate in CA certificates` when there is none. The help text marks it
  for deprecation in favor of `-roots`.
* `-separate` writes each certificate to its own file. With `-out chain.pem` the files are
  `chain-1.pem`, `chain-2.pem` and so on. Without `-out` they are `ca-1.pem`, `ca-2.pem`.

Only one of `-roots`, `-intermediates` and `-rootout` may be given.

### csrattrs

```bash
estclient csrattrs -server localhost:8443 -explicit anchor.pem -aps csrattrs
```

Prints each attribute the server asks for. Against `estserver` with the `csrattrs` path segment:

```text
OID     : 1.2.840.113549.1.9.7
OID     : 1.2.840.10045.4.3.3
Type    : 1.2.840.113549.1.9.14
 Value  : 1.3.6.1.1.1.1.22
Type    : 1.2.840.10045.2.1
 Value  : 1.3.132.0.34
```

An `OID` line is an attribute or algorithm the CA wants. A `Type` line is an attribute with the
values that follow it. An empty answer prints nothing.

### csr

```bash
estclient csr -key key.pem -cn 'John Doe' -emails 'john@doe.com' -out csr.pem
```

Generates a request signed with `-key` or with the configured key. These options set its fields:

| Option | Field |
| --- | --- |
| `-cn` | Subject common name |
| `-sn` | Subject serial number |
| `-org`, `-ou` | Subject organization and organizational unit |
| `-country`, `-province`, `-locality`, `-street`, `-postalcode` | Subject address |
| `-dnsnames`, `-emails`, `-ips`, `-uris` | Subject alternative names |

`-ou`, `-dnsnames`, `-emails`, `-ips` and `-uris` take several values separated by `-separator`.

### enroll

```bash
estclient enroll -server localhost:8443 -explicit anchor.pem -csr csr.pem -out cert.pem
```

Sends the request in `-csr`. Without `-csr` it builds one from the [csr](#csr) options and signs it
with the key. Without a key it fails with `no private key provided`.

`-signingkey <path>` sets a separate key for the request. The client then adds the `tls-unique`
value of the TLS 1.2 connection as the challenge password and signs the request with that key, as
RFC 7030 section 3.5 describes. Over TLS 1.3 nothing is added.

### reenroll

```bash
estclient reenroll -server localhost:8443 -explicit anchor.pem -key key.pem -certs certs.pem -out newcert.pem
```

Presents the certificate in `-certs` and its key in the TLS handshake. Without `-certs` it fails with
`no client certificate provided`. Without `-csr` it copies the subject and the subject alternative
names of the first certificate in `-certs` into a new request and signs it with `-key`. A renewal
with a new key therefore needs `-csr`.

### serverkeygen

```bash
estclient serverkeygen -server localhost:8443 -explicit anchor.pem -cn 'Jane Doe' -out jane.pem -keyout jane-key.pem
```

Writes the certificate to `-out` and the key to `-keyout`, both to standard output by default. The
key is written as a `PRIVATE KEY` block when it is PKCS #8 or as a `PKCS7` block when the server
encrypted it. Any other key fails with `unrecognized private key format`.

Without `-csr` the request is signed with a new temporary P-256 key, because the server ignores the
key in the request.

### tpmenroll

```bash
estclient tpmenroll -config tpm.cfg -server est.example.com:8443 -explicit anchor.pem -out cert.pem
```

Requests a certificate for a key on a TPM 2.0 device, as [TPM enrollment](../client/tpm.md)
describes. The tool reads the public areas of the key and the endorsement key from the TPM, sends
the request, activates the returned credential on the TPM and writes the decrypted certificate.

The key must be a [TPM key](#tpm-keys) in the configuration file. It also needs the endorsement key
handle (`ek_handle`) and its certificates (`ek_certs` or `-ekcerts <path>`). Missing parts fail with
errors such as `no endorsement key certificate(s) provided` or
`private key in configuration file is not a TPM private key`.

No test runs this command against a TPM. The library tests run `/tpmenroll` against the mock CA
and decrypt the credential in software.

### sampleconfig

Prints a sample configuration file. `-hsm` prints one with an HSM key and `-tpm` one with a TPM key.
`-out` writes it to a file.

## Configuration file

Most options can be set in a JSON file given with `-config`. Options on the command line override
the file. `-headers` replaces the whole `additional_headers` map.

```json
{
    "server": "est.fake.domain:8443",
    "additional_path_segment": "someseg",
    "additional_headers": {
        "Certificate-Template": "my-template",
        "Bit-Size": "3072"
    },
    "host_header": "est.fake.host",
    "username": "someuser",
    "password": "somepass",
    "private_key": "test_key.pem"
}
```

| Field | Option |
| --- | --- |
| `server` | `-server` |
| `additional_path_segment` | `-aps` |
| `additional_headers` | `-headers` |
| `host_header` | `-hostheader` |
| `username`, `password` | `-user`, `-pass` |
| `token` | `-token` |
| `proxy` | `-proxy` |
| `explicit_anchor`, `implicit_anchor` | `-explicit`, `-implicit` |
| `client_certificates` | `-certs` |
| `private_key` | `-key` or an `hsm` or `tpm` object |
| `signing_key` | `-signingkey` or an `hsm` or `tpm` object |

* A relative `-config` path is looked up in the current directory, then in the directory that
  `ESTCLIENT_CONFIG_DIRECTORY` names when it is an absolute path, then in the home directory.
* Relative paths inside the file are relative to the directory of the file. Relative paths on the
  command line are relative to the current directory.
* `-insecure`, `-timeout`, `-csr`, the subject options such as `-cn` and the output options `-out`,
  `-keyout`, `-separate`, `-separator`, `-roots`, `-rootout` and `-intermediates` have no key in
  the file.
* When `signing_key` is set, `enroll`, `csr` and `tpmenroll` sign the requests they generate with
  it instead of `private_key`. `reenroll` signs with `private_key` and `serverkeygen` with a
  temporary P-256 key.

## Keys

### Key files

`-key` and `private_key` read a PEM file with a `PRIVATE KEY` (PKCS #8), `RSA PRIVATE KEY` or
`EC PRIVATE KEY` block. PKCS #8 covers RSA, ECDSA, Ed25519 and ML-DSA keys. A block encrypted in
the legacy PEM format, with a `Proc-Type: 4,ENCRYPTED` header, prompts for the passphrase. An
`ENCRYPTED PRIVATE KEY` block is refused.

### Hardware keys

HSM and TPM keys can only be set in the configuration file. They work as the TLS client key and as
the key that signs generated requests.

An HSM key is reached through PKCS #11:

```json
"private_key": {
    "hsm": {
        "pkcs11_library_path": "/usr/local/lib/softhsm/libsofthsm2.so",
        "token_label": "Testing Token",
        "token_pin": "1234",
        "key_id": 1
    }
}
```

When `token_pin` is empty, the tool asks for the PIN on the terminal. CI runs the HSM tests with
SoftHSM on Linux.

### TPM keys

```json
"private_key": {
    "tpm": {
        "device": "/dev/tpmrm0",
        "persistent_handle": 2164391936,
        "storage_handle": 2164260865,
        "ek_handle": 2164326401,
        "key_password": "xyzzy",
        "storage_password": "opensesame",
        "ek_password": "abracadabra",
        "ek_certs": "/path/to/ek/certs/chain.pem",
        "public_area": "signing_key.pub",
        "private_area": "signing_key.priv"
    }
}
```

The key is loaded from `persistent_handle` when it is set. Otherwise it is loaded under
`storage_handle` from the `public_area` and `private_area` files. `ek_handle` and `ek_certs` are
needed by `tpmenroll` only.

## Bootstrapping

`-insecure` skips the check of the server certificate. Use it once to fetch the CA certificates of
a new server, check them out of band, for example by their fingerprint and use them as `-explicit`
from then on:

```bash
estclient cacerts -server localhost:8443 -insecure -roots -out anchor.pem
```

```bash
openssl x509 -in anchor.pem -noout -fingerprint -sha256
```

This does not work when the server certificate does not come from the EST CA, because the fetched
roots then cannot verify the server.

## Output files

* Certificates are written in PEM. New files get mode 0666 and private keys 0600, both reduced by
  the umask.
* An existing file is truncated. On Unix it first loses any permission that a new file would not
  get, so an existing key file ends up readable by its owner only.
* An output path that is a symbolic link is refused with
  `output file link.pem is a symbolic link, name its target instead`.

## Limits

* `estclient` has no TLS-SRP options. Use the library's `SRPUsername` and `SRPPassword` instead.
* It does not show the `Retry-After` value of a deferred request. The error reads, for example,
  `failed to get certificate: 202 triggered deferred response`.
* It has no option for `AllowCertificateChain` or `MaxResponseBody`, so the library defaults apply.
