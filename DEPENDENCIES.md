# Dependencies

The library derives from [globalsign/est](https://github.com/globalsign/est), as [NOTICE](NOTICE)
records. Third-party code is consumed through versioned packages.

| Dependency | Use | License |
| --- | --- | --- |
| github.com/go-chi/chi/v5 | Request routing in the server | MIT |
| go.mozilla.org/pkcs7 | PKCS #7 certificate bundles and server-generated keys in EST messages | MIT |
| github.com/smallstep/scep | The challengePassword attribute in client CSRs, through its `x509util` package | MIT |
| github.com/misiektoja/go-tls-srp | TLS-SRP password sign-in (RFC 5054) in the client and the server | BSD-3-Clause |
| filippo.io/bigmod | Modular arithmetic of SRP, through github.com/misiektoja/go-tls-srp | BSD-3-Clause |
| github.com/google/go-tpm | TPM 2.0 structures in TPM enrollment and TPM-resident keys in `estclient` | Apache-2.0 |
| golang.org/x/time | The server rate limiter | BSD-3-Clause |
| github.com/globalsign/pemfile | PEM file reading in `estclient`, `estserver` and the mock CA | MIT |
| github.com/globalsign/tpmkeys | TPM-resident private keys in `estclient` | MIT |
| github.com/ThalesIgnite/crypto11 | PKCS #11 HSM private keys in `estclient` | MIT |
| github.com/miekg/pkcs11 | The cgo PKCS #11 binding, through github.com/ThalesIgnite/crypto11 | BSD-3-Clause |
| github.com/thales-e-security/pool | HSM session pooling, through github.com/ThalesIgnite/crypto11 | Apache-2.0 |
| github.com/pkg/errors | Error wrapping, through github.com/ThalesIgnite/crypto11 | BSD-2-Clause |
| golang.org/x/term | Password prompts in `estclient` | BSD-3-Clause |
| golang.org/x/crypto | TLS message parsing and terminal input, through github.com/misiektoja/go-tls-srp and github.com/globalsign/pemfile | BSD-3-Clause |
| golang.org/x/sys | System calls, through golang.org/x/term, github.com/google/go-tpm and filippo.io/bigmod | BSD-3-Clause |

Exact versions and checksums are in `go.mod` and `go.sum`. Each dependency retains its own license
and notices in the downloaded module. Those requirements also apply to any distribution that
includes the dependencies. The release SBOM lists the licenses of the complete module graph.
