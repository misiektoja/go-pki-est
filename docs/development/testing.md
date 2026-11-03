# Testing

```bash
GLOBALSIGN_EST_SKIP=hsm,tpm make test
```

`make test` runs `go vet` and then `go test -race -count=1 ./...`. `TESTFLAGS=-v` lists every test,
including the skipped ones.

## What the tests cover

* **The root package** runs the client against the router in the same process. The tests cover
  every operation, the renewal checks, the hooks and their combinations, refusals, the limits,
  TLS-SRP, proxies, bearer tokens, redirects, response limits and ML-DSA.
* **The examples** in `example_test.go` compile with the tests. Those with an `// Output:`
  comment also run and compare their output. They are also the Go listings on this site.
* **`cmd/estclient`** runs the commands against an in-process router with the mock CA, including ML-DSA
  keys, output file permissions and proxies.
* **`cmd/estserver`** tests the default listen address, the timeouts, the TLS-SRP verifier file reader
  and the TLS-SRP listener.

## HSM and TPM tests

`GLOBALSIGN_EST_SKIP` takes a comma-separated list:

* `hsm` skips the tests that use a key on SoftHSM.
* `tpm` skips the test that needs a TPM 2.0 device.

The HSM tests load the key that `cmd/estclient/testdata/test_hsm.cfg` names and sign a request
with it. In CI the Linux job installs `softhsm2` and runs `.github/scripts/setup-softhsm.sh`, which
creates the token `Testing Token` with PIN `1234`, imports an RSA key and rewrites `test_hsm.cfg`
with the library path of the runner. The script writes to the GitHub Actions environment and
overwrites the tracked `test_hsm.cfg`, so do not run it locally. Skip `hsm` unless you have
prepared a matching token yourself.

The only TPM test, `TestNewConfigHardware/TPM`, loads a TPM key from
`cmd/estclient/testdata/test_tpm.cfg`.

## Continuous integration

| Job | Runs |
| --- | --- |
| Linux | `make tidy-check`, `make fmt-check`, the build and `make test` with SoftHSM, skipping `tpm` |
| macOS | The build and `make test`, skipping `hsm` and `tpm` |
| Windows | The build only |
| Lint | `make lint-config`, `make lint` and `make actionlint` |
| Supply chain | `make govulncheck`, `make gitleaks` and the SBOM |
| Documentation | `make docs-build` |

No CI job has a TPM, so the TPM test does not run in CI. No test runs `estclient tpmenroll`
against a TPM. The library tests run `/tpmenroll` against the mock CA and decrypt the credential
in software.

Interoperability with other EST implementations is tested outside this repository, see
[Interoperability](../interoperability.md).
