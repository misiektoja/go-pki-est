# Development

## Setup

You need Go at the version in `go.mod`, 1.27.3 or newer. The HSM tests also need SoftHSM 2 and the
TPM tests a TPM 2.0 device. Without them, skip those tests as [Testing](testing.md) shows.

```bash
git clone https://github.com/misiektoja/go-pki-est.git
cd go-pki-est
GLOBALSIGN_EST_SKIP=hsm,tpm make test
```

Open pull requests against `dev`. `make help` lists every target.

## Layout

| Path | Content |
| --- | --- |
| `*.go` at the root | The `est` package: client, router, CA interface, encoding and errors |
| `example_test.go` | The examples that the documentation site includes |
| `cmd/estclient` | The command line client |
| `cmd/estserver` | The test server and its TLS-SRP listener |
| `internal/mockca` | The mock CA behind `estserver` |
| `internal/tpm` | The TPM credential protection for `/tpmenroll` |
| `internal/basiclogger` | The logger of `estserver` |
| `docs` and `mkdocs.yml` | This site |

## Checks

Run these before submitting a change:

```bash
make fmt-check
make lint
GLOBALSIGN_EST_SKIP=hsm,tpm make test
```

| Target | Check |
| --- | --- |
| `make fmt-check` | Every tracked Go file is gofmt formatted |
| `make vet` | `go vet ./...` |
| `make test` | `go vet` and the tests under the race detector |
| `make lint` | golangci-lint at the version CI uses, installed under `bin/` |
| `make lint-config` | The golangci-lint configuration is valid |
| `make tidy-check` | `go.mod` and `go.sum` are tidy. Run it when they change |
| `make govulncheck` | Known vulnerabilities that reach the module. Run it when a dependency changes |
| `make actionlint` | The GitHub Actions workflows. Run it when a workflow changes |
| `make gitleaks` | Credentials in the working tree and the history |
| `make docs-build` | The documentation site, with warnings as errors |

Protocol changes need negative tests and an RFC citation. User-facing changes update the Go doc
comments, this site and `CHANGELOG.md`.

## Documentation site

The site is built with MkDocs and the Material theme. The toolchain is pinned with hashes in
`docs/requirements.txt`. Install it in a virtual environment and point `PYTHON` at it:

```bash
make docs-deps PYTHON=.venv/bin/python
make docs-serve PYTHON=.venv/bin/python
```

* Go code on the pages comes from `example_test.go` through snippet sections marked with
  `// --8<-- [start:name]` and `// --8<-- [end:name]`. `go test` compiles every example and runs
  those with an `// Output:` comment, so the code on the site cannot drift from the library. Write
  new Go listings there, not in the Markdown.
* `make docs-build` runs with `--strict`, so a broken link, a missing anchor or a page absent from
  the navigation fails the build.
* To change a toolchain version, edit `docs/requirements.in` and run `make docs-requirements`,
  which needs pip-tools.

The documentation workflow runs the same build on every change to the site sources and publishes
the site from `main`.
