# Contributing

go-pki-est is a Go library for Enrollment over Secure Transport (EST). Bug reports, interoperability results and code contributions are welcome. Usage questions belong in Discussions, as [SUPPORT.md](SUPPORT.md) describes.

## Before contributing

Contribute only code you have the right to license under the MIT License. Do not copy code from another EST implementation without checking its license and naming the source in the pull request. The project derives from [globalsign/est](https://github.com/globalsign/est), as [NOTICE](NOTICE) records.

Never commit private keys, enrollment passwords, full CSRs, EST messages captured from a production system or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`. Pull requests run the formatting, vet, lint, test and supply chain checks. `dev` and `main` accept a change only after the build, test, lint, vulnerability and credential scan checks pass.

## Development checks

Run these before submitting a change:

```bash
make fmt-check
make lint
GLOBALSIGN_EST_SKIP=hsm,tpm make test
```

`make fmt-check` fails when a tracked Go file is not gofmt formatted. `make lint` runs golangci-lint at the version CI uses, installed under `bin/`. `make test` runs `go vet` and the tests under the race detector. `TESTFLAGS=-v` lists the skipped tests. Run `make tidy-check` when `go.mod` changes, `make govulncheck` when a dependency changes and `make actionlint` when a workflow changes. `make gitleaks` scans the working tree and the commit history for credentials. `make help` lists every target.

`GLOBALSIGN_EST_SKIP=hsm,tpm` skips the tests that need SoftHSM or a TPM device. CI runs the HSM tests on Linux with SoftHSM. No CI job has a TPM.

Protocol changes need negative tests and an RFC citation. Interoperability claims need sanitized evidence naming the peer and its version. User-facing behavior changes update the Go doc comments, the README and [CHANGELOG.md](CHANGELOG.md).

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Compatibility

The module uses semantic versioning. Versions before v1.0.0 may change the API in a minor release. [CHANGELOG.md](CHANGELOG.md) describes every change that affects callers, including any that needs a code change.

## Releases

[CHANGELOG.md](CHANGELOG.md) has one section per version, dated on the release day. Set `estVersion` in `client.go` to the new version, because the client User-Agent and the server header report it. Set `versionString` in `cmd/estclient/flags.go` and `cmd/estserver/flags.go` to the same version without the `v`. The tests fail when the tools and the library report different versions. Before tagging, run the release check on `main`. With `VERSION` set it also refuses a mismatched `estVersion`:

```bash
GLOBALSIGN_EST_SKIP=hsm,tpm VERSION=v1.1.0 make release-check
```

It tests an export of `HEAD` and imports it from a separate module, so it catches files that are untracked or only present locally. A release starts when a version tag reachable from `main` is pushed:

```bash
git tag -s v1.1.0 -m 'v1.1.0'
git push origin main v1.1.0
```

The release workflow repeats the check on the tag, builds source archives, an SBOM and checksums, attests their provenance and creates a draft release with the changelog section as its description. Review the draft and publish it. [Verifying a release](README.md#verifying-a-release) shows how users check the artifacts. Do not draft a release in the GitHub UI. That creates the tag and the workflow refuses to rebuild a published release.

Push only the new tag. Clones made from globalsign/est hold its `v1.0.x` tags. They declare the old module path, so `go get` cannot fetch them under this one.

## Code style

[.editorconfig](.editorconfig) records the whitespace rules: UTF-8, LF line endings, a final newline, no trailing whitespace, tabs for Go and Make recipes, two-space indentation for YAML and TOML plus four-space indentation for the `estclient` configuration files. Markdown keeps meaningful trailing spaces. `LICENSE` and the TLS-SRP verifier test file remain verbatim. Most editors apply these settings automatically, while a few need a plugin.
