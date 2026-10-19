# Contributing

go-pki-est is a Go library for Enrollment over Secure Transport (EST). Bug reports, interoperability results and code contributions are welcome.

## Before contributing

Contribute only code you have the right to license under the MIT License. Do not copy code from another EST implementation without checking its license and naming the source in the pull request. The project derives from [globalsign/est](https://github.com/globalsign/est), as [NOTICE](NOTICE) records.

Never commit private keys, enrollment passwords, full CSRs, EST messages captured from a production system or non-public PKI documentation. Keep scratch files and local test state out of commits.

Open pull requests against `dev`.

## Development checks

Run these before submitting a change:

```bash
gofmt -l .
```

```bash
go vet ./...
```

```bash
GLOBALSIGN_EST_SKIP=hsm,tpm go test -race ./...
```

`gofmt -l .` must print nothing. `GLOBALSIGN_EST_SKIP=hsm,tpm` skips the tests that need SoftHSM or a TPM device. CI runs the HSM tests on Linux with SoftHSM. No CI job has a TPM.

Protocol changes need negative tests and an RFC citation. Interoperability claims need sanitized evidence naming the peer and its version. User-facing behavior changes update the Go doc comments, the README and [CHANGELOG.md](CHANGELOG.md).

Every change must comply with the Developer Certificate of Origin 1.1. Use `git commit -s` only when you intend to provide that certification.

## Compatibility

The module uses semantic versioning. Versions before v1.0.0 may change the API in a minor release. [CHANGELOG.md](CHANGELOG.md) describes every change that affects callers, including any that needs a code change.

## Releases

[CHANGELOG.md](CHANGELOG.md) has one section per version, dated on the release day. Set `estVersion` in `client.go` to the new version, because the client User-Agent and the server header report it. Before tagging, run the release check on `main`. With `VERSION` set it also refuses a mismatched `estVersion`:

```bash
GLOBALSIGN_EST_SKIP=hsm,tpm VERSION=v1.1.0 make release-check
```

It tests an export of `HEAD` and imports it from a separate module, so it catches files that are untracked or only present locally. A release starts when a version tag reachable from `main` is pushed:

```bash
git tag -s v1.1.0 -m 'v1.1.0'
git push origin main v1.1.0
```

The release workflow repeats the check on the tag, builds source archives, an SBOM and checksums, attests their provenance and creates a draft release with the changelog section as its description. Review the draft and publish it. Do not draft a release in the GitHub UI. That creates the tag and the workflow refuses to rebuild a published release.

Push only the new tag. Clones made from globalsign/est hold its `v1.0.x` tags. They declare the old module path, so `go get` cannot fetch them under this one.
