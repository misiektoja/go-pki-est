# Verifying a release

Each [GitHub release](https://github.com/misiektoja/go-pki-est/releases) carries:

* the complete source tree as `go-pki-est-<version>-source.zip` and `.tar.gz`
* a CycloneDX SBOM, `go-pki-est-<version>-sbom.cdx.json`
* the SHA-256 checksums of those three files, `go-pki-est-<version>_SHA256SUMS.txt`
* a signed build provenance bundle, `go-pki-est-<version>.intoto.jsonl`

Check a downloaded file against the checksums, then confirm that the release workflow of this
repository built it. `--ignore-missing` skips the listed files you did not download:

```bash
shasum -a 256 -c --ignore-missing go-pki-est-v1.4.1_SHA256SUMS.txt
```

```bash
gh attestation verify go-pki-est-v1.4.1-source.tar.gz --repo misiektoja/go-pki-est
```

To verify without network access to the attestation API, add
`--bundle go-pki-est-v1.4.1.intoto.jsonl`.

`go get` and `go install` fetch the module through the Go module proxy and check it against the
checksum database, so they need none of these files. The archives serve users who build from a
downloaded source tree.
