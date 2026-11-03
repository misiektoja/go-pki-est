# Release process

A release starts when a version tag reachable from `main` is pushed. `CHANGELOG.md` has one section
per version and that section becomes the release description.

## Versioning

The module uses semantic versioning, see [Compatibility](../reference/compatibility.md). Three
places carry the version and must agree:

* `estVersion` in `client.go`, with the `v`, which the client `User-Agent` and the server `Server`
  header report
* `versionString` in `cmd/estclient/flags.go` and `cmd/estserver/flags.go`, without the `v`

The tests fail when the tools and the library report different versions.

## Steps

1. On `dev`, complete the `## [X.Y.Z] - <date>` section in `CHANGELOG.md` and set the versions.
2. Merge `dev` into `main` and run the release check there:

    ```bash
    GLOBALSIGN_EST_SKIP=hsm,tpm VERSION=v1.4.1 make release-check
    ```

    It exports `HEAD` with `git archive`, verifies, builds, vets and tests the export and imports it
    from a separate module, so it catches files that are untracked or only present locally. With
    `VERSION` it also checks that `CHANGELOG.md` has a dated heading for the version and no
    unreleased section and that `estVersion` matches.

3. Create a signed tag and push `main` and the tag:

    ```bash
    git tag -s v1.4.1 -m 'v1.4.1'
    git push origin main v1.4.1
    ```

4. The release workflow repeats the check on the tag, builds the source archives, the SBOM and the
   checksums, attests their provenance and creates a **draft** release with the changelog section
   as its description. Review the draft and publish it.

Do not publish a release in the GitHub web interface. Publishing creates the tag, which starts the
workflow. The workflow then refuses to rebuild a release that is already published. A draft that
already exists for the tag is updated and gets the artifacts. Push only the new tag. Clones made from globalsign/est hold its
`v1.0.x` tags, which declare the old module path.

[Verifying a release](../security/verifying-releases.md) shows how users check the artifacts.
