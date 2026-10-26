# What this changes

<!-- What the change does and why. Link the issue it closes. -->

## Validation

<!-- Which of these you ran, and anything that failed. -->

- [ ] `make fmt-check`
- [ ] `make lint`
- [ ] `make test`, with `GLOBALSIGN_EST_SKIP=hsm,tpm` when SoftHSM or a TPM is missing
- [ ] `make gitleaks`
- [ ] `make govulncheck`, for a dependency change
- [ ] Exercised against a real EST peer, for a protocol change

<!-- Name the peer and its version, without hostnames or credentials. -->

## Documentation and changelog

- [ ] User-facing behavior is documented in the Go doc comments and the README
- [ ] `CHANGELOG.md` carries an entry, or the change is not user facing
- [ ] A protocol change cites the RFC section and has a negative test

## Anything a reviewer should know

<!-- Trade-offs, follow-up work, or parts you are unsure about. -->

<!-- Never include enrollment passwords, bearer tokens, private keys, full CSRs or production
     endpoint details in a pull request. -->
