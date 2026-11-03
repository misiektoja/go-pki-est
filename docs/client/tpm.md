# TPM enrollment

`/tpmenroll` is an operation outside RFC 7030 that came with globalsign/est. It issues a
certificate for a key on a TPM 2.0 device and returns it so that only the TPM that holds the key
and the endorsement key (EK) can read it. It uses the credential protection of the TPM 2.0
Library specification: the CA encrypts a secret to the EK, bound to the name of the key being
certified and the TPM releases the secret only to `TPM2_ActivateCredential`.

Because it is not part of RFC 7030, use it with a go-pki-est server whose CA implements
`TPMEnroll`.

## The request

`Client.TPMEnroll` takes these arguments after the context:

| Argument | Content |
| --- | --- |
| `csr` | The certificate request. It is sent like an enrollment request and its signature is checked |
| `ekCerts` | The EK certificate first, then its chain. At least one certificate |
| `ekPub` | The public area of the EK in TPM encoding |
| `akPub` | The public area of the key being certified in TPM encoding |

The server checks that the public key in `ekPub` matches the EK certificate and answers 422
`public key in public area doesn't match` when it does not. The credential is bound to the key
that `akPub` describes, so only a TPM that holds that key and the EK can read the certificate. The
server does not compare `akPub` with the key in the CSR. A CA that needs them to match compares
them itself.

## The response

`TPMEnroll` returns three byte slices:

| Value | Content |
| --- | --- |
| `credBlob` | The encrypted credential, for `TPM2_ActivateCredential` |
| `encSeed` | The seed encrypted to the EK, for `TPM2_ActivateCredential` |
| `cred` | A CMS EnvelopedData that holds the certificate, encrypted with the credential as a pre-shared key |

The client returns the three values as they are. The caller loads the key and the EK on the TPM,
runs `TPM2_ActivateCredential` to recover the credential and decrypts `cred` with it.
`estclient tpmenroll` does all of this, see [estclient](../tools/estclient.md#tpmenroll).

## The CA side

`CA.TPMEnroll` receives the parsed request, the EK certificates and both public areas and returns
the three values. The mock CA behind `estserver` issues the certificate as for `/simpleenroll`,
generates a 16-byte AES key as the credential and encrypts the certificate with it. It builds the
credential with the module's `internal/tpm` package, which other modules cannot import.

A CA that does not offer TPM enrollment returns an `est.Error` with a status such as 501, as the
example CA in [The CA interface](../server/ca.md) does.

## Testing

The library tests run `/tpmenroll` against the mock CA without a TPM and decrypt the credential in
software with the endorsement key. No test activates a credential on a TPM or runs
`estclient tpmenroll` against one.
