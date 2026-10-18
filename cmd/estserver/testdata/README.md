# testdata

`srpvfile` holds TLS-SRP verifiers for testing only. OpenSSL 1.1.1k made it with
`openssl srp -add`. The users and their groups are `alice` (1536 bits), `bob` (2048 bits) and
`dave` (1536 bits). `carol` (3072 bits) was then revoked with `openssl srp -delete`. Each
password is the username followed by `-password`.
