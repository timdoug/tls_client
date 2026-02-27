# tls_client

A featureful TLS 1.2/1.3 client "from scratch" in a single C file: no external
dependencies besides POSIX / C stdlib.

```
$ make
python3 gen_ct_logs.py > ct_log_table.inc
// Extracted 54 logs from 8 operators
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c tls_client.c
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -c https_get.c
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o https_get https_get.o tls_client.o
$ ./https_get https://www.example.com/
<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style></head><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.</p><p><a href="https://iana.org/domains/example">Learn more</a></p></div></body></html>
$
```

## Really, don't use this

It's all vibe-coded! A machine has written every line of code though a human
has manually directed and approved every commit (and I'm no cryptographer). An
impressive display of current capability but please don't consider this secure
in any manner. Maybe fun to slot into an old toy where compiling real libraries
is difficult, but not at all for use in anything more serious...

## What's here

~9,000 lines of C99 (library) that implements:

**X.509 chain validation**: signature verification, hostname matching (CN +
SAN), validity periods, basicConstraints / pathLen / keyUsage / EKU
enforcement, name constraints, critical-extension rejection, out-of-order chain
handling.

**Certificate Transparency**: embedded SCT verification (RFC 6962) against
Chrome's CT log list, enforcing Chrome/Safari/Firefox SCT policy: 2 SCTs for
certificates <=180 days, 3 for longer-lived certificates, from >=2 distinct log
operators.

**CRL revocation checking**: fetches CRL from distribution point URLs embedded
in leaf certificates, verifies the CRL signature against the issuer, and rejects
connections if the certificate serial number appears revoked. Fetched CRLs are
cached to the `crls/` directory and reused until `nextUpdate` expires. Soft-fails
(warns but allows) if no CRL distribution point is present or the fetch fails.

**AIA chasing**: fetches missing intermediate certificates over HTTP when the
server sends an incomplete chain.

**TLS 1.3** (RFC 8446): full handshake with HelloRetryRequest, downgrade
detection, session resumption via PSK-DHE (NewSessionTicket + pre_shared_key
binder computation), and post-quantum hybrid key exchange (X25519MLKEM768).

**TLS 1.2** (RFC 5246): ECDHE and static-RSA key exchange, GCM / CBC /
ChaCha20-Poly1305 record protection.

### Cipher suites

| TLS 1.3 | TLS 1.2 ECDHE | TLS 1.2 RSA |
|---|---|---|
| AES-128-GCM-SHA256 | ECDHE-{RSA,ECDSA}-CHACHA20-POLY1305 | RSA-AES-{128,256}-GCM |
| AES-256-GCM-SHA384 | ECDHE-{RSA,ECDSA}-AES-{128,256}-GCM | RSA-AES-{128,256}-CBC |
| CHACHA20-POLY1305-SHA256 | ECDHE-{RSA,ECDSA}-AES-{128,256}-CBC | |

### Key exchange

- **X25519MLKEM768** post-quantum hybrid (preferred, TLS 1.3 only)
- **X25519**
- **X448**
- **ECDHE P-256**, **P-384**
- **Static RSA** key transport (TLS 1.2 only)

### Signatures

- ECDSA with P-256/SHA-256 and P-384/SHA-384
- Ed25519 (TLS 1.3 CertificateVerify + X.509 cert signatures)
- Ed448 (TLS 1.3 CertificateVerify + X.509 cert signatures)
- RSA PKCS#1 v1.5 with SHA-256/384/512
- RSA-PSS with SHA-256/384

### Crypto primitives

SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512, SHAKE128, SHAKE256,
HMAC, HKDF, AES-128/256 (GCM & CBC), ChaCha20-Poly1305, ML-KEM768 (FIPS 203,
NTT-based), P-256/P-384 field & point arithmetic, X25519/X448 Montgomery
ladder, Ed25519/Ed448 point arithmetic and signature verification, RSA modular
exponentiation (64-bit & 32-bit limb paths).

## What's not implemented

- OCSP stapling / OCSP responder checking
- Client certificates
- Old crypto: TLS 1.0/1.1, RC4/3DES, DHE
- 0-RTT
- Renegotiation and compression

## Trust store

Place PEM-encoded root CA certificates (`.crt`) in the `trust_store/`
directory. To fetch the latest Mozilla CA bundle from Debian stable:

```
make getcerts
```

## CT log table

The CT log public keys and operator IDs are compiled in from
`ct_log_table.inc`, auto-generated on first build by `gen_ct_logs.py`
from Chrome's
[log_list.json](https://www.gstatic.com/ct/log_list/v3/log_list.json).
Delete `ct_log_table.inc` and re-run `make` to refresh.

## Testing

```
make test           # compile, static analysis, 25 random sites + xfail + local crypto
make fulltest       # compile, static analysis, all ~250 sites + xfail + local crypto
make test-local     # local openssl s_server cipher suite tests only (25 tests)
make test-static    # compile + static analysis only
make test-sites     # 25 random site connection tests only
make test-sites-all # all site connection tests (pass + xfail)
make test-xfail     # expected-failure tests only
make test-resume    # session resumption tests (local + 25 random sites)
./tls_test          # RFC/NIST test vectors for all crypto primitives (32 tests)
```

The full suite covers:

- **Static analysis**: cppcheck + clang --analyze
- **~250 site connections**: Google, Amazon, Cloudflare, banks, CDNs, etc.
- **31 expected-failure tests**: badssl.com certificate/cipher edge cases
- **25 local crypto tests**: `openssl s_server` integration tests covering
  every supported cipher suite, key exchange group, and cert type, plus 5
  negative tests (expired cert, wrong hostname, untrusted cert, TLS 1.0/1.1
  rejection)
- **Session resumption tests**: 3 local `openssl s_server` PSK-DHE resumption
  tests (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) plus 25 random
  real-host resumption tests

Bails early after 10 failures.

The local crypto tests start a local `openssl s_server` for each combination
and connect with `tls_client`. This exercises all 3 TLS 1.3 ciphers (with
X25519, P-256, P-384 groups), all 10 TLS 1.2 ECDHE cipher suites (RSA and
ECDSA auth), all 4 static RSA cipher suites, plus Ed25519/X448/Ed448
(auto-skipped if OpenSSL lacks support).

The resumption tests verify TLS 1.3 PSK-DHE session resumption by making two
connections — the first captures a NewSessionTicket, the second resumes with
it. Servers that don't issue tickets or reject PSK are counted as skips (not
failures), since both cases are handled gracefully.

## Building

Requires a C99 compiler. No dependencies beyond libc and POSIX sockets.

```
make
```

Works on x86-64 and ARM64 (auto-selects 64-bit limb arithmetic). 32-bit
platforms are supported with a fallback path.

## License
MIT
