# tls_client

A featureful TLS 1.2/1.3 client "from scratch" in a single C file: no external
dependencies besides POSIX / C stdlib.

```
$ make
python3 gen_ct_logs.py > ct_log_table.inc
// Extracted 54 logs from 8 operators
cc -std=c99 -Wall -Wextra -Werror -pedantic -O2 -o tls_client tls_client.c
$ ./tls_client https://www.example.com
<!doctype html><html lang="en"><head><title>Example Domain</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>body{background:#eee;width:60vw;margin:15vh auto;font-family:system-ui,sans-serif}h1{font-size:1.5em}div{opacity:0.8}a:link,a:visited{color:#348}</style></head><body><div><h1>Example Domain</h1><p>This domain is for use in documentation examples without needing permission. Avoid use in operations.</p><p><a href="https://iana.org/domains/example">Learn more</a></p></div></body></html>
$
```

## Really, don't use this

It's all vibe-coded! A machine has written every line of code though a human
has manually approved every commit (and I'm no cryptographer). An impressive
display of current capability but please don't consider this secure in any
manner. Maybe fun to slot into an old toy where compiling real libraries is
difficult, but not at all for use in anything more serious...

## What's here

~6,000 lines of C99 that implements:

**X.509 chain validation**: signature verification, hostname matching (CN +
SAN), validity periods, basicConstraints / pathLen / keyUsage / EKU
enforcement, name constraints, critical-extension rejection, out-of-order chain
handling.

**Certificate Transparency**: embedded SCT verification (RFC 6962) against
Chrome's CT log list, enforcing Chrome/Apple SCT policy — 2 SCTs for
certificates <=180 days, 3 for longer-lived certificates, from >=2 distinct log
operators.

**CRL revocation checking**: fetches CRL from distribution point URLs embedded
in leaf certificates, verifies the CRL signature against the issuer, and rejects
connections if the certificate serial number appears revoked. Fetched CRLs are
cached to the `crls/` directory and reused until `nextUpdate` expires. Soft-fails
(warns but allows) if no CRL distribution point is present or the fetch fails.

**AIA chasing**: fetches missing intermediate certificates over HTTP when the
server sends an incomplete chain.

**TLS 1.3** (RFC 8446): full handshake with HelloRetryRequest and downgrade
detection.

**TLS 1.2** (RFC 5246): ECDHE and static-RSA key exchange, GCM / CBC /
ChaCha20-Poly1305 record protection.

### Cipher suites

| TLS 1.3 | TLS 1.2 ECDHE | TLS 1.2 RSA |
|---|---|---|
| AES-128-GCM-SHA256 | ECDHE-{RSA,ECDSA}-CHACHA20-POLY1305 | RSA-AES-{128,256}-GCM |
| AES-256-GCM-SHA384 | ECDHE-{RSA,ECDSA}-AES-{128,256}-GCM | RSA-AES-{128,256}-CBC |
| CHACHA20-POLY1305-SHA256 | ECDHE-{RSA,ECDSA}-AES-{128,256}-CBC | |

### Key exchange

- **X25519** (preferred)
- **ECDHE P-256**, **P-384**
- **Static RSA** key transport (TLS 1.2 only)

### Signatures

- ECDSA with P-256/SHA-256 and P-384/SHA-384
- RSA PKCS#1 v1.5 with SHA-256/384/512
- RSA-PSS with SHA-256/384

### Crypto primitives

SHA-1, SHA-256, SHA-384, SHA-512, HMAC, HKDF, AES-128/256 (GCM & CBC),
ChaCha20-Poly1305, P-256/P-384 field & point arithmetic, X25519 Montgomery
ladder, RSA modular exponentiation (64-bit & 32-bit limb paths).

## What's not implemented

- OCSP stapling / OCSP responder checking
- Session resumption (every connection is a full handshake)
- Client certificates
- TLS 1.0/1.1
- RC4/3DES
- DHE
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
make test      # compile, static analysis, 25 random domains + all xfail
make fulltest  # compile, static analysis, all 276 domains + all xfail
```

Runs the compiler, static analysis (cppcheck + clang --analyze), then
expected-pass and 31 expected-fail connection tests covering:

- badssl.com certificate/cipher edge cases + AIA incomplete chain
- ~250 top domains (Google, Amazon, Cloudflare, banks, CDNs, etc.)

Bails early after 10 failures.

## Building

Requires a C99 compiler. No dependencies beyond libc and POSIX sockets.

```
make
```

Works on x86-64 and ARM64 (auto-selects 64-bit limb arithmetic). 32-bit
platforms are supported with a fallback path.

## License
MIT
