# tls_client

A featureful TLS 1.2/1.3 client "from scratch" in a single C file: no external
dependencies besides POSIX / C stdlib.

```
make
./tls_client https://example.com/
```

## Really, don't use this

It's all vibe-coded! A machine has written every line of code though a human
has manually approved every commit (and I'm no cryptographer). An impressive
display of current capability but please don't consider this secure in any
manner. Maybe fun to slot into an old toy where compiling real libraries is
difficult, but not at all for use in anything more serious...

## What's here

~5,700 lines of C17 that implements:

**TLS 1.3** (RFC 8446): full handshake with HelloRetryRequest and downgrade
detection.

**TLS 1.2** (RFC 5246): ECDHE and static-RSA key exchange, GCM / CBC /
ChaCha20-Poly1305 record protection.

**X.509 chain validation**: signature verification, hostname matching (CN +
SAN), validity periods, basicConstraints / pathLen / keyUsage / EKU
enforcement, name constraints, critical-extension rejection, out-of-order chain
handling.

**AIA chasing**: fetches missing intermediate certificates over HTTP when the
server sends an incomplete chain.

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

- **Revocation checking**: OCSP, CRL, and CT/SCT are not implemented
- **Session resumption**: every connection is a full handshake
- **Client certificates**
- **TLS 1.0/1.1**
- **RC4/3DES**
- **DHE** (ECDHE and static RSA are supported)
- **0-RTT**
- **Renegotiation and compression**

## Trust store

Place PEM-encoded root CA certificates (`.crt`) in the `trust_store/`
directory. To fetch the latest Mozilla CA bundle from Debian stable:

```
make getcerts
```

## Testing

```
bash test.sh
```

Runs the compiler, static analysis (cppcheck + clang --analyze), then 276
expected-pass and 31 expected-fail connection tests covering:

- badssl.com certificate/cipher edge cases + AIA incomplete chain
- ~250 top domains (Google, Amazon, Cloudflare, banks, CDNs, etc.)

## Building

Requires a C17 compiler. No dependencies beyond libc and POSIX sockets.

```
make
```

Works on x86-64 and ARM64 (auto-selects 64-bit limb arithmetic). 32-bit
platforms are supported with a fallback path.

## License
MIT
