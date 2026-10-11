# Progress notes

Implementation notes, verified vectors and FPC-specific pitfalls. This file is
updated together with the code so that future work does not have to rediscover
them.

## Status

| Milestone | Scope | State |
| --- | --- | --- |
| A | primitives: BN, CSPRNG, SHA-2/HMAC, AES, ChaCha20-Poly1305 | done |
| B | asymmetric crypto: RSA, EC (P-256/P-384), DH | done |
| C | certificates: ASN.1/DER, X.509, chain verification | done |
| D | TLS 1.2 client (record layer, handshake, AEAD suites) | done |
| E | integration: TLS socket layer, OpenSSL-free HTTPS client | pending |
| F | TLS 1.3 client | pending |

Test suite: `make test` → **248 tests, 0 errors, 0 failures** (Linux,
FPC 3.2.2). The two end-to-end tests drive a real `openssl s_server` and are
skipped when the `openssl` CLI is unavailable.

## Verified vectors

- **BN:** multiplication/division/ModInverse/ModPow checked against Python
  (`pow(a, e, m)`) and known values (`3^413 mod 97`, `2^128`, 2048-bit
  ModPow under a few seconds).
- **SHA-2 / HMAC:** FIPS 180-4 and RFC 4231 vectors; incremental equals
  one-shot on arbitrary chunks.
- **AES:** NIST SP 800-38A (ECB/CBC) and SP 800-38D (GCM) vectors; GCM tag
  rejects a tampered tag or AAD.
- **ChaCha20-Poly1305:** RFC 8439 test vectors; AEAD round-trip and tamper
  rejection.
- **RSA:** NIST CAVP RSADP (SP 800-56B) and RSASP1 (FIPS 186-4) vectors;
  PKCS#1 v1.5 and PSS sign/verify round-trips.
- **EC:** NIST/RFC 6090 vectors for P-256/P-384; ECDH shared secrets and
  ECDSA verify/tamper.
- **DH:** RFC 3526/5114 groups; symmetric shared secret.
- **ASN.1/X.509:** hand-crafted DER vectors (INTEGER, OID, time, string,
  context/application tags, truncation/indefinite-length errors) plus real
  certificates; parsing of subject/issuer, validity, SPKI, SAN, basic
  constraints.
- **Certificates:** chain verification, expired/mismatch/non-CA cases, host
  matching (exact, wildcard, case-insensitive).
- **TLS 1.2:** record-layer limits and error paths, handshake flight
  assembly, CCS, Finished/VerifyData (constant-time), alerts; end-to-end
  handshake + HTTP exchange with `openssl s_server` for
  `ECDHE-RSA-AES128-GCM-SHA256` and `ECDHE-ECDSA-AES128-GCM-SHA256`.

## Design notes

- `tls.bn` represents `TBN` as an array of 64-bit words, little-endian by
  word, normalised (no leading zero words). `TSignedBN` (sign + magnitude)
  exists only for the extended Euclidean algorithm.
- The CSPRNG is an HMAC-DRBG over SHA-256; the entropy source is
  `/dev/urandom` on Unix and `BCryptGenRandom` on Windows.
- `tls.tls12` is transport-agnostic (`ITLSTransport`); the protocol code
  never touches a socket. Tests use an in-memory `TTLSStreamTransport`.
- Only AEAD cipher suites are supported; CBC and static-RSA suites are
  recognised by name but rejected with a clear error
  (`TLS12CipherSuiteSupported`/`TLS12CheckCipherSuiteSupported`).
- Certificate `Reason` strings use stable English keywords
  (`expired`, `issuer`, `nil`, …) that the tests assert on.

## FPC 3.2.2 pitfalls

- `+` is not overloaded for `TBytes` — use a helper such as
  `ASN1_BytesConcat`.
- There is no `System.HexToBytes`; the tests carry a local hex decoder.
- A class property named `Length` shadows the global `Length()` inside that
  class — name such properties differently (`DataLength`).
- `PosEx` is not always available — use a local character search where
  needed.
- Units are compiled into `build/`; never commit `*.o`/`*.ppu` build output.
- A `{$...}` directive nested inside a `{}` comment produces a "Comment
  level 2" warning but is accepted; keep such combinations balanced.

## How to rebuild test data

```bash
make test       # build tests and run them
make fixtures   # regenerate tests/fixtures (needs openssl + python3)
```

`make fixtures` needs the OpenSSL 3.5.9 sources in `./OpenSSL/` for the eight
`openssl_*.der` vectors; without them that step is skipped and the committed
vectors are kept. See [`openssl-reference.md`](openssl-reference.md).
