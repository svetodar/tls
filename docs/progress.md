# Progress notes

Implementation notes, verified vectors and FPC-specific pitfalls. This file is
updated together with the code so that future work does not have to rediscover
them.

## Status

| Milestone | Scope | State |
| --- | --- | --- |
| A | primitives: BN, CSPRNG, SHA-2/HMAC, AES, ChaCha20-Poly1305 | done |
| B | asymmetric crypto: RSA, EC (P-256/P-384), X25519, DH | done |
| C | certificates: ASN.1/DER, X.509, chain verification | done |
| D | TLS 1.2 client (record layer, handshake, AEAD suites) | done |
| E | integration: TLS socket layer, OpenSSL-free HTTPS client | pending |
| F | TLS 1.3 client | done |

Test suite: `make test` → **289 tests, 0 errors, 0 failures** (Linux,
FPC 3.2.2). The six end-to-end tests drive a real `openssl s_server` and are
skipped when the `openssl` CLI or the regenerated fixture keys are
unavailable.

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
- **X25519:** RFC 7748 §5.2 raw vectors and the 1,000-iteration test, §6.1
  Diffie–Hellman (both public keys and the shared secret); bit-255 masking,
  low-order points (u = 0, 1, p−1) and differential testing against a Python
  reference over random and edge-case inputs.
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
- **TLS 1.3:** HKDF against RFC 5869 Appendix A.1/A.3; the key-schedule
  intermediates against RFC 8448 §3 (`early_secret`, `derived_secret`,
  `handshake_secret`) and the traffic secrets/keys/Finished against an
  independent Python reference; the record layer (nonce XOR, AAD, AEAD
  round-trip for AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305, tamper and
  wrong-sequence rejection, inner content type); ClientHello structure and
  ServerHello/HelloRetryRequest/Certificate parsing; CertificateVerify
  context string. End-to-end handshake + HTTP with `openssl s_server -tls1_3`
  for `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
  `TLS_CHACHA20_POLY1305_SHA256`, with RSA-PSS and ECDSA certificates.

## Design notes

- `tls.bn` represents `TBN` as an array of 64-bit words, little-endian by
  word, normalised (no leading zero words). `TSignedBN` (sign + magnitude)
  exists only for the extended Euclidean algorithm.
- The CSPRNG is an HMAC-DRBG over SHA-256; the entropy source is
  `/dev/urandom` on Unix and `BCryptGenRandom` on Windows.
- `tls.x25519` is independent of `tls.bn`: it uses five 51-bit limbs
  (radix 2^51) and a Montgomery ladder whose conditional swap is arithmetic,
  so the ladder does not branch on scalar bits. `FeMul` folds the carry out
  of limb 9 as `361 * carry` (2^510 = 19^2 mod p); without this fold,
  representatives such as `p + 256` give wrong results in low-order-point
  paths.
- `tls.tls12` is transport-agnostic (`ITLSTransport`); the protocol code
  never touches a socket. Tests use an in-memory `TTLSStreamTransport`.
- Only AEAD cipher suites are supported; CBC and static-RSA suites are
  recognised by name but rejected with a clear error
  (`TLS12CipherSuiteSupported`/`TLS12CheckCipherSuiteSupported`).
- Certificate `Reason` strings use stable English keywords
  (`expired`, `issuer`, `nil`, …) that the tests assert on.
- `tls.tls13` keeps the TLS 1.2 record/handshake encoders but has its own
  record protection: TLS 1.3 always uses a 12-byte IV and puts the real
  content type inside the AEAD plaintext, so `TLSAEADFixedIvLength` (which
  returns 4 for TLS 1.2 AES-GCM) must not be reused for the traffic keys.
- The RSA PSS code in `tls.rsa` is SHA-256 only, so the TLS 1.3
  `signature_algorithms` list advertises `rsa_pss_rsae_sha256` but not the
  SHA-384/512 variants; ECDSA P-256/P-384 use the existing certstore
  verifier. `HelloRetryRequest`, PSK/0-RTT and post-handshake `KeyUpdate`
  are rejected with a clear `ETLS13Error`.

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

Running the end-to-end tests (TLS 1.2 and 1.3) requires the `*.key` files:
run `make fixtures` to generate them (the keys are git-ignored). Without them
the e2e tests are skipped.
