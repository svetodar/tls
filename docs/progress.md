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
| E | integration: TLS socket layer, OpenSSL-free HTTPS client | done |
| F | TLS 1.3 client (RFC 8446, 1-RTT, HKDF, AEAD-only, X25519) | done |

Test suite: `make test` → **316 tests, 0 errors, 0 failures** (Linux,
FPC 3.2.2); `make check-no-openssl` → no OpenSSL unit references. The
end-to-end tests drive a real `openssl s_server` and are skipped when the
`openssl` CLI is unavailable; the network-required test to `example.com` only
runs when `TLS_TEST_NETWORK=1`.

## Merge: wip/subag-tls-transport into main (2026-10-16)

The submodule branch `deps/tls` (`wip/subag-tls-transport`, commit
"X25519, ciphertext record limit, pathlen fix; TLS 1.3 client") was merged
into `main` in the standalone clone (`../tls`). The two lines of work had
diverged from `f69dbfe`, so the merge kept the richer implementation of each
area and ported the rest:

- `tls.tls13.pas` from `main` (full 1-RTT client, `CertificateVerify`,
  record layer) plus X25519 key shares taken from the branch: the branch's
  `src/tls.x25519.pas` is now part of the library and `tls.tls13` uses it
  for `key_share` (X25519 is the first default group);
- `tests/test_x25519.pas` from the branch (RFC 7748 vectors);
- `TLS12DefaultSupportedGroups` and the certstore path-length constraint
  from the branch (advertise only implemented groups; count additional
  certificates, not the leaf);
- the ciphertext record limit (`TLSRecordMaxCiphertext` / `AMaxLength`) was
  already present on `main`;
- `tests/test_tls12.pas`, `tests/testrunner.lpr`, README/plan/architecture/
  progress docs merged by hand.

## Fix: EMSA-PSS emBits used the byte length instead of the modulus bits

`PSSEncode`/`PSSVerify` derived `emBits` as `emLen*8 - 1`, but RFC 8017
uses `emBits = modBits - 1` and `emLen = ceil(emBits/8)`. A 1024-bit RSA
key whose primes give a 1023-bit modulus is common (`p`, `q` both 512-bit),
and for it `emLen` is 128 while only 1022 bits are significant: the old
code cleared the top bit only, so EM could be >= n and a valid signature
occasionally failed to verify (about 8% of randomly generated keys).
`PSSEncode`/`PSSVerify` now take the modulus bit length; `SignPSS`/
`VerifyPSS` pass `N.BitLength`. Regression:
`tests/test_rsa.pas` → `TestPSSModBitsBoundary` asserts that with a 1023-bit
modulus the top two bits of EM are zero.

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
  The high-level `TTLS12Client` orchestrates the handshake and the
  application-data exchange over `ITLSTransport`.
- **Socket layer:** `tls.tlssocket` drives a real `TInetSocket`; tests cover
  verified connect (RSA/ECDSA), unknown-CA and host-mismatch rejection, the
  strict no-trust-store error, verification-disabled mode, clean encrypted
  `close_notify`, and a 100 kB multi-record response read in 512-byte chunks.
- **TLS 1.3:** HKDF-Extract/Expand against RFC 5869 A.1–A.3 (SHA-256) plus
  independent SHA-384 vectors; `HkdfLabel` serialization and
  `HKDF-Expand-Label` against python3/`openssl kdf` references. The complete
  SHA-256 key schedule (early, derived, handshake, c/s handshake, master and
  the four traffic secrets) matches the RFC 8448 §3 trace and the RFC 8448
  PSK early secret; SHA-384 was checked against the same independent
  reference. Record layer: `nonce = iv XOR seq_num`, AAD and
  inner-plaintext round-trips (including padding and malformed cases), the
  RFC 8448 AES-128-GCM client-Finished and application-data vectors, and
  published vectors for all three suites. Handshake parsers are covered for
  valid input and for explicit rejection (HelloRetryRequest sentinel random,
  unknown/TLS 1.2 cipher suite, malformed bodies, bad `CertificateVerify`).
  End-to-end handshake + HTTP GET against `openssl s_server -tls1_3` for
  `TLS_AES_128_GCM_SHA256` over P-256 with RSA and ECDSA certificates, for
  `TLS_AES_256_GCM_SHA384` over P-384 and for `TLS_CHACHA20_POLY1305_SHA256`.
  The key_share group is X25519, secp256r1 or secp384r1, selected by the
  server from the offered list.

## Design notes

- `tls.bn` represents `TBN` as an array of 64-bit words, little-endian by
  word, normalised (no leading zero words). `TSignedBN` (sign + magnitude)
  exists only for the extended Euclidean algorithm.
- TBN methods return **new** objects that the caller owns; the arithmetic
  helpers (`Modulo`, `ModAdd`, `ModSub`, `ModMul`, `ModPow`, `ModInverse`,
  `Divide`, `ToString`) free their temporary intermediates. The EC point
  operations free the abandoned intermediates when a result is reassigned.
  This keeps a full handshake allocation-neutral (see the heaptrc notes).
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
- `tls.tlssocket` deliberately reads/writes the socket's file descriptor
  with `fprecv`/`fpsend` instead of `TSocketStream.Read/Write`: the socket
  owns the handler, so going through the stream would recurse into the TLS
  handler. The handler defaults to `VerifyPeerCert = True`; without a trust
  store `Connect` fails instead of silently accepting the certificate.
- After the handshake, alerts (including `close_notify`) are AEAD-protected;
  `TTLS12Client.Recv` decrypts them before decoding, so a normal close is
  reported as EOF (0) rather than as a receive error (-1).
- TLS 1.3 lives in `tls.tls13` on the same layer as `tls.tls12` and reuses
  its `ITLSTransport`, the SNI extension encoder and `TTLS12CertChain` /
  `TCertStore` for verification. HKDF and every 1.3-only derivation stay in
  `tls.tls13`; `tls.prf` remains strictly TLS 1.2. Like the 1.2 client,
  `TTLS13Client` never touches a socket, so it is testable in memory.
- The 1.3 record layer is AEAD-only: `nonce = iv XOR (zero-padded big-endian
  sequence number)` and the AAD is the five-byte record header; the inner
  plaintext is `content || content_type || 0^padding`. Legacy
  `ChangeCipherSpec` records and post-handshake `NewSessionTicket` are
  ignored; `KeyUpdate` is rejected.
- HelloRetryRequest is detected by the RFC 8446 §4.1.3 sentinel random and
  rejected with an explicit `ETLS13Error` (no silent second ClientHello).
  0-RTT/PSK resumption and client certificates are not implemented.
  `key_share` offers X25519, P-256 and P-384; X25519 (`tls.x25519`) is the
  first preference.
- `tls.tls13` must not reuse `TLSAEADFixedIvLength` (which returns 4 for
  TLS 1.2 AES-GCM) for the traffic keys: TLS 1.3 always uses a 12-byte IV
  and puts the real content type inside the AEAD plaintext.
- `ETLS13Error` derives from `ETLS12Error`, so callers may keep catching the
  TLS 1.2 type; every unsupported or malformed input raises it instead of a
  bare `Exception`.

## FPC 3.2.2 pitfalls

- `+` is not overloaded for `TBytes` — use a helper such as
  `ASN1_BytesConcat` (`tls.tls13` carries its own local `BytesConcat`).
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
