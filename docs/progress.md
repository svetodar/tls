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

## Windows default certificate store (task 18)

On Windows the library now uses the system certificate store by default,
so a consumer does not have to point it at a PEM bundle. `crypt32.dll` is
a system API (not a crypto library), so this does not violate the "no
external crypto dependencies" rule; it is the only external call the
library makes on Windows — parsing and verification stay in pure Pascal.

- `tls.certstore` gains `LoadWindowsSystemStore: TCertStore` (Windows
  only). It opens the system `Root` and `CA` stores (`CertOpenStore` with
  `CERT_SYSTEM_STORE_CURRENT_USER` / `LOCAL_MACHINE`), enumerates every
  certificate (`CertEnumCertificatesInStore`), copies each certificate's
  DER bytes out of its context (`CertGetCertificateContextData`), parses
  them with `ParseCertificate` and adds the results via `AddOwnedCert`.
  Every context is freed and both stores are closed before returning; a
  store that cannot be opened raises the new typed error
  `TWinCertStoreError`, a malformed certificate raises `EASN1Error` (the
  partially filled store is dropped first).
- `TCertStore` now distinguishes owned from referenced certificates:
  `Add` keeps a reference only (the caller still owns the certificate),
  `AddOwnedCert` records the certificate in an internal owned list that
  `Destroy` frees. `LoadWindowsSystemStore` uses `AddOwnedCert`, so
  freeing the returned store releases everything it created.
- `TTLSSocketHandler.Connect` resolves the trust store in order: the
  `TrustStore` property, then a bundle from
  `CertificateData.CertCA.FileName`, then — on Windows only — the system
  store via `LoadWindowsSystemStore` unless the new `DisableSystemStore`
  field (default `False`) is set. The handler owns a store it loaded
  itself and frees it after the handshake; with verification requested
  and no store resolvable, `Connect` still returns `False`.
- `examples/https_client.pas` and `tests/tools/tls13_client.pas` load the
  Windows system store on Windows when no CA file is given (the caller
  owns and frees it); on other platforms the old "no CA bundle" error is
  kept.

Tests (skipped off-Windows via `{$ifdef windows}`): `test_certverify` →
`TestWinSystemStoreNonEmpty` (the loaded store is non-empty) and
`TestWinSystemStoreKnownRoot` (the long-lived "Baltimore CyberTrust Root"
is present); `test_tlssocket` → `TestWinSystemStoreFallback` (a connect to
the local `openssl s_server` with no explicit store fails with a chain
error — "issuer not found in store" — proving the fallback used the
system store, where the fixture CA is absent, instead of the strict "no
trust store" error) and `TestWinSystemStoreExampleDotCom` (a verified
connect to `example.com:443` with no explicit store; runs only when
`TLS_TEST_NETWORK=1`). `TestNoTrustStoreFails` sets
`DisableSystemStore := True` so it still asserts the strict no-store
failure on every platform.

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
  On Windows the default system-store fallback is exercised by a
  local-server chain-error test and a network test against `example.com`
  (`TLS_TEST_NETWORK=1`).
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
  handler. The handler defaults to `VerifyPeerCert = True`; the trust store
  is resolved from `TrustStore`, then `CertificateData.CertCA.FileName`,
  then — on Windows — the system store (Root + CA) via
  `LoadWindowsSystemStore` unless `DisableSystemStore` is set; if no store
  can be resolved, `Connect` fails instead of silently accepting the
  certificate.
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
- A `raise;` statement directly in an `except` block followed by a
  `finally` clause is not parsed; nest the `try/except` inside an outer
  `try/finally` (used in `LoadWindowsSystemStore`).

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
the e2e tests are skipped. Rebuilding the fixtures also changes their keys,
so the two reference signatures in `test_tls13.TestCertificateVerifySignatures`
(`EC_SIG`, `RSA_SIG`) must be regenerated as the comment above that test
describes; otherwise it fails with an "openssl ... signature verifies"
assertion.

## Resource-leak audit (2026-10-19)

The library was audited for leaked heap objects (with the test runner built
with `-gh`, so `heap dump by heaptrc` at the end of a run names every block
that was never freed) and for leaked OS resources (file handles, library
handles, `crypt32` certificate contexts and stores).

Heap tracing is opt-in: `make test` builds the runner without it, while
`make leaktest` builds `bin/testrunner_leak` with `-gh -dTLS_HEAPTRACE` and
runs the certificate-verification suite. Tracing a whole run costs too much —
heaptrc hooks every allocation, and the EC and certificate suites then take
minutes instead of seconds — so only the leak checks pay for it. The
`TestWinSystemStoreNoLeak` dump itself is slow (heaptrc walks the whole heap
twice: about 12 minutes on a desktop with a full Windows root store), which
is another reason it stays out of `make test`.

Resource handles. `LoadWindowsSystemStore` closes both system stores on every
path, `LoadPEM`/`LoadBundle` free their `TStringList`, `tls.rand` frees the
`bcrypt.dll` handle (and the `/dev/urandom` stream on Unix) and its global
`TCriticalSection`. No handle leak was found.

`CERT_CONTEXT` handling was worse than a leak: `EnumWinStore` called
`CertEnumCertificatesInStore(hStore, ctx)` to fetch the next context and then
read `ctx^.pbCertEncoded` and finally called `CertFreeCertificateContext(ctx)`.
The enumerator *frees* the context passed to it as `pPrevCertContext`, so the
DER bytes were read from freed memory and every context was freed twice. That
corrupted the heap: on Windows the three system-store tests (and therefore the
whole certificate-verification suite, and `make test`) ended with exit code
`0xC0000374` (`STATUS_HEAP_CORRUPTION`) even though the assertions passed.
`EnumWinStore` now copies the DER bytes while the context is still valid and
lets the enumerator release each context; the only context it frees itself is
the one still held when an exception aborts the loop.

Heap objects. These leaks were found and fixed:

- `tls.x509`: `ParseCertificate`, `ParseName` and `ParseSPKI` returned an
  object only on success but had no handler for the error path, so a
  malformed certificate leaked a `TX509Cert` (with everything already parsed
  into it); `GetBasicConstraints` and the version field called
  `BNToLongInt(ReadInteger(...))`, which drops the `TBN` that `ReadInteger`
  creates — two objects (40 bytes) per parsed certificate. The new
  `ReadIntegerAsLongInt` releases that temporary.
- `tls.asn1`: `ParseDER` leaked the parsed tree when trailing bytes made it
  reject the input.
- `tls.certstore`: `LoadBundle` added the certificates it parsed with `Add`
  (reference only), so freeing the returned store kept every certificate
  alive; it now uses `AddOwnedCert` and releases both the store and the
  certificates parsed so far when the bundle is malformed. `Clear` now
  frees the owned certificates as its documentation always claimed.
- `tls.bn`: `NotBits` leaked the three temporaries of its chained expression.
- `tls.dh`: `Generate` and `ValidatePeerPubFull` leaked the `2`/`1`
  constants they built inline and every value they overwrote (`Priv`, `Q`).
- `tls.rsa`: `IsPrime` never freed `n-1`, `d`, `a`, `x` and `tmp` (on any
  path, including every Miller–Rabin round), `Generate` leaked each rejected
  candidate and the `p-1`/`q-1` factors, `SignPKCS1v15`/`SignPSS` leaked the
  encoded message, and `FromPublicBytes` leaked the two `TBN` it passed to
  `FromPublic`.
- `tls.ec`: `CurveP256`/`CurveP384` leaked the two coordinate `TBN` handed to
  `TECPoint.CreateFromXY` (which clones them) on every call, `PointNeg`
  leaked its `0` constant, and `ECDSASign` leaked the half-built signature
  when it raised.

Verification: the X.509 and certificate-verification suites now report
`0 unfreed memory blocks`, and the EC, TLS 1.2, TLS 1.3 and socket suites no
longer report any block allocated inside `src/`. The system-store tests
(`TestWinSystemStoreNonEmpty`, `TestWinSystemStoreKnownRoot`,
`TestWinSystemStoreNoLeak`), individually and inside the whole
`TCertVerifyTests` suite, now exit with status 0 instead of `0xC0000374`.
`TestWinSystemStoreNoLeak` needs heaptrc, so it only measures under
`make leaktest`; in the normal run it is compiled without tracing and passes
without doing anything.

Known remaining leaks are all in test code, which builds `TBN`/`TECPoint`
objects inline in assertions and never frees them: `tests/test_bn.pas`
(`TestSmallArithmetic`, `TestModInverseKnown`, `TestDivideProperty`,
`TestModInverseProperty`, `TestModPowLaws`, `TestFermat61`,
`TestPerformance2048`), `tests/test_rsa.pas` (the RSADP/RSASP1/PSS vector
tests, `TestGenerateAndRoundTrip`, `TestPKCS1v15EncodeDecode`),
`tests/test_dh.pas` (`TestSymmetrySmallPrime`) and `tests/test_asn1.pas`.
They are one-shot allocations in short-lived test processes, so they do not
affect the library; cleaning them up is a follow-up task. The test helpers
that were cheap to fix were fixed: `test_rand` (`TestRandomBitsRange`,
`TestRandomBitsWithTBN`), `test_ec` (the new `PointFromHex` helper,
`TestScalarMulSmall`, `TestECDSATampered`), `test_rsa` (`TestIsPrime` builds
its candidates through a helper that frees them) and `test_certverify`
(`MakeStore` hands the certificate to the store with `AddOwnedCert` instead
of leaking it).
