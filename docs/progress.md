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
| G | trust sources: Windows system store, embedded root bundle | done |

Test suite: `make test` → **385 tests, 0 errors, 0 failures** (FPC
3.2.2); `make check-no-openssl` → no OpenSSL unit references. The
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

## Embedded root certificates (task 19)

The Mozilla root program now ships inside the executable. A DER table of
trusted roots is embedded as an `RT_RCDATA` resource of `tls.roots`, read
lazily once per process, integrity-checked with SHA-256 and turned into a
`TCertStore` that `VerifyChain` accepts; the PEM snapshot in `certs/` stays the
source of truth in git. No external crypto dependency was added — base64, DER
parsing and SHA-256 were already here — and `fpcres` is needed only by the
generator, never at run time.

- `tls.certstore` gained the memory readers `LoadPEMFromMemory(text)` and
  `LoadBundleFromStream(stream)`; `LoadPEM` and `LoadBundle` are now thin file
  wrappers over them, so a bundle can come from a file, a resource or any
  `TStream`. Errors stay `EASN1Error`, and a bundle store owns its certificates
  (`AddOwnedCert`). The spec also listed `LoadBundleFromMemory`; it was not
  added — a string goes through `LoadBundleFromStream` with a `TStringStream`,
  and one bundle reader is enough.
- `TCertStore` lookups are indexed. `Add`/`AddOwnedCert` compute each
  certificate's lookup keys once — the canonical subject name (lower-case,
  blanks collapsed; the same `CanonicalSubjectName`/`subjectHash` normalisation)
  and its SKI as lower-case hex — and keep sorted order arrays, so
  `FindBySubject`/`FindBySKI` are binary searches that still return the
  certificate added first. Lookups never write, so a store shared between
  threads (the embedded roots) can be searched concurrently. `VerifyChain` and
  its `Reason` texts are untouched, and `test_tlssocket` passes unchanged.
- `tls.roottable` owns the format: a 48-byte header (`TLSROT`, version, flags,
  `count`, `snapshotDate` as Unix days, `dataSha256`), 34-byte records
  (`derOffset`, `derLength`, `subjectHash`, `skiPresent` + 20-byte SKI, trust
  bits `web`/`email`/`code`/`distrusted`) and then the DER blobs; `dataSha256`
  covers everything after the header. `DecodeRootTable` validates magic,
  version, flags, `count` bounds, every offset/length and the record area, and
  raises the new `ECertBundleError` on the first violated invariant;
  `CertStoreFromTable`/`BuildCertStore` skip `distrusted` entries — they never
  become trust anchors — and return a store that owns its certificates.
- `tools/rootsgen/rootsgen.lpr` reads `certs/roots.pem` with its own PEM
  splitter and base64 decoder, parses each certificate through `tls.x509`,
  derives the subject hash, the SKI and the trust byte, sorts records
  deterministically (`subjectHash`, then SHA-256 of the DER, then PEM order),
  writes `build/roots/roots.bin` and `build/roots/tlsroots.rc` and calls
  `fpcres` to produce `src/tlsroots.res`. It needs no openssl, python or
  network, and two runs on the same inputs are byte-identical.
- `tls.roots` is the only unit with `{$R tlsroots.res}` and the only one that
  names the resource (`TLSROOTS`, `RT_RCDATA`). Every read recomputes SHA-256
  over the payload and compares it with the header digest byte by byte, without
  an early exit; a mismatch raises `ECertBundleError` ("embedded roots are
  corrupted") instead of handing out a weaker store. `VerifyEmbeddedRootsSha256`
  exposes that check so the tests can feed it tampered and truncated bytes,
  which a resource linked into the executable does not allow. `EmbeddedRoots`
  is a lazily built, double-checked, thread-safe cache of the decoded table and
  of the store; `EmbeddedRootsDate` and
  `EmbeddedRootsIsStale(ANow, AMaxAgeDays = 365)` report the snapshot date and
  its age (a flag, not an error: a future date is never stale, a negative
  `AMaxAgeDays` is an `EArgumentOutOfRangeException`); `ReleaseEmbeddedRoots`
  drops both so that the next call rebuilds them. A failed attempt caches
  nothing, so the next call retries instead of seeing a half-built store.
- Pinned by the tests: 120 roots (certifi `2026.10.19`, `certs/roots.pem`
  238 856 bytes), snapshot date `2026-10-22` (Unix days 20748), table
  132 677 bytes, `dataSha256 =
  391521bf207b7891ed90e9a967db17413c728eb2db1bcd0b291978928aad0dec`. ISRG Root
  X1 is present exactly once (published DER SHA-256 `96bcec…08c6`, SKI
  `79b459e6…f6e99b6e`) and `VerifyChain(EmbeddedRoots, ISRG Root X1)`
  succeeds; an RSA chain from `tests/fixtures` verifies only after its CA is
  added to a small table built from those fixtures, which exercises the reader
  and the store path end to end.
- New tests: `tests/test_roottable.pas` (`TRootTableTests`, 27 cases: the valid
  table, every broken header/record, the `distrusted` filter),
  `tests/test_roots.pas` (`TRootsTests`, 18 cases: pinned count/date/digest,
  record layout, ISRG Root X1, fixture chain, staleness, tampered/truncated
  table through `VerifyEmbeddedRootsSha256`, cache rebuild) and 13
  memory-reader cases in `tests/test_certverify.pas`.
- `make roots` is the only step that needs `fpcres`, and it fails early with a
  message when the tool is missing. Unlike the plan in the task spec, `build`,
  `test` and `leaktest` do not depend on `src/tlsroots.res`: a fresh checkout
  runs `make roots` once, or builds with `-dTLS_NO_EMBEDDED_ROOTS`.

### Follow-up stages (tracked separately)

Task 19 was implemented and verified on the Windows x86_64 FPC 3.2.2 target
only. Two further stages are deliberately **not** part of this work and are
tracked as separate steps so the commit stays one task:

- **Linux FPC 3.2.2 verification run.** Rebuild the resource with the Linux
  `fpcres` and run `make roots`, `make test`, `make leaktest` and
  `make check-no-openssl` on a Linux x86_64 host. The unit-level expectation is
  that nothing changes: the compiler links `{$R tlsroots.res}` on every FPC
  target, `RT_RCDATA` comes from `System` there instead of `windows`, and
  `tls.rand` reads `/dev/urandom`. Two outcomes have to be checked rather than
  assumed: `src/tlsroots.res` produced by the Linux `fpcres` is byte-identical
  to the one produced on Windows, and the resource is readable at run time from
  an ELF executable. If either differs, this note gets the actual numbers.
- **Integration into the consuming `subag` project** (submodule `deps/tls`).
  Bump the submodule, make `EmbeddedRoots` the default trust source in the
  host's TLS setup, remove the "put ca-bundle.pem next to the program" message,
  and keep the documented order explicit store → embedded roots → OS store →
  explicit opt-out. That change lives in the host repository and is its own
  pull request, not a change to this library.

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
- `tls.roottable` is bytes-in/structure-out — no file, resource or OS call —
  and `tls.certstore` stays bundle-format agnostic; the embedded table is
  reached only through `tls.roots`, the single unit with a `{$R}`. That keeps
  the byte-level format testable in memory (`TRootTableTests` builds tables by
  hand) and lets `tools/rootsgen` link the same units without pulling in the
  resource it produces (the Makefile filters `tls.roots` out of its
  dependencies).
- The documented trust-source order is explicit `TrustStore` → embedded roots →
  OS store → explicit opt-out (`DisableSystemStore`). Only the first and the
  Windows store are wired into `TTLSSocketHandler` today; using
  `EmbeddedRoots` as its fallback is a separate host-side step, so a consumer
  that wants the bundle passes `EmbeddedRoots` as the `TrustStore` (and must
  not free it).

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
- `{$R file.res}` in a unit is a hard compile-time dependency: a missing
  `.res` is a fatal error, not a link error, so a build of a component that
  leaves `tls.roots` in the uses clause needs `make roots` first — or
  `-dTLS_NO_EMBEDDED_ROOTS`, which drops the `{$R}` and makes every embedded
  roots call raise `ECertBundleError`.
- `RT_RCDATA` is not defined by `SysUtils`: it comes from `System` on some
  targets and from `windows` on Windows — `uses Classes, SysUtils {$ifdef
  windows}, Windows {$endif}` compiles both ways.
- `TResourceStream.Create(HInstance, 'TLSROOTS', RT_RCDATA)` is how a named
  `{$R}` entry is read: `RT_RCDATA` is a `PChar`-typed resource type, the
  name is the string from the `.rc`, and no `MakeIntResource`/numeric id is
  involved. A missing entry is an `EResNotFound` at run time (hence the typed
  `ECertBundleError` wrapper), a missing `.res` a compile error.
- heaptrc's `DumpHeap` walks freed blocks too and faults under FPC 3.2.2 once
  the memory manager has released a page back to the OS; for a heap-growth
  check read `GetFPCHeapStatus.CurrHeapUsed` instead (see
  `TestWinSystemStoreNoLeak`).

## How to rebuild test data

```bash
make test       # build tests and run them
make fixtures   # regenerate tests/fixtures (needs openssl + python3)
make roots      # regenerate src/tlsroots.res from certs/ (needs fpcres)
```

`make fixtures` needs the OpenSSL 3.5.9 sources in `./OpenSSL/` for the eight
`openssl_*.der` vectors; without them that step is skipped and the committed
vectors are kept. See [`openssl-reference.md`](openssl-reference.md).

`make roots` is deterministic and is needed only when the snapshot in `certs/`
changes or after a fresh checkout: `src/tlsroots.res` is generated and
git-ignored, and `tls.roots` does not compile without it unless
`-dTLS_NO_EMBEDDED_ROOTS` is given. `tests/test_roots.pas` pins the resulting
certificate count, snapshot date and `dataSha256`, so a refreshed snapshot has
to update those constants in the same commit.

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
minutes instead of seconds — so only the leak checks pay for it. The second
reason used to be the dump itself; the next paragraph explains why that is no
longer the case.

`TestWinSystemStoreNoLeak` used to dump the whole heap; heaptrc walks every
block it has ever handed out, freed ones included, and dereferences their
headers, so under FPC 3.2.2 it faults once the memory manager has returned a
freed page to the OS (the EC suite allocates multi-megabyte buffers, and the
system store alone allocates for 158 certificates). The walk also took about
12 minutes with a full Windows root store. The test now compares
`GetFPCHeapStatus.CurrHeapUsed` before and after repeated
`LoadWindowsSystemStore` calls: the counter is a number, safe to read at any
time, and the check takes milliseconds.

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
