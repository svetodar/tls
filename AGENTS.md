# AGENTS.md — working agreement for this repository

This file describes how work is done in the `tls` repository. It applies to
every contributor, human or automated agent, and is intentionally free of
details that belong to a particular development tool or harness.

## What this project is

A pure Free Pascal implementation of a **TLS client** and of all the
cryptographic primitives it needs. The library must stay free of external
crypto dependencies: no OpenSSL, no libcrypto, no other C library, no `openssl`
unit from FPC. Everything is implemented in Pascal, on top of the RTL and the
standard FPC packages only.

Primary target: **FPC 3.2.2**, plain object Pascal (`{$mode objfpc}{$H+}`), no
LCL/Lazarus dependency inside the library.

## Language

Technical English is the main language of this repository: documentation,
source comments, identifiers, test names, commit messages, issues and reviews.
Do not introduce other natural languages in code or docs.

## Layout and conventions

- `src/tls.<area>.pas` — one unit per area, named after the repository
  (for example `tls.bn.pas`, `tls.tls12.pas`). Unit names carry the `tls.`
  prefix so that they never collide with RTL/FCL units. No unit may be named
  after, or reference, a consuming application.
- `tests/test_<area>.pas` — fpcunit tests for the matching area, registered in
  `tests/testrunner.lpr`. Test class names are `<Area>Tests`.
- `tests/fixtures/` — certificates, DER vectors and the generator script.
  Key files (`*.key`) are git-ignored: regenerate them with `make fixtures`,
  never commit them.
- `tests/tools/` — standalone debugging programs; not part of the test run.
- `docs/tasks/NN-<name>.md` — one task spec per work item, with goal, inputs,
  outputs, acceptance criteria and references.
- `docs/` — design, plan, progress notes. Update the docs together with code
  that changes documented behaviour.

## Architecture rules

The library is layered bottom-up; a layer may only depend on layers below it:

```
[0] bn, rand, sha2 -> hmac, aes, chacha20
[1] rsa, ec, dh                    (use [0])
[2] asn1 -> x509 -> certstore      (verification uses [1] and sha2)
[3] prf, tls12 (-> tls13 planned)  (use everything below)
[4] socket layer and host integration (planned)
```

- Protocol code must never talk to a socket or a file directly: `tls.tls12`
  uses the abstract `ITLSTransport` (`Read`/`Write`/`BytesAvailable`). Keep new
  protocol code transport-agnostic so it stays testable in memory.
- The library must not know about its consumers. No host-specific unit names,
  paths, messages or configuration.
- Only client-side TLS is in scope. Server mode, renegotiation, TLS 1.0/1.1,
  CBC cipher suites and static-RSA key exchange are out of scope; unsupported
  suites must produce a clear error, never a silent misbehaviour.

## Definition of done

1. `make test` passes (`./build.sh` is an equivalent convenience wrapper).
2. New behaviour is covered by tests that use *published* vectors
   (NIST/FIPS/SP 800-38A/38D, RFC 4231/8439, RFC 5246 and friends) or a
   documented independent reference. Never assert against the implementation's
   own output alone.
3. The end-to-end test may be skipped where the `openssl` CLI is unavailable,
   but it must pass where it is available — never delete or weaken it to get
   green.
4. Public API or layout changes are reflected in `docs/architecture.md`
   (and `docs/progress.md` when relevant).
5. Every source file starts with a comment block containing
   `SPDX-License-Identifier: Apache-2.0`.

## Crypto engineering rules

- Secret-dependent data must be compared in constant time; never branch on or
  log secret material. Test keys are the only exception and stay in
  `tests/fixtures/` (git-ignored).
- Randomness comes from `tls.rand` only; never use `Random()`/`RandSeed` for
  key material, nonces or IVs.
- Reject malformed input loudly: parsers (DER, X.509, handshake, records) must
  raise a typed error (`EASN1Error`, `EX509Error`, `ETLS12Error`, …) instead of
  returning partial data. Lengths and bounds are always validated before use.
- Keep record/handshake limits explicit (`TLSRecordMaxPayload` and friends) and
  test the boundary conditions (truncated, oversized, unknown type).

## Known FPC 3.2.2 pitfalls (keep in mind, they cost real debugging time)

- `+` is not overloaded for `TBytes` — use a helper such as `ASN1_BytesConcat`.
- There is no `System.HexToBytes`; write a local hex decoder in tests.
- A class property named `Length` shadows the global `Length()` inside that
  class — name such properties differently (`DataLength`).
- `PosEx` is not always available — use a local character search when needed.
- Units are compiled into `build/`; never commit build output, `*.o` or
  `*.ppu` files.

## How to work on a task

1. Read the matching spec in `docs/tasks/` and the relevant part of
   `docs/architecture.md`.
2. Implement the unit (or the change) together with its tests.
3. Run `make test`; fix until green.
4. Update docs (task spec status, `docs/progress.md` notes, README unit table
   if a unit was added).
5. Keep commits focused: one task per commit, message in the imperative mood,
   describing behaviour rather than files touched.
