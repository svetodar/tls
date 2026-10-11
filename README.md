# tls — TLS client and cryptographic primitives in pure Free Pascal

`tls` is a self-contained TLS client library written in **Free Pascal**, with
its own implementations of every cryptographic primitive it needs. It does not
link against OpenSSL, libcrypto or any other C library: hashing, symmetric and
asymmetric cryptography, certificate parsing and the TLS protocol itself are
implemented in Pascal.

The library targets **FPC 3.2.2** and is written in plain Object Pascal
(`{$mode objfpc}{$H+}`), with no dependency on Lazarus/LCL.

## Status

| Milestone | Scope | State |
| --- | --- | --- |
| A | primitives: BN, CSPRNG, SHA-2/HMAC, AES, ChaCha20-Poly1305 | done |
| B | asymmetric crypto: RSA, EC (P-256/P-384), DH | done |
| C | certificates: ASN.1/DER, X.509, chain verification | done |
| D | TLS 1.2 client (record layer, handshake, AEAD suites) | done |
| E | integration: TLS socket layer, drop-in replacement for OpenSSL | pending |
| F | TLS 1.3 client | pending |

TLS 1.2 currently interoperates end to end with a real TLS server
(`openssl s_server`, ECDHE-RSA and ECDHE-ECDSA suites, AES-GCM and
ChaCha20-Poly1305). Server-side TLS, renegotiation, TLS 1.0/1.1, CBC suites
and static-RSA key exchange are intentionally out of scope.

Test suite: **`make test` → 248 tests, 0 errors, 0 failures** (Linux, FPC 3.2.2).

## Requirements

- Free Pascal ≥ 3.2.2 with the standard packages (`fcl-fpcunit`, `fcl-base`,
  `fcl-web` for `ssockets`);
- `openssl` CLI — needed only by the end-to-end tests (`openssl s_server`);
  without it those two tests are skipped;
- `openssl` + `python3` — needed only to regenerate the test fixtures
  (`make fixtures`).

## Build and test

```bash
make            # build the test runner and run the unit tests
make build      # build bin/testrunner only
make test       # run the tests
./build.sh      # same as "make test", with a gmkdir shim when needed
make fixtures   # regenerate certificate and DER fixtures (openssl + python3)
make clean
```

## Layout

```
src/              library units (tls.<area>.pas)
tests/            fpcunit tests, one unit per source area
tests/fixtures/   certificates, DER vectors, fixture generator (gen_certs.sh)
tests/tools/      standalone debugging programs (not part of the test run)
docs/             design, plans, task specs, progress notes
Makefile          build of the test runner
build.sh          convenience wrapper around make
```

## Units

| Unit | Purpose |
| --- | --- |
| `tls.bn` | arbitrary-precision integers: add/sub/mul/div, modular arithmetic, ModPow, ModInverse, hex/dec/bytes conversion |
| `tls.rand` | CSPRNG: HMAC-DRBG (NIST SP 800-90A) over SHA-256, entropy from `/dev/urandom` or `BCryptGenRandom` |
| `tls.sha2` | SHA-256/384/512 |
| `tls.hmac` | HMAC (RFC 2104) |
| `tls.aes` | AES-128/192/256, CBC (with and without PKCS#7), GCM |
| `tls.chacha20` | ChaCha20, Poly1305, AEAD ChaCha20-Poly1305 |
| `tls.rsa` | RSA: key parsing/generation, PKCS#1 v1.5 and PSS signatures, RSAES-PKCS1-v1_5 |
| `tls.ec` | NIST P-256/P-384: point arithmetic, ECDH, ECDSA |
| `tls.dh` | finite-field DH (DHE), standard groups |
| `tls.prf` | TLS 1.2 PRF and key-schedule helpers (RFC 5246, RFC 7627) |
| `tls.asn1` | ASN.1/DER parser and encoder |
| `tls.x509` | X.509 v3 certificate parsing |
| `tls.certstore` | trust store and chain/signature verification |
| `tls.tls12` | TLS 1.2 client: record layer, handshake, AEAD record protection, alerts |

The transport used by `tls.tls12` is abstract (`ITLSTransport` with
`Read`/`Write`/`BytesAvailable`), so the protocol code never touches a socket
directly; `TTLSStreamTransport` adapts any `TStream`, and the tests use an
in-memory mock.

## Documentation

- [`docs/plan.md`](docs/plan.md) — goal, scope, layers, milestones, risks.
- [`docs/architecture.md`](docs/architecture.md) — unit layering and public API.
- [`docs/tasks/`](docs/tasks/) — task specs `01-bn.md` … `16-e2e.md`
  (one per work item; the pending ones define milestones E and F).
- [`docs/progress.md`](docs/progress.md) — implementation notes, verified
  vectors, FPC pitfalls.
- [`docs/openssl-reference.md`](docs/openssl-reference.md) — how to obtain the
  OpenSSL sources used as a reference and where to look for each algorithm.

## Contributing

See [`AGENTS.md`](AGENTS.md) for the conventions this repository follows
(layering, test requirements, language, licensing) — they apply to human and
agent contributors alike.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
Every source file carries an `SPDX-License-Identifier: Apache-2.0` tag.
