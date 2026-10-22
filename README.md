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
| B | asymmetric crypto: RSA, EC (P-256/P-384), X25519, DH | done |
| C | certificates: ASN.1/DER, X.509, chain verification | done |
| D | TLS 1.2 client (record layer, handshake, AEAD suites) | done |
| E | integration: TLS socket layer, drop-in replacement for OpenSSL | done |
| F | TLS 1.3 client (1-RTT, AEAD, HKDF, X25519) | done |

TLS 1.2 and TLS 1.3 currently interoperate end to end with a real TLS
server (`openssl s_server`): TLS 1.2 with ECDHE-RSA and ECDHE-ECDSA suites
(AES-GCM and ChaCha20-Poly1305), TLS 1.3 with `TLS_AES_128_GCM_SHA256`,
`TLS_AES_256_GCM_SHA384` and `TLS_CHACHA20_POLY1305_SHA256` (ECDSA or
RSA-PSS CertificateVerify), with the X25519, secp256r1 and secp384r1
groups. A complete HTTPS client can be built on top of the library without
system OpenSSL (see `examples/https_client.pas`). Server-side TLS,
renegotiation, TLS 1.0/1.1, CBC suites and static-RSA key exchange are
intentionally out of scope. TLS 1.3 does not implement 0-RTT/PSK
resumption, HelloRetryRequest or KeyUpdate.

Test suite: **`make test` → 385 tests, 0 errors, 0 failures** (FPC
3.2.2; the end-to-end tests are skipped when the `openssl` CLI or the
regenerated certificate keys are unavailable).

Verified on the Windows x86_64 FPC 3.2.2 target. A Linux verification run
(`make roots` + `make test` there) and switching the consuming `subag` project
to the embedded roots are tracked as separate follow-up stages, not as part of
task 19 — see *Follow-up stages* in `docs/tasks/19-embedded-roots.md`.

## Requirements

- Free Pascal ≥ 3.2.2 with the standard packages (`fcl-fpcunit`, `fcl-base`,
  `fcl-web` for `ssockets`);
- `openssl` CLI — needed only by the end-to-end tests (`openssl s_server`);
  without it those two tests are skipped;
- `openssl` + `python3` — needed only to regenerate the test fixtures
  (`make fixtures`);
- `fpcres` — the resource compiler shipped with FPC — needed only by
  `make roots`, which compiles the root snapshot into `src/tlsroots.res`.
  That file is generated and not tracked, so a fresh checkout needs
  `make roots` (or a build with `-dTLS_NO_EMBEDDED_ROOTS`) before the library
  compiles; see *Embedded root certificates* below.

## Build and test

```bash
make            # build the test runner and run the unit tests
make build      # build bin/testrunner only
make test       # run the tests
make leaktest   # same runner built with heaptrc; runs the leak checks
make example    # build bin/https_client (OpenSSL-free HTTPS client)
make check-no-openssl  # verify no library/example uses clause pulls in openssl
./build.sh      # same as "make test", with a gmkdir shim when needed
make fixtures   # regenerate certificate and DER fixtures (openssl + python3)
make roots      # regenerate src/tlsroots.res from certs/ (needs fpcres)
make clean
```

## Layout

```
src/              library units (tls.<area>.pas)
examples/         example programs (https_client.pas)
tests/            fpcunit tests, one unit per source area
tests/fixtures/   certificates, DER vectors, fixture generator (gen_certs.sh)
tests/tools/      standalone debugging programs (not part of the test run)
certs/            inputs of the embedded root snapshot (roots.pem, roots.date,
                  distrusted.txt) — see certs/README.md
tools/rootsgen/   generator: PEM snapshot -> DER table -> tlsroots.res
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
| `tls.x25519` | X25519 (Curve25519 Diffie–Hellman, RFC 7748) |
| `tls.dh` | finite-field DH (DHE), standard groups |
| `tls.prf` | TLS 1.2 PRF and key-schedule helpers (RFC 5246, RFC 7627) |
| `tls.asn1` | ASN.1/DER parser and encoder |
| `tls.x509` | X.509 v3 certificate parsing |
| `tls.certstore` | trust store and chain/signature verification; indexed lookup by canonical subject and SKI, PEM loading from a file, a stream or memory (`LoadPEM`, `LoadPEMFromMemory`, `LoadBundle`, `LoadBundleFromStream`) |
| `tls.roottable` | binary format of the embedded root table: `DecodeRootTable`, `CertStoreFromTable`/`BuildCertStore` (distrusted roots skipped), typed `ECertBundleError` |
| `tls.roots` | embedded root certificates: reads the `TLSROOTS` resource linked via `{$R}`, verifies its SHA-256, caches `EmbeddedRoots`, reports `EmbeddedRootsDate`/`EmbeddedRootsIsStale` |
| `tls.tls12` | TLS 1.2 client: record layer, handshake, AEAD record protection, alerts, high-level `TTLS12Client` |
| `tls.tls13` | TLS 1.3 client (RFC 8446): HKDF key schedule, AEAD-only record layer, 1-RTT handshake, high-level `TTLS13Client` |
| `tls.tlssocket` | FPC `sslsockets`-compatible socket handler (`TTLSSocketHandler`) and `ITLSTransport` over a socket |

The transport used by `tls.tls12` and `tls.tls13` is abstract (`ITLSTransport`
with `Read`/`Write`/`BytesAvailable`), so the protocol code never touches a
socket directly; `TTLSStreamTransport` adapts any `TStream`, and the tests use
an in-memory mock.

## Integration (drop-in replacement for OpenSSL)

A consumer that uses FPC's SSL sockets can switch to this library without
rewriting its I/O code: `tls.tlssocket` registers `TTLSSocketHandler` as the
default `TSSLSocketHandler` class, and exposes the same `Connect`, `Send`,
`Recv`, `Close`, `Shutdown` and `VerifyPeerCert` surface. Certificates are
verified by default; a trust store is configured with `TrustStorePath` (a
PEM bundle) or by assigning a `TCertStore` to `TrustStore`. On Windows, when
no trust store is configured, `Connect` falls back to the Windows system
certificate store (the Root and CA stores of the current user and the local
machine) via `LoadWindowsSystemStore`; set `DisableSystemStore := True` to
opt out of that fallback. A third option that works on every platform is the
root snapshot embedded in the executable: `H.TrustStore := EmbeddedRoots`
(see *Embedded root certificates* below), which needs neither a file nor the
system store.

```pascal
uses ssockets, tls.tlssocket;

var
  H: TTLSSocketHandler;
  S: TInetSocket;
begin
  H := TTLSSocketHandler.Create;
  H.VerifyPeerCert := True;
  H.TrustStorePath := '/etc/ssl/certs/ca-certificates.crt';
  S := TInetSocket.Create('example.com', 443, H);
  try
    S.Connect;                       // TCP + TLS 1.2 handshake
    H.Send(Request[1], Length(Request));
    N := H.Recv(Buf, SizeOf(Buf));   // decrypted application data
  finally
    S.Free;                          // also frees the handler
  end;
end;
```

The complete program is [`examples/https_client.pas`](examples/https_client.pas)
(`make example`); `make check-no-openssl` proves that neither the library nor
the example imports the FPC OpenSSL bindings. No system `libssl`/`libcrypto`
is required at build or run time.

## Embedded root certificates

The library can carry a Mozilla root snapshot inside the executable, so a
consumer needs neither a PEM bundle on disk nor the Windows certificate store
to verify a chain. Four pieces take part:

| Path | Role |
| --- | --- |
| `certs/roots.pem`, `certs/roots.date`, `certs/distrusted.txt` | committed inputs: the snapshot (a verbatim certifi `cacert.pem`), its date, and the SHA-256 fingerprints of distrusted roots; provenance and the pinned digests are in [`certs/README.md`](certs/README.md) |
| `tools/rootsgen/` | standalone generator: parses the PEM bundle with the library's own parser and writes a deterministic DER table, a `.rc` script and, through `fpcres`, `src/tlsroots.res` |
| `src/tls.roottable.pas` | the table format (`TLSROT` magic, header with snapshot date and SHA-256, fixed-size records, DER blobs) and its decoder; `BuildCertStore` turns it into a `TCertStore`, skipping records marked distrusted |
| `src/tls.roots.pas` | links the resource with `{$R tlsroots.res}` and exposes it: `EmbeddedRoots` (a cached `TCertStore`), `EmbeddedRootsDate`, `EmbeddedRootsIsStale` |

```bash
make roots      # certs/* -> build/roots/{roots.bin,tlsroots.rc} -> src/tlsroots.res
```

`make roots` is the only step that needs `fpcres` (FPC's resource compiler,
shipped with FPC; name it with `make roots FPCRES=/path/to/fpcres` when it is
not on `PATH`). It is deterministic: the committed inputs always produce the
same bytes, and `tests/test_roots.pas` pins the resulting certificate count,
snapshot date and `dataSha256`, so a refreshed snapshot must update both
together. `src/tlsroots.res` is generated and not tracked: run `make roots`
once after checkout, or build with `-dTLS_NO_EMBEDDED_ROOTS`, which compiles
the unit without the resource — every embedded-roots call then raises
`ECertBundleError` instead of silently trusting nothing, and only the tests in
`tests/test_roots.pas` (they expect a resource) fail on such a host.

Using the embedded store takes one assignment; the handler does not take
ownership of a `TrustStore` assigned this way:

```pascal
uses tls.roots, tls.tlssocket, tls.certstore;

H.TrustStore := EmbeddedRoots;   // cached, unit-owned; never free it
if EmbeddedRootsIsStale(Now, 365) then
  WriteLn('warning: root snapshot is ', EmbeddedRootsDate, ' (old)');
```

`EmbeddedRootsTableBytes` returns the raw table for tooling, and
`ReleaseEmbeddedRoots` drops the cache (tests and leak checks only).

Every read of the resource is integrity-checked first: SHA-256 is recomputed
over the table payload and compared with the digest in the header, so a
truncated or replaced resource raises `ECertBundleError` rather than decoding
into a quietly weaker trust store.

## Documentation

- [`docs/plan.md`](docs/plan.md) — goal, scope, layers, milestones, risks.
- [`docs/architecture.md`](docs/architecture.md) — unit layering and public API.
- [`docs/tasks/`](docs/tasks/) — task specs `01-bn.md` … `17-x25519.md`
  (one per work item; every task is complete).
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
