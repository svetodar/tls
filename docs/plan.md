# Plan — TLS client and cryptographic primitives in pure Free Pascal

## Goal

Provide a self-contained **TLS client** and every cryptographic primitive it
needs, implemented in pure Free Pascal and free of external crypto
dependencies. No OpenSSL, no `libcrypto`, no FPC `openssl`/`opensslsockets`
units: hashing, symmetric and asymmetric cryptography, certificate parsing,
chain verification and the TLS protocol itself live in this repository.

The result is an HTTPS-capable client that works in environments where OpenSSL
is absent, outdated (FPC 3.2.2's `openssl` unit does not know OpenSSL 3.x) or
undesirable.

## Scope

In scope:

1. **Primitives (layer 0):** arbitrary-precision integers (BN), a CSPRNG,
   SHA-256/384/512 + HMAC, AES (CBC, GCM), ChaCha20-Poly1305, and the TLS PRF.
2. **Asymmetric crypto (layer 1):** RSA (PKCS#1 v1.5, PSS, RSAES),
   EC (NIST P-256/P-384, ECDHE, ECDSA), X25519 (Curve25519), finite-field
   DH (DHE).
3. **Certificates (layer 2):** ASN.1/DER parser, X.509 v3 parsing, trust
   store and chain/signature/validity verification, with trust anchors taken
   from an explicit store, from a root bundle embedded in the executable or,
   on Windows, from the system certificate store.
4. **TLS (layer 3):** a TLS 1.2 client (record layer, handshake, AEAD cipher
   suites) and, as an extension, a TLS 1.3 client.
5. **Integration (layer 4):** a socket handler compatible with FPC
   `sslsockets`, plus an OpenSSL-free HTTPS example.

Out of scope: server mode, renegotiation, TLS 1.0/1.1, CBC cipher suites and
static-RSA key exchange (only ephemeral key exchange with AEAD is supported),
PKCS#12/CMS and certificate generation.

## Architecture

Layers, bottom-up; each layer depends only on the ones below it:

```
[0] bn, rand, sha2 -> hmac, aes, chacha20
[1] rsa, ec, x25519, dh            (use [0])
[2] asn1 -> x509 -> certstore -> roottable -> roots  (verification uses [1] and sha2)
[3] prf, tls12, tls13              (use everything below)
[4] socket layer and host integration (planned)
```

- **Layer 0 (primitives):** independent of each other except HMAC → SHA-2.
- **Layer 1 (asymmetric):** RSA, EC, DH; depend on BN and the CSPRNG.
- **Layer 2 (certificates):** ASN.1 → X.509 → chain verification.
- **Layer 3 (TLS):** TLS 1.2/1.3; depend on all primitives and verification.
- **Layer 4 (integration):** the TLS socket layer and its consumers.

See [`architecture.md`](architecture.md) for the unit-by-unit breakdown.

## Work items

Each work item has a specification in [`docs/tasks/`](tasks/):

| # | File | Layer | Depends on |
| --- | --- | --- | --- |
| 01 | `01-bn.md` | 0 | — |
| 02 | `02-rand.md` | 0 | — |
| 03 | `03-sha2.md` | 0 | — |
| 04 | `04-aes.md` | 0 | — |
| 05 | `05-chacha20.md` | 0 | — |
| 06 | `06-rsa.md` | 1 | 01, 02, 03 |
| 07 | `07-ec.md` | 1 | 01, 02, 03 |
| 08 | `08-dh.md` | 1 | 01, 02, 03 |
| 09 | `09-asn1.md` | 2 | — |
| 10 | `10-x509.md` | 2 | 09 |
| 11 | `11-certverify.md` | 2 | 03, 06, 07, 10 |
| 12 | `12-tls12.md` | 3 | 01–11 |
| 13 | `13-tls13.md` | 3 | 01–11, 12 |
| 14 | `14-tlssocket.md` | 4 | 12 (13) |
| 15 | `15-http.md` | 4 | 14 |
| 16 | `16-e2e.md` | 4 | 15 |
| 17 | `17-x25519.md` | 1 | 01, 02 |
| 18 | `18-windows-default-cert-store.md` | 2, 4 | 10, 11, 14 |
| 19 | `19-embedded-roots.md` | 2 | 03, 10, 11 |

## Milestones

- **A — primitives (01–05).** Layer 0 complete and covered by
  NIST/FIPS/SP 800-38A/38D and RFC test vectors. No network involved.
- **B — asymmetric crypto (06–08).** RSA, EC and DH complete, verified with
  published vectors (signatures, ECDH).
- **C — certificates (09–11).** ASN.1/X.509 parse real certificates; chain
  verification works with test CAs.
- **D — TLS 1.2 (12).** Client handshake and record layer; data can be
  exchanged with a real TLS server (`openssl s_server`, `stunnel` or a mock).
- **E — integration (14–16).** A complete HTTPS client works without system
  OpenSSL; end-to-end tests run against a local server. **Done.**
- **F — TLS 1.3 (13, 17).** Client-side TLS 1.3 with the 1-RTT handshake,
  HKDF key schedule, AEAD record layer and the X25519, secp256r1 and
  secp384r1 groups; interoperates with `openssl s_server -tls1_3` (all
  three mandatory cipher suites). **Done** (2026-10-12; X25519 added in the
  wip merge, 2026-10-16).

- **G — trust sources (18, 19).** On Windows the system `Root`/`CA` store is
  the default trust source (`crypt32.dll`, the only external call the library
  makes), and a SHA-256-checked bundle of the Mozilla roots is linked into the
  executable instead of being read from a PEM file next to it. The file-based
  `LoadPEM`/`LoadBundle` path is unchanged. **Done** (2026-10-22) on the
  Windows FPC 3.2.2 target. Two stages are tracked separately and are not part
  of this milestone's commit: the Linux verification run (`make roots` with the
  Linux `fpcres`, then `make test`/`make leaktest`) and the integration into the
  consuming `subag` project (bump `deps/tls`, make `EmbeddedRoots` the default
  trust source, drop the "put ca-bundle.pem next to the program" message) — see
  `docs/tasks/19-embedded-roots.md`, *Follow-up stages*.

## Risks

- **BN is the riskiest block.** Arbitrary precision, modular arithmetic,
  exponentiation and inversion: a mistake yields wrong signatures or keys.
  Mitigation: published test vectors; start from fixed-width arithmetic and
  generalise only afterwards.
- **Performance.** Pure Pascal without assembly is slower than OpenSSL. For
  an HTTPS client (handshake plus modest traffic) this is acceptable; AES-GCM
  and SHA-256 are the hot spots and can be optimised later.
- **Certificate verification.** Fully correct path building, CRL/OCSP and name
  constraints are complex. Mitigation: begin with a "strictly sufficient"
  check (signature, validity, SAN/CN, basic constraints); CRL/OCSP later.
- **Server compatibility.** The cipher suites that providers actually use
  must be covered (ECDHE + AES-GCM first). Mitigation: end-to-end tests
  against several real endpoints.
- **Code size.** Tens of thousands of lines. Mitigation: strict modularity;
  every unit is self-contained and tested in isolation.

## General acceptance criteria

1. `make test` passes without system OpenSSL (`openssl`/`opensslsockets` are
   not in any `uses` clause).
2. An HTTPS request to a real endpoint returns correctly and the certificate
   is verified.
3. Every primitive is covered by tests with published vectors.
4. `docs/architecture.md` and `docs/progress.md` reflect the current state.

## OpenSSL sources

The OpenSSL 3.5.9 sources used as a reference are downloaded locally into
`./OpenSSL/openssl-3.5.9/` (git-ignored). See
[`openssl-reference.md`](openssl-reference.md) for the location of each
algorithm.
