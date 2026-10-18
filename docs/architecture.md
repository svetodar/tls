# Architecture

This document describes the unit layering and the public surface of the
library. It is the reference to update whenever a unit or a public type is
added or changed.

## Layers

The library is layered bottom-up; a layer may only depend on the layers below
it:

```
[0] bn, rand, sha2 -> hmac, aes, chacha20
[1] rsa, ec, x25519, dh            (use [0])
[2] asn1 -> x509 -> certstore      (verification uses [1] and sha2)
[3] prf, tls12, tls13              (use everything below)
[4] tls.tlssocket, examples        (use [3])
```

## Units

| Unit | Purpose | Depends on |
| --- | --- | --- |
| `tls.bn` | Arbitrary-precision non-negative integers: add/sub/mul/div, bitwise ops, modular arithmetic, ModPow, ModInverse, hex/dec/bytes conversion. `TSignedBN` supports the extended Euclidean algorithm. | — |
| `tls.rand` | CSPRNG: HMAC-DRBG (NIST SP 800-90A) over SHA-256; entropy from `/dev/urandom` or `BCryptGenRandom`. | `tls.sha2`, `tls.hmac` |
| `tls.sha2` | SHA-256/384/512 (incremental and one-shot). | — |
| `tls.hmac` | HMAC (RFC 2104) over the SHA-2 family. | `tls.sha2` |
| `tls.aes` | AES-128/192/256; CBC (with PKCS#7) and GCM. | — |
| `tls.chacha20` | ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439). | — |
| `tls.rsa` | RSA key parsing/generation; PKCS#1 v1.5 and PSS signatures; RSAES-PKCS1-v1_5. | `tls.bn`, `tls.rand`, `tls.sha2` |
| `tls.ec` | NIST P-256/P-384: point arithmetic, ECDH, ECDSA. | `tls.bn`, `tls.rand`, `tls.sha2` |
| `tls.x25519` | X25519 (Curve25519 Diffie–Hellman, RFC 7748): constant-structure Montgomery ladder over GF(2^255−19) in radix 2^51. | `tls.rand` |
| `tls.dh` | Finite-field Diffie-Hellman (DHE), standard groups. | `tls.bn`, `tls.rand` |
| `tls.asn1` | ASN.1/DER parser and encoder. | — |
| `tls.x509` | X.509 v3 certificate parsing (subject/issuer, validity, SPKI, extensions). | `tls.asn1`, `tls.bn`, `tls.ec`, `tls.rsa` |
| `tls.certstore` | Trust store, chain building and signature/validity verification; `LoadWindowsSystemStore` (Windows only) populates a store from the system `Root`/`CA` stores via `crypt32.dll` (raises `TWinCertStoreError` on failure); `TCertStore` tracks ownership (`Add` vs `AddOwnedCert`). | `tls.x509`, `tls.rsa`, `tls.ec`, `tls.sha2`, `tls.asn1` |
| `tls.prf` | TLS 1.2 PRF and key-schedule helpers (RFC 5246, RFC 7627). | `tls.hmac` |
| `tls.tls12` | TLS 1.2 client: record layer, handshake, AEAD record protection, alerts, `ITLSTransport`, high-level `TTLS12Client`. | `tls.bn`, `tls.rand`, `tls.sha2`, `tls.hmac`, `tls.aes`, `tls.chacha20`, `tls.rsa`, `tls.ec`, `tls.dh`, `tls.prf`, `tls.x509`, `tls.certstore` |
| `tls.tls13` | TLS 1.3 client (RFC 8446): HKDF key schedule, AEAD-only record layer, 1-RTT handshake, `TTLS13Client`; HelloRetryRequest/0-RTT are rejected. | `tls.tls12`, `tls.sha2`, `tls.hmac`, `tls.rand`, `tls.bn`, `tls.ec`, `tls.x25519`, `tls.rsa`, `tls.x509`, `tls.certstore`, `tls.aes`, `tls.chacha20` |
| `tls.tlssocket` | FPC `sslsockets`-compatible socket handler (`TTLSSocketHandler`) and `ITLSTransport` adapter over a connected socket (`TTLSInetSocketTransport`); on Windows, `Connect` falls back to the system certificate store unless `DisableSystemStore` is set. | `tls.tls12`, `tls.certstore`, `ssockets`, `sslsockets`, `sslbase` |

## Transport abstraction

Protocol code never talks to a socket or a file directly. `tls.tls12` and
`tls.tls13` read and write through `ITLSTransport`:

```pascal
ITLSTransport = interface
  function Read(var ABuffer; ACount: LongInt): LongInt;
  function Write(const ABuffer; ACount: LongInt): LongInt;
  function BytesAvailable: LongInt;
end;
```

- `TTLSStreamTransport` adapts any `TStream` (used by the tests with an
  in-memory mock).
- `TTLSInetSocketTransport` (in `tls.tlssocket`) adapts a connected
  `TSocketStream`; it uses `fprecv`/`fpsend` on the file descriptor so that
  it does not recurse through the socket's own `TSSLSocketHandler`.
- `TTLSSocketHandler` (in `tls.tlssocket`) is the FPC
  `sslsockets.TSSLSocketHandler`-compatible entry point used by consumers
  (and registered as the default handler).

Record and handshake limits are explicit constants (`TLSRecordMaxPayload`,
`TLSRecordMaxCiphertext`, `TLSHandshakeMaxLength`,
`TLSMaxCertificateListLen`); all lengths are validated before use.

## Certificate verification

`tls.certstore` exposes a `TCertStore` (a set of trusted CA certificates) and
`VerifyChain`, which:

1. builds the chain from the leaf up to a trusted root (by
   AuthorityKeyIdentifier/SubjectKeyIdentifier and subject/issuer names);
2. verifies each signature (RSA PKCS#1 v1.5/PSS or ECDSA) over the raw
   `TBS` bytes;
3. checks validity against the current time;
4. checks basic constraints (CA flag, path length);
5. matches the host name against SAN DNS entries (falling back to CN),
   including wildcards.

The result is a `TVerifyResult` with an `OK` flag, the chain length and a
human-readable `Reason` (used by tests and by the socket layer).

On Windows, `LoadWindowsSystemStore` (Windows only) populates a new
`TCertStore` from the system certificate store: it opens the `Root` and
`CA` stores of the current user and the local machine through the system
`crypt32.dll` API (`CertOpenStore`, `CertEnumCertificatesInStore`,
`CertGetCertificateContextData`), reads each certificate's DER bytes and
parses them with `ParseCertificate`. `crypt32.dll` is a system API, not a
crypto library, so this does not violate the no-external-crypto rule;
parsing and verification stay in pure Pascal. It raises
`TWinCertStoreError` if a store cannot be opened and `EASN1Error` if a
certificate in the store is malformed.

`TCertStore` tracks ownership: `Add` keeps a reference to a certificate
owned by the caller, while `AddOwnedCert` records a certificate the store
created itself (from parsed DER); `Destroy` and `Clear` free the owned
certificates and leave the referenced ones alone. `LoadBundle` parses the
certificates it reads, so it registers them with `AddOwnedCert`: freeing the
returned store releases them, and a malformed bundle releases both the store
and the certificates parsed so far before the error propagates.

`TTLSSocketHandler` resolves the trust store in this order: the
`TrustStore` property, then a bundle loaded from
`CertificateData.CertCA.FileName`, and, on Windows only, the system store
via `LoadWindowsSystemStore` (the handler owns and frees the store it
loads itself). `DisableSystemStore := True` disables the Windows fallback:
with no store configured, `Connect` then fails.

## TLS 1.2 client

`tls.tls12` implements the client side of RFC 5246:

- record layer (content types, version, fragmentation, 2^14 payload limit);
- handshake messages and flight assembly, with a running transcript hash;
- `ClientHello` with SNI, `supported_groups`, `signature_algorithms`,
  extended master secret and renegotiation info;
- parsing of `ServerHello`, `Certificate`, `ServerKeyExchange`,
  `ServerHelloDone`; `ClientKeyExchange` for ECDHE (P-256/P-384) and DHE;
- `ChangeCipherSpec`, `Finished`/VerifyData (constant-time comparison);
- AEAD record protection: AES-GCM (RFC 5288) and ChaCha20-Poly1305
  (RFC 7905); CBC and static-RSA suites are explicitly rejected.

## TLS 1.3 client

`tls.tls13` implements the client side of RFC 8446 on top of the transport and
record plumbing of `tls.tls12`:

- HKDF (RFC 5869) over HMAC-SHA256/384/512 and `HKDF-Expand-Label` with the
  `tls13 ` prefix; the full key schedule (early/derived/handshake/master
  secrets and the four handshake/application traffic secrets, aggregated in
  `TTLS13KeySchedule`).
- 1-RTT handshake: `ClientHello` with SNI, `supported_versions = 0x0304`,
  `supported_groups`, `signature_algorithms`, `key_share` and
  `psk_key_exchange_modes`; parsing of `ServerHello`,
  `EncryptedExtensions`, `Certificate` (TLS 1.3 format) and
  `CertificateVerify`; `Finished` with constant-time verify-data comparison.
- Key exchange `key_share` on X25519 (`tls.x25519`), P-256 and P-384
  (shared secret = X coordinate of the (EC)DHE point).
- Record layer 1.3: AEAD only (`TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`),
  `nonce = iv XOR seq_num`, AAD = the record header, inner plaintext
  `content || content_type || 0^padding`; legacy `ChangeCipherSpec` records
  are ignored.
- `CertificateVerify` verification with the RFC 8446 §4.4.3 content string
  (`0x20 * 64 || context || 0x00 || Transcript-Hash`) for
  `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384` and
  `rsa_pss_rsae_sha256`; the chain reuses `tls.certstore`.
- High-level `TTLS13Client` (`Connect`/`Send`/`Recv`/`Shutdown`/`Close`,
  `HandshakeDone`, `CipherSuite`, `CertChain`, `PendingBytes`), still
  transport-agnostic through `ITLSTransport`.

Unsupported cases fail loudly with `ETLS13Error`: HelloRetryRequest is
detected via its sentinel random and rejected, 0-RTT/early data and PSK
resumption are not supported, and unknown suites, groups or signature
schemes are refused.

## Data flow (HTTPS)

```
application HTTP client
        |  TStream / socket API
        v
tls.tlssocket  (TSSLSocketHandler-compatible handler)   [task 14]
        |  ITLSTransport
        v
tls.tls12 / tls.tls13  (record layer + handshake)       [task 12, 13]
        |
        +--> tls.certstore  (verify server chain)       [task 11]
        +--> tls.prf / HKDF, tls.aes / tls.chacha20 (keys, AEAD)
        +--> tls.ec / tls.rsa / tls.dh (key exchange)

tls.tls13  (HKDF + 1-RTT handshake)                    [task 13]
        |  reuses tls.tls12's ITLSTransport, record/handshake primitives
        |  and certificate chain
        +--> tls.x25519 / tls.ec (key_share)
        +--> tls.aes / tls.chacha20 (AEAD record protection)
```

The `examples/https_client.pas` program exercises the TLS 1.2 path end to end
(via `tls.tlssocket`) and `make check-no-openssl` fails if any library or
example `uses` clause pulls in the FPC OpenSSL bindings. `tls.tls13` is not yet
wired into `tls.tlssocket`; it is driven directly through `ITLSTransport` by
`tests/test_tls13_e2e.pas` and `tests/tools/tls13_client.pas`.

## Conventions

- Units are named `tls.<area>.pas`; the `tls.` prefix avoids collisions with
  RTL/FCL units.
- Errors are typed (`EBNError`, `EASN1Error`, `EX509Error`, `ETLS12Error`,
  `ETLS13Error`, …) and raised on malformed input rather than returning
  partial data.
- Secret-dependent comparisons are constant-time; secret material is never
  logged.
- Randomness for keys, nonces and IVs comes from `tls.rand` only.
