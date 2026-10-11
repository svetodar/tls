# Architecture

This document describes the unit layering and the public surface of the
library. It is the reference to update whenever a unit or a public type is
added or changed.

## Layers

The library is layered bottom-up; a layer may only depend on the layers below
it:

```
[0] bn, rand, sha2 -> hmac, aes, chacha20
[1] rsa, ec, dh                    (use [0])
[2] asn1 -> x509 -> certstore      (verification uses [1] and sha2)
[3] prf, tls12 (-> tls13 planned)  (use everything below)
[4] socket layer and host integration (planned)
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
| `tls.dh` | Finite-field Diffie-Hellman (DHE), standard groups. | `tls.bn`, `tls.rand` |
| `tls.asn1` | ASN.1/DER parser and encoder. | — |
| `tls.x509` | X.509 v3 certificate parsing (subject/issuer, validity, SPKI, extensions). | `tls.asn1`, `tls.bn`, `tls.ec`, `tls.rsa` |
| `tls.certstore` | Trust store, chain building and signature/validity verification. | `tls.x509`, `tls.rsa`, `tls.ec`, `tls.sha2`, `tls.asn1` |
| `tls.prf` | TLS 1.2 PRF and key-schedule helpers (RFC 5246, RFC 7627). | `tls.hmac` |
| `tls.tls12` | TLS 1.2 client: record layer, handshake, AEAD record protection, alerts, `ITLSTransport`. | `tls.bn`, `tls.rand`, `tls.sha2`, `tls.hmac`, `tls.aes`, `tls.chacha20`, `tls.rsa`, `tls.ec`, `tls.dh`, `tls.prf`, `tls.x509`, `tls.certstore` |

Planned: `tls.tls13` (TLS 1.3 client) and `tls.tlssocket` (FPC
`sslsockets`-compatible socket handler).

## Transport abstraction

Protocol code never talks to a socket or a file directly. `tls.tls12` reads and
writes through `ITLSTransport`:

```pascal
ITLSTransport = interface
  function Read(var ABuffer; ACount: LongInt): LongInt;
  function Write(const ABuffer; ACount: LongInt): LongInt;
  function BytesAvailable: LongInt;
end;
```

- `TTLSStreamTransport` adapts any `TStream` (used by the tests with an
  in-memory mock).
- The planned `TInetSocket`-based transport and the socket handler (task 14)
  implement the same interface, so protocol code stays testable in memory.

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

## Data flow (HTTPS, planned)

```
application HTTP client
        |  TStream / socket API
        v
tls.tlssocket  (TSSLSocketHandler-compatible handler)   [task 14]
        |  ITLSTransport
        v
tls.tls12  (record layer + handshake)                   [task 12]
        |
        +--> tls.certstore  (verify server chain)       [task 11]
        +--> tls.prf, tls.aes / tls.chacha20 (keys, AEAD)
        +--> tls.ec / tls.rsa / tls.dh (key exchange)
```

## Conventions

- Units are named `tls.<area>.pas`; the `tls.` prefix avoids collisions with
  RTL/FCL units.
- Errors are typed (`EBNError`, `EASN1Error`, `EX509Error`, `ETLS12Error`, …)
  and raised on malformed input rather than returning partial data.
- Secret-dependent comparisons are constant-time; secret material is never
  logged.
- Randomness for keys, nonces and IVs comes from `tls.rand` only.
