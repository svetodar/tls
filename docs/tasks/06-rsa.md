# task 06 — RSA

Layer 1. Dependencies: 01 (BN), 02 (CSPRNG), 03 (SHA-2).

## Goal

Implement RSA for client-side TLS: verification of certificate signatures
(PKCS#1 v1.5 and PSS), RSA encryption of the premaster secret (legacy RSA key
exchange). Key generation — optional (for tests).

## File

`src/tls.rsa.pas`

## What to implement

- `TRSAKey`: `N`, `E`, (opt.) `D`, `P`, `Q` — as `TBN`.
- **Public operations** (required for the client):
  - `PublicEncrypt(m)` / `PublicDecrypt` — `m^e mod N` (for RSA key exchange).
  - `VerifyPKCS1v15(signature, hash, oid)` — PKCS#1 v1.5 padding
    (DigestInfo with the algorithm OID), verification of `s^e mod N`.
  - `VerifyPSS(signature, hash)` — RSA-PSS (PKCS#1 v2.1).
- **Secret operations** (for tests/generation):
  - `Generate(bits)` — two primes (Miller–Rabin), `D = e^{-1} mod (p-1)(q-1)`.
  - `SignPKCS1v15(hash, oid)`, `SignPSS(hash)`.
- Parsing an RSA public key from DER (SubjectPublicKeyInfo) — with task 09/10.

## Acceptance criteria

- `PublicEncrypt`/`PublicDecrypt` are invertible.
- `VerifyPKCS1v15` accepts a valid signature and rejects a modified one.
- Match with known RSA test vectors (NIST / RFC 8017).
- Verification of a real certificate's signature (with task 10/11).
- Tests — `tests/test_rsa.pas`.

## OpenSSL references

- `crypto/rsa/rsa_lib.c`, `crypto/rsa/rsa_crpt.c` (encryption),
  `crypto/rsa/rsa_sign.c` (signatures, PKCS#1 v1.5/PSS), `crypto/rsa/rsa_gen.c`
  (generation), `crypto/rsa/rsa_asn1.c` (DER), `crypto/evp/e_pkey_rsa.c`.
