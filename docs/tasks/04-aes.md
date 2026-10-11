# task 04 — AES (CBC, GCM)

Layer 0. Dependencies: none.

## Goal

Implement AES-128/256 in CBC and GCM modes. GCM is the primary mode for
modern TLS cipher suites (AES-GCM). CBC is for legacy suites and
padding.

## File

`src/tls.aes.pas`

## What to implement

- AES core: key expansion (128/192/256), `BlockEncrypt`/`BlockDecrypt`
  (16-byte block). S-box tables, MixColumns.
- **CBC** mode: `AESCBC(key, iv, data, mode)` — with PKCS#7 padding
  (and `Unpad`).
- **GCM** mode: `AESGCM(key, iv, aad, plaintext, mode)` → ciphertext +
  16-byte tag; tag verification on decryption. Support for IV of arbitrary
  length (standard 96-bit).
- TLS-friendly API: `EncryptGCM`/`DecryptGCM` with AAD (TLS
  record header).

## Acceptance criteria

- AES-ECB/CBC/GCM match NIST SP 800-38A / SP 800-38D vectors.
- GCM: encrypt→decrypt is reversible; invalid tag is rejected.
- GCM with AAD: changing AAD breaks tag verification.
- Tests — `tests/test_aes.pas`.

## OpenSSL references

- `crypto/aes/aes_core.c` (core), `crypto/aes/aes_cbc.c` (CBC),
  `crypto/aes/aesgcm.c` (GCM), `crypto/modes/gcm128.c` (GCM mode).
