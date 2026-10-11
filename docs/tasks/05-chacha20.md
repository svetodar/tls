# task 05 — ChaCha20 + Poly1305

Layer 0. Dependencies: none.

## Goal

Implement AEAD ChaCha20-Poly1305 (RFC 8439) — for TLS 1.3 cipher suite
`TLS_CHACHA20_POLY1305_SHA256` and as a fallback AEAD.

## File

`src/tls.chacha20.pas`

## What to implement

- **ChaCha20** (RFC 8439): 64-byte block, key 32, counter 4, nonce 12.
  `ChaCha20(key, counter, nonce, data)` — stream (encrypt == decrypt).
- **Poly1305** (RFC 8439): one-time key 32 bytes, MAC 16 bytes.
  Exact arithmetic mod (2^130 − 5).
- **ChaCha20-Poly1305 AEAD** (RFC 8439 §2.8):
  `Encrypt(key, nonce, aad, plaintext)` → ciphertext + tag;
  `Decrypt(...)` with tag verification.
  Poly1305 key = first 32 bytes of the ChaCha20 block with counter=0.

## Acceptance criteria

- ChaCha20 and Poly1305 match the RFC 8439 test vectors.
- AEAD encrypt→decrypt is reversible; invalid tag/adata is rejected.
- Tests — `tests/test_chacha.pas`.

## OpenSSL references

- `crypto/chacha/chacha_enc.c` (ChaCha20), `crypto/poly1305/poly1305.c`
  (Poly1305), `crypto/evp/e_chacha20_poly1305.c` (AEAD wrapper).
