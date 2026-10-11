# task 02 — CSPRNG (random bytes)

Layer 0. Dependencies: none.

## Goal

Provide a cryptographically secure source of random bytes for nonces, ephemeral
keys, IVs, salts. Needed in all other blocks (BN.RandomBits, EC, DH,
TLS handshake).

## File

`src/tls.rand.pas`

## What to implement

- Hash-based CSPRNG (SHA-256, task 03) — e.g., HMAC-DRBG (NIST
  SP 800-90A) or a simple hash-based DRBG.
- Entropy:
  - Unix: `/dev/urandom` (primary source).
  - Windows: `CryptGenRandom`/`BCryptGenRandom` from `bcrypt.dll`
    (dynamic import via `LoadLibrary`/`GetProcAddress`).
  - Fallback: `GetTickCount64` + PID + time + (opt.) memory — only as
    a supplement, not as the primary source.
- API: `RandomBytes(out Buf: TBytes)`, `RandomQWord`, `RandomBits(n)`.
- Reentrancy/thread safety (mutex around the DRBG state).
- Reinitialization/reseeding (`Reseed`) by timer or volume.

## Acceptance criteria

- `RandomBytes` does not block and returns the requested number of bytes.
- On Unix reads `/dev/urandom`; on Windows — `BCryptGenRandom`.
- Output is unpredictable: two consecutive calls yield different values.
- Tests — `tests/test_rand.pas`: volume, absence of repeats, basic
  statistical check (uniformity over the first bits on a large sample).

## OpenSSL references

- `crypto/rand/rand_pool.c`, `crypto/rand/rand_lib.c`,
  `crypto/rand/drbg.c` (HMAC-DRBG), `crypto/rand/rand_fork.c`.
