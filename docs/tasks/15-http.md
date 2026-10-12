# task 15 — OpenSSL-free HTTPS client integration

Status: done (examples/https_client.pas, `make example`, `make check-no-openssl`).

Layer 4. Dependencies: 14 (TLS socket).

## Goal

Prove that a complete HTTPS client can be built on top of the library with no
system OpenSSL: no FPC `openssl`/`opensslsockets` units, no `libssl`/
`libcrypto`. Provide a small example and make the OpenSSL-free build explicit
and verifiable.

## Files

- `examples/https_client.pas` — example program (HTTPS GET).
- `Makefile` — an `example` target.
- `README.md` — short "integration" section.

## What to implement

- An example program that:
  - opens a TCP connection and wraps it with `TTLSSocketHandler`
    (registering it as the default handler), or uses `fphttpclient` with the
    custom handler registered;
  - performs an HTTPS GET against a local TLS server and prints the response.
- Ensure neither the library nor the example references `openssl` or
  `opensslsockets`.
- Document the drop-in replacement: how a consumer replaces
  `opensslsockets` with `tls.tlssocket` and points the handler at a trust
  store.
- (Optional) fallback: if no trust store is configured, fail with a clear
  error instead of crashing.

## Acceptance criteria

- The example builds and runs against a local TLS server **without** system
  OpenSSL.
- A source check (grep) finds no `openssl`/`opensslsockets` in `src/` and
  `examples/`.
- The integration does not require changes to the TLS protocol code.
- HTTP (non-HTTPS) support, where the consumer needs it, is unaffected.

## References

- `src/tls.tlssocket.pas` (handler), `src/tls.tls12.pas` (transport),
  `tests/test_tls12_e2e.pas` (local `openssl s_server` reference setup).
