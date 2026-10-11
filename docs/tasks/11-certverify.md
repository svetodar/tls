# task 11 — Chain verification + trust store

Layer 2. Dependencies: 03 (SHA-2), 06 (RSA), 07 (EC), 10 (X.509).

## Goal

Verify the server certificate chain: from the server certificate to a
trusted root. Validate signatures, validity periods, names, basic constraints.
Trusted CA store.

## File

`src/tls.certstore.pas` (+ verification logic, can be in `tls.x509.pas`)

## What to implement

- **Trust store** (`TCertStore`):
  - Load CA certificates from a PEM file (e.g., the system
    `ca-certificates.crt` / bundle) and/or a built-in list.
  - Look up CA by Subject/AuthorityKeyIdentifier.
- **Verification** (`VerifyChain(leaf, intermediates, store, host)`):
  1. Build the chain: leaf → … → root (by AKI/SKI/Subject=Issuer).
  2. Verify each signature (RSA/ECDSA) over `TBS` (task 06/07).
  3. Check validity periods (NotBefore/NotAfter) against the current time.
  4. Check basic constraints (CA flag on issuers, pathlen).
  5. Check the name: host ∈ SAN (DNS) or CN (fallback); support
     wildcard (`*.example.com`).
  6. (Opt.) key usage / extended key usage (serverAuth).
  7. (Opt.) CRL/OCSP — later, does not block the basic variant.
- Result: `True`/`False` + human-readable reason (for errors).

## Acceptance criteria

- A valid chain to a trusted root → `True`.
- A substituted/expired/unsigned certificate → `False` with a reason.
- Name mismatch (host not in SAN) → `False`.
- Works on real chains (e.g., a public website's certificate).
- Tests — `tests/test_certverify.pas` (on test CAs + real ones).

## OpenSSL references

- `crypto/x509/x509_vfy.c` (verify chain), `crypto/x509/x509_cmp.c`
  (name comparison), `crypto/x509/x509_lu.c`, `crypto/x509/x509_att.c`,
  `crypto/x509/v3_purp.c` (extensions), `crypto/x509/x509_spki.c`
  (public keys).
