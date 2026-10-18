# task 18 — Windows default certificate store

Status: done (src/tls.certstore.pas, src/tls.tlssocket.pas, examples/https_client.pas, tests/tools/tls13_client.pas, tests/test_certverify.pas, tests/test_tlssocket.pas).

Layer 2 (`tls.certstore`) and layer 4 (`tls.tlssocket`). Dependencies: 10
(X.509), 11 (chain verification / trust store), 14 (TLS socket handler).

## Goal

On Windows, use the certificates installed in the system certificate store
by default, so that a consumer does not have to point the library at a PEM
bundle. The library already verifies chains against a `TCertStore`; this
task adds a way to populate that store from the Windows system store
(`Root` and `CA`) via the system `crypt32.dll` API, and makes the socket
handler fall back to it automatically on Windows when no store is
configured.

`crypt32.dll` is a system API (not a crypto library), so using it does not
violate the "no external crypto dependencies" rule. It is the only external
call the library makes on Windows; everything else (parsing, verification)
stays in pure Pascal.

## Files

- `src/tls.certstore.pas` — new `LoadWindowsSystemStore` + typed error +
  owned-certificate support in `TCertStore`.
- `src/tls.tlssocket.pas` — default to the Windows store on Windows.
- `examples/https_client.pas`, `tests/tools/tls13_client.pas` — use the
  Windows store on Windows.
- `tests/test_certverify.pas`, `tests/test_tlssocket.pas` — tests.

## What to implement

### `tls.certstore.pas`

- `TWinCertStoreError` — a typed error (derived from `Exception`) raised when
  the Windows store cannot be opened or enumerated.
- `crypt32.dll` prototypes (Windows only, guarded by `{$ifdef windows}`):
  `CertOpenStore`, `CertCloseStore`, `CertEnumCertificatesInStore`,
  `CertGetCertificateContextData`.
- `TCertStore` gains ownership support:
  - an `ownedCerts` list of certificates the store created itself (from
    parsed DER) and must free;
  - `AddOwnedCert(const Cert: TX509Cert)` — add a certificate the store now
    owns;
  - `Destroy` frees every certificate in `ownedCerts` (in addition to the
    existing non-owned references, which it does not free).
- `LoadWindowsSystemStore: TCertStore` — returns a new `TCertStore` populated
  from the Windows system store:
  - opens the `Root` and `CA` stores (`CertOpenStore` with
    `CERT_SYSTEM_STORE_CURRENT_USER`/`LOCAL_MACHINE` as appropriate);
  - enumerates each certificate (`CertEnumCertificatesInStore`);
  - reads each certificate's DER bytes (`CertGetCertificateContextData`);
  - parses the DER with `ParseCertificate` (task 10) and adds the result via
    `AddOwnedCert`;
  - frees every context and closes both stores before returning;
  - raises `TWinCertStoreError` if a store cannot be opened.

### `tls.tlssocket.pas`

- `TTLSSocketHandler` gains `DisableSystemStore: Boolean = False`.
- In `Connect`, on Windows, when no trust store is configured
  (`FTrustStore = nil`) and `DisableSystemStore` is `False`, call
  `LoadWindowsSystemStore` and use the result as the trust store (the handler
  owns and frees it).
- Update the `Connect` doc comment to describe the Windows default-store
  behaviour and the `DisableSystemStore` opt-out.

### Consumers

- `examples/https_client.pas` and `tests/tools/tls13_client.pas`: on Windows,
  when no CA file is given, use `LoadWindowsSystemStore` instead of only the
  Unix PEM bundles.

## Acceptance criteria

- On Windows, `LoadWindowsSystemStore` returns a non-empty store containing
  the system root CAs (a test asserts `Count > 0` and that a well-known root
  is present; the test is skipped when not on Windows).
- On Windows, `TTLSSocketHandler.Connect` with no explicit store verifies
  against the system store (a test connects to a real server and succeeds;
  skipped when not on Windows or when the network is unavailable).
- `DisableSystemStore := True` restores the old behaviour: with no store,
  `Connect` fails (the existing `TestNoTrustStoreFails` is adapted to set
  `DisableSystemStore := True` so it still asserts the strict failure).
- `TCertStore.Destroy` frees owned certificates (no leak); non-owned
  references are still not freed by the store.
- The system-store leak check (`TestWinSystemStoreNoLeak`) passes under
  `make leaktest`, which builds the runner with heap tracing; the normal
  `make test` run stays untraced.
- `make test` passes; `make check-no-openssl` still reports no OpenSSL unit
  references (`crypt32.dll` is not an OpenSSL unit).

## References

- Windows `crypt32.dll`: `CertOpenStore`, `CertCloseStore`,
  `CertEnumCertificatesInStore`, `CertGetCertificateContextData`
  (Microsoft docs, "Certificate Store Functions").
- `docs/tasks/10-x509.md` (`ParseCertificate`), `docs/tasks/11-certverify.md`
  (`TCertStore`, `VerifyChain`), `docs/tasks/14-tlssocket.md`
  (`TTLSSocketHandler`).
