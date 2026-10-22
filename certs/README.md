# `certs/` — inputs of the embedded root snapshot

Committed *inputs* of `tools/rootsgen`. The generated artefacts
(`build/roots/`, `src/tlsroots.res`, `certs/roots.bin`) are not tracked; run
`make roots` to rebuild them. Certificates are public data: nothing secret is
committed here.

## Files

- `roots.pem` — verbatim copy of certifi's `cacert.pem` (the Mozilla root
  program as curated for Python). Keep it byte-identical to upstream, so the
  recorded SHA-256 below can be re-checked after a refresh. `tools/rootsgen`
  reads every `-----BEGIN CERTIFICATE-----` block and ignores the
  `# Issuer:` / `# SHA256 Fingerprint:` comment lines that certifi puts in
  front of each block.
- `roots.date` — one `YYYY-MM-DD` line, the snapshot date stored in the table
  header and used by `EmbeddedRootsIsStale`.
- `distrusted.txt` — SHA-256 fingerprints of roots marked distrusted in
  Mozilla `certdata.txt` (comments allowed, may be empty). Currently empty on
  purpose: see the comment inside the file.

## Provenance of the first snapshot

| field | value |
| --- | --- |
| upstream | certifi `cacert.pem` (Mozilla Root Store) |
| release tag | `2026.10.19` |
| URL | <https://raw.githubusercontent.com/certifi/python-certifi/2026.10.19/certifi/cacert.pem> |
| retrieved | 2026-10-22 |
| snapshot date (`roots.date`) | 2026-10-22 |
| certificates | 120 |
| size | 238 856 bytes |
| SHA-256 of `roots.pem` | `50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785` |

The bytes are unchanged from upstream; only the file name differs. To
re-check on a POSIX host: `sha256sum certs/roots.pem`, on Windows:
`certutil -hashfile certs\roots.pem SHA256`.

## Fingerprint of the generated table

`make roots` is deterministic: the committed inputs above always produce the
bytes below. These are the values pinned by `tests/test_roots.pas`, so a test
failure after a refresh means the constants and this table need updating
together.

| field | value |
| --- | --- |
| certificates in the table (`count`) | 120 |
| snapshot date, Unix days | 20748 (2026-10-22) |
| DER payload | 128 549 bytes |
| table size (`build/roots/roots.bin`) | 132 677 bytes |
| table `dataSha256` | `391521bf207b7891ed90e9a967db17413c728eb2db1bcd0b291978928aad0dec` |
| SHA-256 of `src/tlsroots.res` | `61b206c96179e6e2e6a25da001010a60cf433c3a3de4b51d21cd7af1b6e1a9aa` |

`dataSha256` covers everything after the 48-byte table header (records plus DER
payload), so it is the same value the library re-checks when it reads the
resource.

## Refreshing the snapshot

1. Download a newer certifi release tag (or `certdata.txt`) and replace
   `roots.pem` wholesale — do not hand-edit individual certificates.
2. Put the retrieval date into `roots.date`.
3. Add the fingerprints of roots whose trust bits are gone / that are marked
   distrusted to `distrusted.txt` (keep their certificates in `roots.pem` so
   the table records the distrust instead of silently dropping them).
4. Run `make roots` and update the pinned `count` / snapshot date /
   `dataSha256` constants in `tests/test_roots.pas` together with the
   README table above.

`certs/roots.pem` is exempted from the repository-wide `*.pem` rule in
`.gitignore`; it is the source of truth for the embedded table and must stay
tracked.
