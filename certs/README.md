# `certs/` — inputs of the embedded root snapshot

Committed *inputs* of `tools/rootsgen`. The intermediate artefacts
(`build/roots/`, `certs/roots.bin`) are not tracked; run `make roots` to
rebuild them. The compiled resource `src/tlsroots.res` is tracked as well:
`tls.roots` links it with `{$R}`, which the compiler resolves next to the unit,
so the file has to travel with the sources. Certificates are public data:
nothing secret is committed here.

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
- `extra/*.pem` — trust anchors that are *not* part of the certifi snapshot,
  one self-signed root per file (see below). `make roots` passes each of them
  to the generator as `--extra FILE` and they land in the same table.

## Provenance of the first snapshot

| field | value |
| --- | --- |
| upstream | certifi `cacert.pem` (Mozilla Root Store) |
| release tag | `2026.10.19` |
| URL | <https://raw.githubusercontent.com/certifi/python-certifi/2026.10.19/certifi/cacert.pem> |
| retrieved | 2026-10-22 |
| snapshot date (`roots.date`) | 2026-10-22 |
| certificates in `roots.pem` | 120 |
| size | 238 856 bytes |
| SHA-256 of `roots.pem` | `50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785` |

The bytes are unchanged from upstream; only the file name differs. To
re-check on a POSIX host: `sha256sum certs/roots.pem`, on Windows:
`certutil -hashfile certs\roots.pem SHA256`.

The table built from these inputs is larger than the snapshot: the extra roots
in `certs/extra/` are merged in, so `count` is 121 rather than 120.

## Extra roots (`certs/extra/`)

`certs/extra/*.pem` hold anchors that are not in the Mozilla set. `make roots`
turns every PEM in the directory into one `--extra FILE` argument for
`tools/rootsgen`, which validates it exactly like a snapshot record (base64,
DER length, X.509 parse, distrust bits) and merges it into the same table. The
table format, `src/tlsroots.res` and `EmbeddedRoots` stay as in task 19, so a
consumer sees one flat trust store. Duplicate detection compares the whole
DER, not a digest: a certificate already in the table — repeated in the
snapshot, twice in one extra file, or reached twice through `--extra` —
aborts the generation instead of producing two records for one anchor.

Rules for this directory:

- one *trust anchor* per file, self-signed, with a file name that describes
  the certificate;
- a `#` comment header records what a reviewer needs — subject, key,
  validity, source URL, retrieval date and SHA-256 of the DER. The generator
  ignores `#` lines, as it already does for certifi's comments;
- no intermediates: a subordinate CA travels with the peer's
  `certificate_list` and is not an anchor of its own;
- below the header the PEM block is the published download byte for byte; the
  file is tracked (`!certs/extra/*.pem` in `.gitignore`) and checked out
  unchanged (`-text` in `.gitattributes`).

The only entry so far is `russian_trusted_root_ca.pem`:

| field | value |
| --- | --- |
| subject | `C=RU, O=The Ministry of Digital Development and Communications, CN=Russian Trusted Root CA` |
| key | RSA 3072 |
| validity | 2022-03-01 .. 2032-02-27 |
| source | <https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt> |
| retrieved | 2026-11-17 |
| SHA-256 of the DER | `d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31` |

It lives here rather than in `roots.pem` because that file has to stay a
byte-identical copy of the certifi release: editing it would invalidate the
recorded SHA-256 and the next wholesale refresh would silently drop the
addition. The snapshot date (`roots.date`, `EmbeddedRootsDate`) keeps
describing the Mozilla set, so adding an extra root does not make the snapshot
look fresher.

## Fingerprint of the generated table

`make roots` is deterministic: the committed inputs above — `roots.pem`,
`roots.date`, `distrusted.txt` and every `certs/extra/*.pem` — always produce
the bytes below. These are the values pinned by `tests/test_roots.pas`, so a
test failure after a refresh means the constants and this table need updating
together.

| field | value |
| --- | --- |
| certificates in the table (`count`) | 121 (120 from `roots.pem`, 1 extra) |
| snapshot date, Unix days | 20748 (2026-10-22) |
| DER payload | 130 027 bytes |
| table size (`build/roots/roots.bin`) | 134 189 bytes |
| table `dataSha256` | `4fc1f93f8d8e384eeff60a3850e3b687f04922b8fa9330097b72bd157081eeb5` |
| SHA-256 of `src/tlsroots.res` | `a6c517ca25a8740b8d01f676f39c87d972b214d1eae5f73ffdf40c1fcb8e0242` |

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
4. For an anchor outside the snapshot, drop one PEM into `certs/extra/` with
   the comment header described above (and delete the file when the anchor is
   withdrawn); the snapshot files stay untouched.
5. Run `make roots` and update the pinned `count` / snapshot date /
   `dataSha256` constants in `tests/test_roots.pas` together with the
   README tables above.

`certs/roots.pem` and `certs/extra/*.pem` are exempted from the
repository-wide `*.pem` rule in `.gitignore`; they are the source of truth for
the embedded table and must stay tracked.
