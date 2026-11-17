# task 20 — the Russian Trusted Root CA as an extra anchor

Status: implemented; the acceptance run (`make check-roots`, `make test`,
`make check-no-openssl`) is recorded in `docs/progress.md` when the change
lands. Files: `tools/rootsgen/rootsgen.lpr`, `Makefile`, `.gitignore`,
`.gitattributes`, `certs/extra/russian_trusted_root_ca.pem` (new),
`src/tlsroots.res`, `tests/test_roots.pas`, `certs/README.md`, `README.md`,
`docs/architecture.md`, `docs/progress.md`, `docs/plan.md`.

No new unit; the change is confined to the layer-2 root bundle and to the
tooling that builds it. Dependencies: 19 (embedded roots, `tools/rootsgen`,
table format, `tls.roots`), 10 (`ParseCertificate`), 11 (`VerifyChain`).

## Goal

Some trust anchors a client needs are not in the Mozilla/NSS snapshot that
`certs/roots.pem` carries — the Russian Trusted Root CA published by the
Ministry of Digital Development and Communications is one of them. Adding such
a root must not mean hand-editing the certifi snapshot (it has to stay a
verbatim upstream copy), and it must not mean a second bundle next to the
first: the embedded table stays the single trust source of the library.

So the generator grows one repeatable option, `--extra FILE`, that merges
additional PEM roots into the same table as the snapshot. `make roots` passes
every `certs/extra/*.pem` through it, the resource is regenerated and
committed as in task 19, and `EmbeddedRoots` therefore contains the Russian
Trusted Root CA without any change to `tls.roots`. The extra files are
checked exactly like the snapshot records (base64, DER length, X.509 parse,
distrust bits) and are deduplicated by DER, so one trust anchor can never end
up with two table records.

The certificate itself is public data; nothing secret is committed.

## Files

- `certs/extra/russian_trusted_root_ca.pem` — new: comment header plus the
  published PEM of the self-signed root, verbatim.
- `tools/rootsgen/rootsgen.lpr` — repeatable `--extra PATH`, merge with
  duplicate detection, help text.
- `Makefile` — `certs/extra/*.pem` become generator inputs and are turned
  into `--extra` arguments for `roots` and `check-roots`.
- `.gitignore`, `.gitattributes` — the extra PEMs are tracked and byte-exact.
- `src/tlsroots.res` — regenerated (132 757 → 134 269 bytes).
- `tests/test_roots.pas` — new pinned values and one new case.
- `certs/README.md`, `README.md`, `docs/architecture.md`, `docs/progress.md`,
  `docs/plan.md` — the extra inputs, the option and the new pins.

## What to implement

### `certs/extra/russian_trusted_root_ca.pem`

- Directory `certs/extra/` holds roots that are *not* part of the certifi
  snapshot. One file per anchor; the file name describes the certificate.
- The file starts with a `#` comment header recording what a reviewer needs:
  subject (`C=RU, O=The Ministry of Digital Development and Communications,
  CN=Russian Trusted Root CA`), key (`RSA 3072`), validity
  (`2022-03-01 .. 2032-02-27`), the source URL
  (`https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt`), the
  retrieval date (`2026-11-17`) and the SHA-256 fingerprint of the DER
  (`d26d2d0231b7c39f92cc738512ba54103519e4405d68b5bd703e9788ca8ecf31`).
- Below the header the PEM block is the published file byte for byte; the
  header is the only addition. `tools/rootsgen` ignores `#` lines, as it
  already does for certifi's per-certificate comments.
- Only the self-signed root is shipped. The vendor also publishes a separate
  "Russian Trusted Sub CA" that chains to this root; an intermediate is not a
  trust anchor, it arrives with the peer's `certificate_list`, and storing it
  here would add a second record for bytes the handshake already delivers.
  The header says so, so the decision is not lost on the next reader.

### `tools/rootsgen/rootsgen.lpr`

- `--extra PATH`: one more PEM root file, **repeatable**, merged after the
  main snapshot in command-line order. Paths are collected during argument
  parsing into a dynamic array (`TPathList`/`TExtraPaths`), so the tool keeps
  no allocation that would have to be freed on every exit path.
- `LoadAllEntries(APEMPath, AExtraPaths, ADistrusted)` replaces the direct
  `LoadEntries(APEMPath, …)` call in the main program: it loads the snapshot,
  then every extra file through the *same* `LoadEntries`, so the extra roots
  get identical validation and identical trust bits. An extra root listed in
  `certs/distrusted.txt` is stored as distrusted, never as a usable anchor,
  wherever it came from.
- Track the origin file of every entry in a parallel array, so a failure can
  name both sides.
- Duplicate detection compares the whole DER (`SameBytes` /
  `FindEntryByDer`), not a digest: a fingerprint collision must not make two
  different certificates look like one. A certificate that is already in the
  table — repeated in the snapshot, twice inside one extra file, or reached
  twice through `--extra` — raises `ERootsGenError` naming the extra file and
  the file the earlier copy came from. Silently skipping would make the record
  count depend on the inputs in a way nothing reports, and two records for one
  anchor would let chain building pick whichever the table order puts first.
- A missing, unreadable, certificate-less or broken extra file raises with its
  path: an unusable input must never yield a table that silently lacks a root.
- `--help` documents the option, its repetition and the dedup rule.
- Output stays deterministic: the merge only adds records, and the existing
  sort by `subjectHash` then DER digest fixes the final order.

### `Makefile`

- `ROOTS_EXTRA := $(wildcard certs/extra/*.pem)`; it joins `ROOTS_INPUTS`, so
  adding, removing or editing an extra PEM makes `src/tlsroots.res` look out
  of date in both `roots` and `check-roots`.
- `ROOTS_EXTRA_ARGS := $(foreach pem,$(ROOTS_EXTRA),--extra $(pem))` turns the
  sorted `wildcard` list into one argument pair per file and is spliced into
  the two generator command lines. With no PEM in the directory the variable
  is empty and the command line is exactly the one of task 19.
- Comment in place: the directory may be empty or absent, but every PEM in it
  must trigger a regeneration.

### `.gitignore` / `.gitattributes`

- `.gitignore`: `!certs/extra/*.pem` re-includes the extra inputs after the
  repository-wide `*.pem` rule (the same treatment `certs/roots.pem` has).
- `.gitattributes`: `certs/extra/*.pem -text`. They are verbatim upstream
  downloads and the generator reads their DER, whose SHA-256 the tests pin; a
  line-ending rewrite on checkout would break the build.

### `src/tlsroots.res`

Regenerated from the committed inputs and committed with them, as decided in
task 19 (*Revision: the resource is committed*):

| field | task 19 | task 20 |
| --- | --- | --- |
| `count` | 120 | 121 |
| DER payload | 128 549 bytes | 130 027 bytes |
| table (`build/roots/roots.bin`) | 132 677 bytes | 134 189 bytes |
| `dataSha256` | `391521bf…aad0dec` | `4fc1f93f8d8e384eeff60a3850e3b687f04922b8fa9330097b72bd157081eeb5` |
| `src/tlsroots.res` | 132 757 bytes | 134 269 bytes |
| SHA-256 of the resource | `61b206c9…b6e1a9aa` | `a6c517ca25a8740b8d01f676f39c87d972b214d1eae5f73ffdf40c1fcb8e0242` |

The snapshot date (20748 = 2026-10-22) is unchanged: the extra root is not a
snapshot refresh, and `EmbeddedRootsDate`/`EmbeddedRootsIsStale` keep
reporting the age of the Mozilla set.

### Tests

`tests/test_roots.pas` (`TRootsTests`, now 19 cases):

- Pinned values updated together with the resource: `EXPECTED_RECORD_COUNT =
  121`, `EXPECTED_PAYLOAD_SHA256 =
  '4fc1f93f8d8e384eeff60a3850e3b687f04922b8fa9330097b72bd157081eeb5'`;
  snapshot date/year/month/day unchanged. The existing header, layout and
  self-check cases therefore also cover the merged table.
- New constants for the certificate as its publisher declares it, none of
  which depends on this build: subject `C=RU`,
  `O=The Ministry of Digital Development and Communications`,
  `CN=Russian Trusted Root CA`; SHA-256 of the DER
  `d26d2d02…ca8ecf31`; SKI `e1d181e5ce5a5f04aad2e9b69d66b1c5faac2c87`;
  `CA:TRUE` with `pathlen:4`; `notAfter` `2032-02-27 21:04:15` UTC. `OID_COUNTRY`
  (`2.5.4.6`) joins the name OIDs already used.
- `CountBySubject(ATable, ACN, AOrg, ACountry)` parses every DER blob and
  compares all three attributes, so a look-alike issuer name (another country
  or organisation) is not counted.
- `TestRussianTrustedRootCaIsPresent`: the root appears in the shipped table
  **exactly once** by subject and exactly once by published fingerprint (the
  merge must neither duplicate it nor accept a different certificate with the
  same name); the embedded store resolves it by CN and keeps subject, SKI,
  `BasicConstraints` and `notAfter` as published. A silent loss of the
  `--extra` input, a duplicated record or a replaced certificate each fail
  this case with its own message.

### Docs

- `certs/README.md`: a `certs/extra/` section (purpose, provenance of the
  Russian root, "one anchor per file, no intermediates", why it is not in
  `roots.pem`) and the refreshed fingerprint table above; the refresh
  procedure gains the step "drop a new anchor into `certs/extra/` and run
  `make roots`".
- `README.md`: `certs/extra/` in the layout, `tools/rootsgen --extra` and
  `make roots` description, the test count, and the note that the extra roots
  end up in `EmbeddedRoots` like the snapshot ones.
- `docs/architecture.md`: the bundle's sources are `certs/roots.pem` plus
  `certs/extra/*.pem` merged by `--extra`; `tls.roots` and the table format are
  untouched.
- `docs/progress.md`: new task-20 section with the pins (121 roots, 19 root
  test cases), the merge/dedup rules and the acceptance run.
- `docs/plan.md`: line 20 in the task table and the mention in milestone G.

## Acceptance criteria

- `make check-roots` regenerates the resource from `certs/` (including
  `certs/extra/*.pem`) and reports it byte-identical to the committed
  `src/tlsroots.res`; `make roots` run twice produces the same bytes.
- `EmbeddedRoots.Count = 121` and the payload digest equals the pinned
  `4fc1f93f…081eeb5`; `EmbeddedRootsDate` still reports 2026-10-22.
- The Russian Trusted Root CA is in `EmbeddedRoots` exactly once, with the
  published subject, SHA-256 fingerprint, SKI, `CA:TRUE` / `pathlen:4` and
  `notAfter`; the existing ISRG Root X1 case and the fixture-chain cases still
  pass, so the merge did not disturb the snapshot records.
- `--extra` is repeatable and order-preserving; a duplicate certificate, a
  missing file and a file without a certificate block each abort the
  generation with a message that names the file, and no table is written.
- An extra root listed in `certs/distrusted.txt` is stored distrusted.
- `make test` passes (386 tests, 0 errors, 0 failures) and
  `make check-no-openssl` still finds no OpenSSL unit reference.
- Building the library still needs neither `fpcres` nor `make roots`: the
  resource is committed, and a directory without extra PEMs behaves exactly as
  in task 19.
- No new external dependency: `tools/rootsgen` stays pure Pascal and uses only
  the existing library units.

## Out of scope

- Shipping the Russian Trusted Sub CA or any other intermediate CA as an
  anchor. Intermediates travel with the peer's `certificate_list`; only a
  self-signed anchor belongs in `certs/extra/`.
- Trust *policy*: the library keeps one flat anchor table and has no notion of
  "only this jurisdiction", of per-host allow-lists or of distrusting a root by
  country. A consumer that wants a narrower policy builds its own `TCertStore`
  (that is what the explicit `TrustStore` is for).
- Automatic retrieval of extra roots or of the vendor's published files; a
  maintainer downloads, records the provenance and commits the PEM, exactly as
  with the snapshot.
- Changing the table format, `tls.roottable`, `tls.roots` or the resource
  name: task 20 is an input and tooling change only, so the embedded table
  still decodes with the task-19 reader.
- Rotating the extra root when the vendor re-issues it — that is a snapshot
  refresh like any other and updates `certs/extra/`, the resource and the
  pinned constants together.

## References

- `docs/tasks/19-embedded-roots.md` — the generator, the DER-table format,
  the committed resource, the pinned constants and `make check-roots`.
- Publisher of the certificate:
  <https://gu-st.ru/content/lending/russian_trusted_root_ca_pem.crt>
  (retrieved 2026-11-17); subject and validity as printed in the committed
  file's header.
- RFC 5280 §4.2.1.9 (BasicConstraints, `pathLenConstraint`), §4.2.1.2
  (SubjectKeyIdentifier), §6 (certification path validation).
- `docs/tasks/10-x509.md` (`ParseCertificate`, SKI, BasicConstraints),
  `docs/tasks/11-certverify.md` (`TCertStore`, `VerifyChain`).
