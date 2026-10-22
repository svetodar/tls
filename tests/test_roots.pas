{ SPDX-License-Identifier: Apache-2.0 }
unit test_roots;

{ Tests for the embedded root certificates (tls.roots).

  These cases inspect the artefact the library actually ships: the
  RT_RCDATA resource compiled into the executable by `make roots`, not a
  hand-made table. EmbeddedRootsTableBytes must return a non-empty table whose
  header — magic, version, record count, snapshot date and payload SHA-256 —
  equals the constants pinned below.

  The pinned values come from the generator run that produced
  src/tlsroots.res (snapshot certs/roots.pem, certifi 2026.10.19); they are
  refreshed together with the snapshot, so a changed snapshot must change
  them in the same commit.

  The digest is checked three independent ways: against the pinned reference,
  against a SHA-256 recomputed here with tls.sha2 from the resource payload,
  and against the copy the header stores. The record area is also walked
  straight from the raw bytes, without DecodeRootTable, so a decoder bug
  cannot make the layout check pass.

  The next three cases leave the artefact behind and look at real chains.
  ISRG Root X1, the Let's Encrypt anchor, must be in the snapshot exactly
  once, must match the SHA-256 fingerprint and SubjectKeyIdentifier published
  for that certificate, must be findable through both indexes of the trust
  store, and must verify as a one-certificate chain ("root -> root") at the
  snapshot date. The fixture chain (tests/fixtures/leaf_rsa.der ->
  ca_rsa.der) is then anchored in a store built from the snapshot: without the
  fixture CA the leaf must be rejected as unknown, and once that CA is added
  the very same store must verify the two-certificate chain.

  The digest is also exercised on its failure path: the resource cannot be
  corrupted from a test, so VerifyEmbeddedRootsSha256 is handed copies of the
  shipped table with one byte changed (in the DER area, in a record's trust
  byte, in the header digest) and with the table cut short. Each of them must
  raise ECertBundleError, never decode into a quietly weaker trust store.

  The snapshot date is then turned into an age flag: EmbeddedRootsIsStale is
  checked at its boundary (exactly AMaxAgeDays old is not stale yet, one day
  more is), for a snapshot dated in the future, and for the rejected negative
  limit. ReleaseEmbeddedRoots is exercised last: after it the next call must
  rebuild the table and the store from the resource and report the same pinned
  values.

  When the library is built with -dTLS_NO_EMBEDDED_ROOTS there is no resource
  to inspect; the cases below are compiled out then, mirroring the
  $(ROOTSRES) rule in the Makefile. In a normal build a missing or corrupted
  resource is a failure, never a skip. }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TRootsTests = class(TTestCase)
  published
{$ifndef TLS_NO_EMBEDDED_ROOTS}
    { --- The resource and its header --- }
    procedure TestResourceIsPresent;
    procedure TestHeaderMagicVersionAndFlags;
    procedure TestPinnedRecordCount;
    procedure TestRecordLayoutFromRawBytes;
    { --- Pinned snapshot data --- }
    procedure TestPinnedPayloadSha256;
    procedure TestSelfCheckAcceptsResource;
    procedure TestPinnedSnapshotDate;
    procedure TestDecodeRootTableMatchesPinnedHeader;
    { --- A known public root, checked against published values --- }
    procedure TestIsrgRootX1IsPresent;
    procedure TestIsrgRootX1VerifyChain;
    { --- A chain from tests/fixtures, anchored in the snapshot --- }
    procedure TestFixtureChainVerifiesAgainstEmbeddedRoots;
    { --- The integrity self-check, on tampered copies --- }
    procedure TestSelfCheckRejectsTamperedPayload;
    procedure TestSelfCheckRejectsTamperedHeaderDigest;
    procedure TestSelfCheckRejectsTruncatedTable;
    { --- Staleness of the snapshot (a flag, not an error) --- }
    procedure TestIsStaleOnAndBeforeSnapshotDate;
    procedure TestIsStaleBoundary;
    procedure TestIsStaleRejectsNegativeMaxAge;
    { --- The cache can be dropped and rebuilt --- }
    procedure TestReleaseEmbeddedRootsRebuildsCache;
{$endif}
  end;

implementation

uses
  SysUtils, Classes,
  tls.sha2, tls.roottable, tls.roots, tls.certstore, tls.x509;

const
  { Properties pinned for the snapshot committed in certs/roots.pem: 120
    trusted roots dated 2026-10-22 (Unix days 20748) whose payload hashes to
    the digest below. `make roots` prints the same three values; update them
    here when the snapshot is refreshed. }
  EXPECTED_RECORD_COUNT = 120;
  EXPECTED_SNAPSHOT_DAYS = 20748; { 2026-10-22 as Unix days, UTC }
  EXPECTED_SNAPSHOT_YEAR = 2026;
  EXPECTED_SNAPSHOT_MONTH = 10;
  EXPECTED_SNAPSHOT_DAY = 22;
  EXPECTED_PAYLOAD_SHA256 =
    '391521bf207b7891ed90e9a967db17413c728eb2db1bcd0b291978928aad0dec';

  { Properties of ISRG Root X1 (the Let's Encrypt root), taken from the
    certificate Let's Encrypt publishes and printed by
    `openssl x509 -in isrgrootx1.pem -fingerprint -sha256 -text`: the SHA-256
    fingerprint of its DER and its 20-byte SubjectKeyIdentifier. Both are
    properties of that root, not of this build, so they survive a snapshot
    refresh and only fail if the snapshot stops carrying the real root. }
  ISRG_ROOT_X1_CN = 'ISRG Root X1';
  ISRG_ROOT_X1_ORG = 'Internet Security Research Group';
  ISRG_ROOT_X1_SHA256 =
    '96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6';
  ISRG_ROOT_X1_SKI = '79b459e67bb6e5e40173800888c81a58f6e99b6e';

  { Name attributes used to recognise the root: O = 2.5.4.10 and
    CN = 2.5.4.3 (RFC 4514 / X.520). }
  OID_ORG = '2.5.4.10';
  OID_COMMON_NAME = '2.5.4.3';

{$ifndef TLS_NO_EMBEDDED_ROOTS}

{--- Helpers ---}

{ Little-endian uint32 of the table header/record fields. }
function GetUInt32(const AData: TBytes; AOffset: Integer): LongWord;
begin
  Result := LongWord(AData[AOffset]) or
    (LongWord(AData[AOffset + 1]) shl 8) or
    (LongWord(AData[AOffset + 2]) shl 16) or
    (LongWord(AData[AOffset + 3]) shl 24);
end;

{ Lower-case hex, the form `make roots` prints and the pinned constant uses. }
function HexOf(const AData: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to Length(AData) - 1 do
    Result := Result + LowerCase(Format('%.2x', [AData[I]]));
end;

{ The magic bytes as text, to compare against ROOT_TABLE_MAGIC. }
function MagicOf(const AData: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to ROOT_TABLE_MAGIC_LEN - 1 do
    Result := Result + Chr(AData[ROOT_TABLE_HDR_MAGIC_OFS + I]);
end;

{ Everything after the header: records plus DER blobs, i.e. the region the
  header's SHA-256 covers. }
function PayloadOf(const AData: TBytes): TBytes;
begin
  Result := Copy(AData, ROOT_TABLE_PAYLOAD_OFS,
    Length(AData) - ROOT_TABLE_PAYLOAD_OFS);
end;

{ How many DER blobs of ATable hash to ADigestHex. Counted over the decoded
  table, i.e. over the bytes the store is built from, so it says whether the
  snapshot really carries that certificate (exactly once). }
function CountDerWithSha256(ATable: TRootTable;
  const ADigestHex: string): LongInt;
var
  I: LongInt;
begin
  Result := 0;
  for I := 0 to ATable.Count - 1 do
    if HexOf(SHA256(ATable.CertificateDer(I))) = ADigestHex then
      Inc(Result);
end;

{ First certificate of AStore whose CN is ACN, nil when there is none. The
  store indexes subjects and SKIs only, and the subject string here is taken
  from the certificate itself, so the root is located attribute by attribute —
  which is also what a caller looking for "the Let's Encrypt root" does. }
function FindByCommonName(const AStore: TCertStore;
  const ACN: string): TX509Cert;
var
  I: LongInt;
  Cert: TX509Cert;
begin
  Result := nil;
  for I := 0 to AStore.Count - 1 do
  begin
    Cert := AStore.At(I);
    if Cert.Subject.GetByOID(OID_COMMON_NAME) = ACN then
      Exit(Cert);
  end;
end;

{--- Fixture chain helpers (tests/fixtures) ---}

{ Raw bytes of a file under tests/fixtures. The runner lives in build/, so the
  directory is resolved from the executable first and from the working
  directory second, exactly as test_certverify does. }
function LoadFixture(const AName: string): TBytes;
var
  Fs: TFileStream;
  Path: string;
begin
  Path := ExtractFilePath(ParamStr(0)) + '..' + PathDelim + 'tests' +
    PathDelim + 'fixtures' + PathDelim + AName;
  if not FileExists(Path) then
    Path := 'tests' + PathDelim + 'fixtures' + PathDelim + AName;
  Fs := TFileStream.Create(Path, fmOpenRead);
  try
    Result := nil;
    SetLength(Result, Fs.Size);
    if Fs.Size > 0 then
      Fs.ReadBuffer(Result[0], Fs.Size);
  finally
    Fs.Free;
  end;
end;

{ Parsed DER certificate from tests/fixtures; the caller frees it. }
function ParseFixture(const AName: string): TX509Cert;
begin
  Result := ParseCertificate(LoadFixture(AName));
end;

{--- Tampered-copy helpers ---}

{ A copy of AData with byte AOffset xor'ed with AXor. The shipped resource
  itself is never touched: the check under test takes the bytes as a
  parameter, which is exactly why it is public. }
function TamperedCopy(const AData: TBytes; AOffset: Integer;
  AXor: Byte): TBytes;
begin
  Result := Copy(AData, 0, Length(AData));
  Result[AOffset] := Result[AOffset] xor AXor;
end;

{ Message of the ECertBundleError VerifyEmbeddedRootsSha256 raises for ATable,
  '' when the bytes are accepted. Any other exception propagates, so an
  unexpected error fails the case with its own text instead of looking like a
  rejection. }
function VerifyError(const ATable: TBytes): string;
begin
  Result := '';
  try
    VerifyEmbeddedRootsSha256(ATable);
  except
    on E: ECertBundleError do
      Result := E.Message;
  end;
end;

{--- The resource and its header ---}

procedure TRootsTests.TestResourceIsPresent;
var
  Data, Again: TBytes;
begin
  Data := EmbeddedRootsTableBytes;
  AssertTrue('the embedded root table must not be empty',
    Length(Data) > ROOT_TABLE_HEADER_SIZE);

  { The accessor promises a copy the caller owns: two reads must agree in
    size and content, and a caller must not be able to shrink the table seen
    by everyone else. }
  Again := EmbeddedRootsTableBytes;
  AssertEquals('two reads must return the same table size',
    Length(Data), Length(Again));
  AssertEquals('two reads must return the same payload digest',
    HexOf(PayloadOf(Data)), HexOf(PayloadOf(Again)));
end;

procedure TRootsTests.TestHeaderMagicVersionAndFlags;
var
  Data: TBytes;
begin
  Data := EmbeddedRootsTableBytes;
  AssertEquals('the resource must start with the table magic',
    ROOT_TABLE_MAGIC, MagicOf(Data));
  AssertEquals('the resource must carry the format version this reader knows',
    ROOT_TABLE_VERSION, Data[ROOT_TABLE_HDR_VERSION_OFS]);
  AssertEquals('the reserved flags byte must be zero',
    0, Data[ROOT_TABLE_HDR_FLAGS_OFS]);
end;

procedure TRootsTests.TestPinnedRecordCount;
var
  Data: TBytes;
  Count: LongWord;
begin
  Data := EmbeddedRootsTableBytes;
  Count := GetUInt32(Data, ROOT_TABLE_HDR_COUNT_OFS);
  AssertTrue('a snapshot must contain at least one root', Count > 0);
  AssertEquals('the snapshot has a different record count than pinned',
    EXPECTED_RECORD_COUNT, Integer(Count));
end;

procedure TRootsTests.TestRecordLayoutFromRawBytes;
var
  Data: TBytes;
  Count, I, RecOfs, DerBase, Next, DerOffset, DerLength: LongWord;
begin
  Data := EmbeddedRootsTableBytes;
  Count := GetUInt32(Data, ROOT_TABLE_HDR_COUNT_OFS);
  AssertTrue('record count must be positive', Count > 0);

  DerBase := ROOT_TABLE_RECORDS_OFS + Count * ROOT_TABLE_RECORD_SIZE;
  AssertTrue('the record area must fit into the table',
    LongWord(Length(Data)) > DerBase);

  { The generator writes the DER blobs back to back, in record order, right
    after the record area, and nothing else follows: the first blob starts at
    DerBase, each next one where its predecessor ended, and the last one ends
    at the end of the table. Checked without DecodeRootTable on purpose. }
  Next := DerBase;
  for I := 0 to Count - 1 do
  begin
    RecOfs := ROOT_TABLE_RECORDS_OFS + I * ROOT_TABLE_RECORD_SIZE;
    DerOffset := GetUInt32(Data, RecOfs + ROOT_TABLE_REC_DEROFS_OFS);
    DerLength := GetUInt32(Data, RecOfs + ROOT_TABLE_REC_DERLEN_OFS);
    AssertTrue(Format('record %d: the DER blob must not be empty', [I]),
      DerLength > 0);
    AssertEquals(Format('record %d: the DER blob must follow the previous one',
      [I]), Next, DerOffset);
    Inc(Next, DerLength);
  end;
  AssertEquals('the DER blobs must fill the table to its end',
    LongWord(Length(Data)), Next);
end;

{--- Pinned snapshot data ---}

procedure TRootsTests.TestPinnedPayloadSha256;
var
  Data, Stored: TBytes;
begin
  Data := EmbeddedRootsTableBytes;

  { Independent reference: SHA-256 of the payload region, as pinned for this
    snapshot. A resource replaced after the build (or a generator change that
    rewrites the table) shows up here. }
  AssertEquals('the payload digest differs from the pinned one',
    EXPECTED_PAYLOAD_SHA256, HexOf(SHA256(PayloadOf(Data))));

  { ... and the header must carry exactly that digest, which is what the
    unit's self-check compares against. }
  Stored := Copy(Data, ROOT_TABLE_HDR_SHA256_OFS, ROOT_TABLE_SHA256_LEN);
  AssertEquals('the header digest differs from the pinned one',
    EXPECTED_PAYLOAD_SHA256, HexOf(Stored));
end;

procedure TRootsTests.TestSelfCheckAcceptsResource;
var
  Data: TBytes;
begin
  Data := EmbeddedRootsTableBytes;
  { The accessor already runs this check; calling it again documents that the
    shipped resource satisfies the contract rather than only that the reader
    happened to succeed. It raises ECertBundleError on a mismatch. }
  VerifyEmbeddedRootsSha256(Data);
  AssertTrue('the shipped resource passed its SHA-256 self-check', True);
end;

procedure TRootsTests.TestPinnedSnapshotDate;
var
  Data: TBytes;
begin
  Data := EmbeddedRootsTableBytes;
  AssertEquals('the header carries a different snapshot date than pinned',
    EXPECTED_SNAPSHOT_DAYS,
    Integer(GetUInt32(Data, ROOT_TABLE_HDR_DATE_OFS)));

  { The public accessor converts the header field to a TDateTime with no
    time-of-day part, so the date must survive the cache and the conversion. }
  AssertEquals('EmbeddedRootsDate must report the pinned snapshot date',
    Format('%.4d-%.2d-%.2d', [EXPECTED_SNAPSHOT_YEAR, EXPECTED_SNAPSHOT_MONTH,
      EXPECTED_SNAPSHOT_DAY]),
    FormatDateTime('yyyy-mm-dd', EmbeddedRootsDate));
end;

procedure TRootsTests.TestDecodeRootTableMatchesPinnedHeader;
var
  Table: TRootTable;
begin
  Table := DecodeRootTable(EmbeddedRootsTableBytes);
  try
    AssertEquals('the shipped table must decode to the pinned record count',
      EXPECTED_RECORD_COUNT, Table.Count);
    AssertEquals('the decoded table must keep the pinned snapshot date',
      EXPECTED_SNAPSHOT_DAYS, Integer(Table.SnapshotUnixDays));
    AssertEquals('the decoded table must expose the pinned digest',
      EXPECTED_PAYLOAD_SHA256, HexOf(Table.DataSha256));
  finally
    Table.Free;
  end;
end;

{--- A known public root, checked against published values ---}

{ The snapshot must carry ISRG Root X1 -- the root behind Let's Encrypt and the
  anchor most publicly trusted chains end at. It is checked against the values
  published for that certificate: the SHA-256 fingerprint of its DER and its
  SubjectKeyIdentifier. Neither depends on this build, so the case only fails
  when the snapshot stops carrying the real root. }
procedure TRootsTests.TestIsrgRootX1IsPresent;
var
  Table: TRootTable;
  Store: TCertStore;
  Cert: TX509Cert;
begin
  Table := DecodeRootTable(EmbeddedRootsTableBytes);
  try
    AssertEquals('the snapshot must carry ISRG Root X1 exactly once',
      1, CountDerWithSha256(Table, ISRG_ROOT_X1_SHA256));
  finally
    Table.Free;
  end;

  Store := EmbeddedRoots;
  Cert := FindByCommonName(Store, ISRG_ROOT_X1_CN);
  AssertTrue('ISRG Root X1 must be in the embedded trust store',
    Cert <> nil);
  AssertEquals('ISRG Root X1 must be the Let''s Encrypt root, not a look-alike',
    ISRG_ROOT_X1_ORG, Cert.Subject.GetByOID(OID_ORG));

  { The 20 bytes openssl prints as "X509v3 Subject Key Identifier": the same
    value the record of the table carries, and the key FindBySKI indexes. }
  AssertEquals('ISRG Root X1 must keep its published SubjectKeyIdentifier',
    ISRG_ROOT_X1_SKI, HexOf(Cert.GetSubjectKeyIdentifier));

  { The root is reachable through both indexes of the store. }
  AssertTrue('FindBySubject must find ISRG Root X1',
    Store.FindBySubject(Cert.Subject.ToNameString) = Cert);
  AssertTrue('FindBySKI must find ISRG Root X1 by its own SKI',
    Store.FindBySKI(Cert.GetSubjectKeyIdentifier) = Cert);
end;

{ "root -> root" is the shortest real chain there is. VerifyChain must recognise
  the certificate as self-signed, require CA:TRUE and a valid period, and report
  a chain of one certificate. The snapshot date is the reference time, so the
  case does not start failing as the machine clock approaches the root's
  notAfter (ISRG Root X1 is valid 2015-06-04 .. 2035-06-04). }
procedure TRootsTests.TestIsrgRootX1VerifyChain;
var
  Store, Only: TCertStore;
  Cert: TX509Cert;
  Bc: TBasicConstraints;
  Res: TVerifyResult;
begin
  Store := EmbeddedRoots;
  Cert := FindByCommonName(Store, ISRG_ROOT_X1_CN);
  AssertTrue('ISRG Root X1 must be in the embedded trust store',
    Cert <> nil);

  Bc := Cert.GetBasicConstraints;
  AssertTrue('ISRG Root X1 must be a CA', Bc.IsCA);

  { VerifyChain stops at a self-signed certificate without checking that
    signature again, so the root is asked to verify itself here: only genuine,
    unaltered root bytes pass, which is what the fingerprint check above pairs
    with. }
  AssertTrue('ISRG Root X1 must verify its own signature',
    VerifySignature(Cert, Cert));

  Res := VerifyChain(Store, Cert, 8, EmbeddedRootsDate);
  AssertTrue('VerifyChain(root, root) must succeed, got: ' + Res.Reason,
    Res.OK);
  AssertEquals('the chain of a self-signed root is the root alone',
    1, Res.ChainLen);
  AssertEquals('a successful verification carries no reason', '', Res.Reason);

  { A store built straight from the embedded table -- independent of the cached
    one -- verifies the same root, i.e. the anchor really comes from the
    snapshot and the walk finds it there. }
  Only := BuildCertStore(EmbeddedRootsTableBytes);
  try
    Res := VerifyChain(Only, Cert, 8, EmbeddedRootsDate);
    AssertTrue('VerifyChain must succeed against a store built from the table, ' +
      'got: ' + Res.Reason, Res.OK);
    AssertEquals('that store must report the same one-certificate chain',
      1, Res.ChainLen);
  finally
    Only.Free;
  end;
end;

{ A chain unrelated to the snapshot -- tests/fixtures/leaf_rsa.der issued by
  tests/fixtures/ca_rsa.der -- verified by a store built from the embedded
  table. Two things are checked: the snapshot alone does not anchor that leaf
  (its issuer is not among the embedded roots), and after the fixture CA is
  added to the very same store the walk finds it. So the embedded store behaves
  as an ordinary TCertStore for real chains, and the lookup index it builds
  keeps working when more certificates are added to 120-odd roots. }
procedure TRootsTests.TestFixtureChainVerifiesAgainstEmbeddedRoots;
var
  Store: TCertStore;
  Leaf, Ca: TX509Cert;
  Res: TVerifyResult;
  Before: Integer;
  At: TDateTime;
begin
  { Independent of the cached store, so the case says nothing about (and is not
    affected by) whatever else the runner did with EmbeddedRoots. }
  Store := BuildCertStore(EmbeddedRootsTableBytes);
  Leaf := nil;
  Ca := nil;
  try
    Leaf := ParseFixture('leaf_rsa.der');
    Ca := ParseFixture('ca_rsa.der');

    { The fixtures really are a leaf -> CA pair: the leaf names the CA as its
      issuer. }
    AssertEquals('the fixture leaf must be issued by the fixture CA',
      CanonicalSubjectName(Ca.Subject.ToNameString),
      CanonicalSubjectName(Leaf.Issuer.ToNameString));

    { The reference time is taken from the certificate, one day into its
      validity, so the case neither depends on the machine clock nor stops
      working when the 365-day fixture expires. }
    At := Leaf.NotBefore + 1;

    { Snapshot alone: the leaf cannot be chained. This shows the store does not
      accept a certificate just because it holds 120 roots. }
    Res := VerifyChain(Store, Leaf, 8, At);
    AssertFalse('the fixture leaf must not verify against the snapshot alone',
      Res.OK);
    AssertTrue('the snapshot must reject it for the missing issuer, got: ' +
      Res.Reason, Pos('issuer', LowerCase(Res.Reason)) > 0);

    { Adding the fixture CA to the same store anchors the chain. The store does
      not own Ca (Add keeps a reference), so it is freed below by the test. }
    Before := Store.Count;
    Store.Add(Ca);
    AssertEquals('the store must now hold the snapshot plus the added CA',
      Before + 1, Store.Count);
    AssertTrue('the added CA must be findable through the subject index',
      Store.FindBySubject(Ca.Subject.ToNameString) = Ca);

    Res := VerifyChain(Store, Leaf, 8, At);
    AssertTrue('VerifyChain must accept the fixture chain, got: ' + Res.Reason,
      Res.OK);
    AssertEquals('the fixture chain is leaf -> CA', 2, Res.ChainLen);
    AssertEquals('a successful verification carries no reason', '', Res.Reason);
  finally
    Store.Free;
    Ca.Free;
    Leaf.Free;
  end;
end;

{--- The integrity self-check, on tampered copies ---}

{ The shipped resource cannot be corrupted from a test, so the check is given
  copies of it with a single byte changed -- the shape of a resource replaced,
  truncated or patched after `make roots`. Every such copy must be reported as
  ECertBundleError; DecodeRootTable alone would accept the record area one,
  because the records still agree with each other and only the digest differs.

  The accepted bytes are checked last, so the case fails on the change and not
  on a self-check that rejects everything. }
procedure TRootsTests.TestSelfCheckRejectsTamperedPayload;
var
  Data: TBytes;
  Msg: string;
begin
  Data := EmbeddedRootsTableBytes;
  AssertTrue('the table must be long enough to tamper with',
    Length(Data) > ROOT_TABLE_RECORDS_OFS + ROOT_TABLE_RECORD_SIZE);

  { A flipped bit in the DER area: the very last byte of the table belongs to
    the last certificate blob, i.e. to the payload. }
  Msg := VerifyError(TamperedCopy(Data, Length(Data) - 1, $01));
  AssertTrue('a changed payload must be rejected, got no error', Msg <> '');
  AssertTrue('the message must say the table is corrupted, got: "' + Msg + '"',
    Pos('corrupted', LowerCase(Msg)) > 0);

  { A flipped bit in the trust byte of the first record: no certificate bytes
    change, yet the trust set would silently widen. Only the digest covers
    this. }
  Msg := VerifyError(TamperedCopy(Data,
    ROOT_TABLE_RECORDS_OFS + ROOT_TABLE_REC_TRUST_OFS,
    ROOT_TABLE_TRUST_EMAIL));
  AssertTrue('a changed trust byte must be rejected, got no error', Msg <> '');
  AssertTrue('the message must say the table is corrupted, got: "' + Msg + '"',
    Pos('corrupted', LowerCase(Msg)) > 0);

  { The untampered bytes still pass the same call. }
  AssertEquals('the shipped resource must still pass its self-check', '',
    VerifyError(Data));
end;

procedure TRootsTests.TestSelfCheckRejectsTamperedHeaderDigest;
var
  Data: TBytes;
  Msg: string;
begin
  Data := EmbeddedRootsTableBytes;

  { The header digest is outside the hashed region, so the payload still agrees
    with the records; nothing but this check catches the change. }
  Msg := VerifyError(TamperedCopy(Data,
    ROOT_TABLE_HDR_SHA256_OFS + ROOT_TABLE_SHA256_LEN - 1, $ff));
  AssertTrue('a changed header digest must be rejected, got no error',
    Msg <> '');
  AssertTrue('the message must say the table is corrupted, got: "' + Msg + '"',
    Pos('corrupted', LowerCase(Msg)) > 0);
  { Both digests are quoted: what the header claims and what the payload
    actually hashes to. }
  AssertTrue('the message must quote the stored digest, got: "' + Msg + '"',
    Pos('sha256=', LowerCase(Msg)) > 0);
end;

procedure TRootsTests.TestSelfCheckRejectsTruncatedTable;
var
  Data: TBytes;
  Msg: string;
begin
  Data := EmbeddedRootsTableBytes;

  { Too short for a header at all -- including the empty table, which is what
    an unbuilt or zero-length resource looks like. }
  Msg := VerifyError(Copy(Data, 0, ROOT_TABLE_HEADER_SIZE - 1));
  AssertTrue('a table shorter than its header must be rejected, ' +
    'got no error', Msg <> '');
  AssertTrue('the message must say the table is truncated, got: "' + Msg + '"',
    Pos('truncated', LowerCase(Msg)) > 0);

  Msg := VerifyError(nil);
  AssertTrue('an empty table must be rejected, got no error', Msg <> '');

  { Cut inside the payload: the header is intact, the records still parse, and
    only the digest comparison notices that DER blobs went missing. }
  Msg := VerifyError(Copy(Data, 0, Length(Data) - 1));
  AssertTrue('a table cut inside the payload must be rejected, ' +
    'got no error', Msg <> '');
  AssertTrue('a cut payload is a digest mismatch, got: "' + Msg + '"',
    Pos('corrupted', LowerCase(Msg)) > 0);
end;

{--- Staleness of the snapshot (a flag, not an error) ---}

{ The snapshot is fresh on its own date: with a zero-day limit the age is 0,
  which is not "older than 0". A snapshot dated in the future has a negative
  age and is never stale. No error is raised for an old snapshot either -- the
  caller decides what to do with the flag. }
procedure TRootsTests.TestIsStaleOnAndBeforeSnapshotDate;
var
  Snapshot: TDateTime;
begin
  Snapshot := EmbeddedRootsDate;
  AssertFalse('a snapshot is not stale on its own date',
    EmbeddedRootsIsStale(Snapshot, 0));
  AssertFalse('the default 365-day limit must accept the snapshot itself',
    EmbeddedRootsIsStale(Snapshot));
  AssertFalse('a snapshot dated in the future is never stale',
    EmbeddedRootsIsStale(Snapshot - 30, 0));

  { The reference value really is the pinned snapshot date, i.e. the flag is
    computed from the resource and not from the machine clock. }
  AssertEquals('EmbeddedRootsIsStale must use the pinned snapshot date',
    Format('%.4d-%.2d-%.2d', [EXPECTED_SNAPSHOT_YEAR, EXPECTED_SNAPSHOT_MONTH,
      EXPECTED_SNAPSHOT_DAY]),
    FormatDateTime('yyyy-mm-dd', Snapshot));
end;

{ The limit is exclusive: exactly AMaxAgeDays old is not stale yet, one day
  more is. Checked for the default limit and for two small ones, so the rule
  is a property of the function rather than an accident of 365. }
procedure TRootsTests.TestIsStaleBoundary;
var
  Snapshot: TDateTime;
begin
  Snapshot := EmbeddedRootsDate;

  AssertFalse('a snapshot exactly 365 days old is not stale yet',
    EmbeddedRootsIsStale(Snapshot + 365));
  AssertTrue('a snapshot 366 days old is stale',
    EmbeddedRootsIsStale(Snapshot + 366));

  AssertFalse('a snapshot exactly 30 days old is not stale with a 30-day limit',
    EmbeddedRootsIsStale(Snapshot + 30, 30));
  AssertTrue('a snapshot 31 days old is stale with a 30-day limit',
    EmbeddedRootsIsStale(Snapshot + 31, 30));

  AssertFalse('a snapshot exactly one day old is not stale with a 1-day limit',
    EmbeddedRootsIsStale(Snapshot + 1, 1));
  { A minute past the limit is already stale: the comparison is strict. }
  AssertTrue('a snapshot older than the limit by a minute is stale',
    EmbeddedRootsIsStale(Snapshot + 1 + 1 / 1440, 1));
end;

{ A negative limit is a caller error, not "no limit": it is rejected with the
  typed RTL exception before the resource is even decoded. }
procedure TRootsTests.TestIsStaleRejectsNegativeMaxAge;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    EmbeddedRootsIsStale(EmbeddedRootsDate, -1);
  except
    on E: EArgumentOutOfRangeException do
      Raised := True;
  end;
  AssertTrue('a negative maximum age must raise ' +
    'EArgumentOutOfRangeException', Raised);

  { A zero-day limit is valid and still accepts the snapshot itself. }
  AssertFalse('a zero-day limit must be accepted',
    EmbeddedRootsIsStale(EmbeddedRootsDate, 0));
end;

{--- The cache can be dropped and rebuilt ---}

{ The unit owns the cached table and store; ReleaseEmbeddedRoots drops both, so
  the next calls must read and decode the resource again and arrive at the same
  pinned values. This is also the teardown the leak check needs: the store is
  freed here instead of only at process exit, and nothing dangles afterwards. }
procedure TRootsTests.TestReleaseEmbeddedRootsRebuildsCache;
var
  Snapshot: TDateTime;
  Cert: TX509Cert;
begin
  AssertEquals('the cached store must hold the pinned snapshot',
    EXPECTED_RECORD_COUNT, EmbeddedRoots.Count);
  Snapshot := EmbeddedRootsDate;

  ReleaseEmbeddedRoots;

  { Same values: dropping the cache is invisible to callers. }
  AssertEquals('the rebuilt store must hold the same snapshot',
    EXPECTED_RECORD_COUNT, EmbeddedRoots.Count);
  AssertEquals('the rebuilt date must equal the pinned snapshot date',
    Snapshot, EmbeddedRootsDate);

  { ... and the rebuilt store is a working one, not an empty shell: the same
    root is there, with the values published for it. }
  Cert := FindByCommonName(EmbeddedRoots, ISRG_ROOT_X1_CN);
  AssertTrue('the rebuilt store must still carry ISRG Root X1', Cert <> nil);
  AssertEquals('the rebuilt copy must keep its published SubjectKeyIdentifier',
    ISRG_ROOT_X1_SKI, HexOf(Cert.GetSubjectKeyIdentifier));
  AssertTrue('the rebuilt store must index it by subject',
    EmbeddedRoots.FindBySubject(Cert.Subject.ToNameString) = Cert);

  { A second release is a no-op, not a crash. }
  ReleaseEmbeddedRoots;
  AssertEquals('the store must be rebuildable more than once',
    EXPECTED_RECORD_COUNT, EmbeddedRoots.Count);
end;

{$endif}

initialization
  RegisterTest(TRootsTests);

end.
