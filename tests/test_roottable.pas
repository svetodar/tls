{ SPDX-License-Identifier: Apache-2.0 }
unit test_roottable;

{ Tests for the embedded root-table reader (tls.roottable): DecodeRootTable on
  a well-formed in-memory table and on corrupted input (magic, version, flags,
  record count, record area, SKI flag, trust bits, DER offset and length), the
  accessors of TRootTable/TRootEntry, and the store builders
  CertStoreFromTable/BuildCertStore (distrusted records, a DER blob that is
  not a certificate, a nil table, VerifyChain over a store built from a table).

  Every table is assembled in memory from the DER fixtures, so the suite does
  not depend on tools/rootsgen or on the embedded resource. }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TRootTableTests = class(TTestCase)
  published
    { --- Decoding a well-formed table --- }
    procedure TestDecodeEmptyTable;
    procedure TestDecodeValidTable;
    procedure TestDecodeZeroRecords;
    procedure TestDecodeKeepsPrivateCopy;
    procedure TestEntryOutOfRange;
    { --- Corrupted header --- }
    procedure TestDecodeTruncatedHeader;
    procedure TestDecodeBadMagic;
    procedure TestDecodeBadVersion;
    procedure TestDecodeReservedFlags;
    procedure TestDecodeCountAboveLimit;
    procedure TestDecodeRecordAreaExceedsTable;
    { --- Corrupted record --- }
    procedure TestDecodeBadSkiPresent;
    procedure TestDecodeNonZeroSkiWhenAbsent;
    procedure TestDecodeUnknownTrustBits;
    procedure TestDecodeEmptyDerBlob;
    procedure TestDecodeDerLengthAboveLimit;
    procedure TestDecodeDerOffsetOverlapsRecords;
    procedure TestDecodeDerEndExceedsTable;
    { --- Store building --- }
    procedure TestBuildStoreFromTable;
    procedure TestBuildStoreVerifiesChain;
    procedure TestBuildStoreSkipsDistrusted;
    procedure TestBuildStoreIncludesDistrusted;
    procedure TestBuildStoreSkipsBrokenDistrustedDer;
    procedure TestBuildStoreBrokenDer;
    procedure TestBuildStoreNilTable;
    procedure TestBuildCertStoreFromBytes;
    procedure TestBuildCertStoreBadBytes;
  end;

implementation

uses
  SysUtils, Classes,
  tls.sha2, tls.x509, tls.certstore, tls.roottable;

{--- Test data ---}

const
  { Snapshot date carried by the test tables: 2025-12-15 as Unix days (UTC).
    The reader only stores and converts it, so the exact value is arbitrary;
    the expectations below derive from it. }
  TEST_SNAPSHOT_DAYS = 20437;
  TEST_SNAPSHOT_YEAR = 2025;
  TEST_SNAPSHOT_MONTH = 12;
  TEST_SNAPSHOT_DAY = 15;

  { Magic of a table ('TLSROT'), in the order the reader expects it. }
  TEST_TABLE_MAGIC: array[0..ROOT_TABLE_MAGIC_LEN - 1] of AnsiChar = 'TLSROT';

  { A DER blob that is well-formed ASN.1 but is not a certificate: an INTEGER
    fixture is enough to reach the "cannot be parsed" branch. }
  NOT_A_CERT_FIXTURE = 'der_int_zero.der';

  { Certificate fixtures used as trust anchors. }
  RSA_CA_FIXTURE = 'ca_rsa.der';
  EC_CA_FIXTURE = 'ca_ec.der';
  RSA_LEAF_FIXTURE = 'leaf_rsa.der';

type
  { One record the table builder writes. The fields mirror the on-disk record,
    so a test can produce deliberately inconsistent values (for example a
    non-zero SKI marked as absent, or a DER length above the format limit). }
  TRootRecordSpec = record
    Der: TBytes;
    SubjectHash: LongWord;
    HasSki: Boolean;
    Ski: TBytes;
    Trust: Byte;
  end;

{--- Helpers ---}

function LoadFixture(const Name: string): TBytes;
var
  fs: TFileStream;
  path: string;
begin
  path := ExtractFilePath(ParamStr(0)) + '..' + PathDelim + 'tests' +
    PathDelim + 'fixtures' + PathDelim + Name;
  if not FileExists(path) then
    path := 'tests' + PathDelim + 'fixtures' + PathDelim + Name;
  fs := TFileStream.Create(path, fmOpenRead);
  try
    SetLength(Result, fs.Size);
    if fs.Size > 0 then
      fs.ReadBuffer(Result[0], fs.Size);
  finally
    fs.Free;
  end;
end;

procedure PutUInt32(var AData: TBytes; AOffset: Integer; AValue: LongWord);
begin
  AData[AOffset] := Byte(AValue);
  AData[AOffset + 1] := Byte(AValue shr 8);
  AData[AOffset + 2] := Byte(AValue shr 16);
  AData[AOffset + 3] := Byte(AValue shr 24);
end;

{ Absolute offset of record AIndex inside a table. }
function RecordAt(AIndex: Integer): Integer;
begin
  Result := ROOT_TABLE_RECORDS_OFS + AIndex * ROOT_TABLE_RECORD_SIZE;
end;

{ Opaque 32-bit hash of a subject name. The reader never interprets this field
  (tools/rootsgen fills it in), so a local FNV-1a over the lower-cased name is
  enough: the tests only check that the value round-trips. }
function NameHash(const AName: string): LongWord;
var
  I: Integer;
  S: string;
begin
  Result := 2166136261;
  S := LowerCase(AName);
  for I := 1 to Length(S) do
  begin
    Result := Result xor LongWord(Ord(S[I]));
    Result := Result * 16777619;
  end;
end;

{ Spec for a real certificate fixture: subject hash and SKI come from the
  parsed certificate, exactly as tools/rootsgen would fill them in. }
function SpecFromCert(const ADer: TBytes; ATrust: Byte): TRootRecordSpec;
var
  Cert: TX509Cert;
  Ski: TBytes;
begin
  Result.Der := ADer;
  Result.SubjectHash := 0;
  Result.HasSki := False;
  Result.Ski := nil;
  Result.Trust := ATrust;
  Cert := ParseCertificate(ADer);
  try
    Result.SubjectHash := NameHash(Cert.Subject.ToNameString);
    Ski := Cert.GetSubjectKeyIdentifier;
    Result.HasSki := Length(Ski) = ROOT_TABLE_SKI_LEN;
    Result.Ski := Ski;
  finally
    Cert.Free;
  end;
end;

{ Assemble a table from ASpecs: header, records, then the DER blobs
  back-to-back, with the SHA-256 of the payload in the header. Mirrors the
  layout documented in tls.roottable, so the decoder sees a well-formed
  bundle. }
function BuildTable(const ASpecs: array of TRootRecordSpec;
  ASnapshotDays: LongWord): TBytes;
var
  I, Count, DerTotal, DerOfs, DerPos, RecBase: Integer;
  Payload, Digest: TBytes;
begin
  Count := Length(ASpecs);
  DerTotal := 0;
  for I := 0 to Count - 1 do
    Inc(DerTotal, Length(ASpecs[I].Der));

  { Payload = records followed by the DER blobs. }
  SetLength(Payload, Count * ROOT_TABLE_RECORD_SIZE + DerTotal);
  DerOfs := ROOT_TABLE_HEADER_SIZE + Count * ROOT_TABLE_RECORD_SIZE;
  for I := 0 to Count - 1 do
  begin
    RecBase := I * ROOT_TABLE_RECORD_SIZE;
    PutUInt32(Payload, RecBase + ROOT_TABLE_REC_DEROFS_OFS, LongWord(DerOfs));
    PutUInt32(Payload, RecBase + ROOT_TABLE_REC_DERLEN_OFS,
      LongWord(Length(ASpecs[I].Der)));
    PutUInt32(Payload, RecBase + ROOT_TABLE_REC_SUBJECTHASH_OFS,
      ASpecs[I].SubjectHash);
    if ASpecs[I].HasSki then
      Payload[RecBase + ROOT_TABLE_REC_SKIPRESENT_OFS] := ROOT_TABLE_SKI_PRESENT
    else
      Payload[RecBase + ROOT_TABLE_REC_SKIPRESENT_OFS] := ROOT_TABLE_SKI_ABSENT;
    if Length(ASpecs[I].Ski) > 0 then
      Move(ASpecs[I].Ski[0], Payload[RecBase + ROOT_TABLE_REC_SKI_OFS],
        ROOT_TABLE_SKI_LEN);
    Payload[RecBase + ROOT_TABLE_REC_TRUST_OFS] := ASpecs[I].Trust;
    DerPos := DerOfs - ROOT_TABLE_HEADER_SIZE;
    if Length(ASpecs[I].Der) > 0 then
      Move(ASpecs[I].Der[0], Payload[DerPos], Length(ASpecs[I].Der));
    Inc(DerOfs, Length(ASpecs[I].Der));
  end;

  Digest := SHA256(Payload);
  SetLength(Result, ROOT_TABLE_HEADER_SIZE + Length(Payload));
  Move(TEST_TABLE_MAGIC, Result[0], ROOT_TABLE_MAGIC_LEN);
  Result[ROOT_TABLE_HDR_VERSION_OFS] := ROOT_TABLE_VERSION;
  Result[ROOT_TABLE_HDR_FLAGS_OFS] := 0;
  PutUInt32(Result, ROOT_TABLE_HDR_COUNT_OFS, LongWord(Count));
  PutUInt32(Result, ROOT_TABLE_HDR_DATE_OFS, ASnapshotDays);
  Move(Digest[0], Result[ROOT_TABLE_HDR_SHA256_OFS], ROOT_TABLE_SHA256_LEN);
  if Length(Payload) > 0 then
    Move(Payload[0], Result[ROOT_TABLE_PAYLOAD_OFS], Length(Payload));
end;

function BuildOneTable(const ASpec: TRootRecordSpec): TBytes;
var
  Specs: array[0..0] of TRootRecordSpec;
begin
  Specs[0] := ASpec;
  Result := BuildTable(Specs, TEST_SNAPSHOT_DAYS);
end;

function BuildTwoTable(const AFirst, ASecond: TRootRecordSpec): TBytes;
var
  Specs: array[0..1] of TRootRecordSpec;
begin
  Specs[0] := AFirst;
  Specs[1] := ASecond;
  Result := BuildTable(Specs, TEST_SNAPSHOT_DAYS);
end;

function BuildEmptyTable: TBytes;
var
  Specs: array of TRootRecordSpec;
begin
  Specs := nil;
  Result := BuildTable(Specs, TEST_SNAPSHOT_DAYS);
end;

{ Decode ATable and return the ECertBundleError message; '' means the table
  was accepted (and freed here). Any other exception propagates, so an
  unexpected error fails the test with its own message. }
function DecodeError(const ATable: TBytes): string;
var
  Table: TRootTable;
begin
  Result := '';
  Table := nil;
  try
    try
      Table := DecodeRootTable(ATable);
    except
      on E: ECertBundleError do
        Result := E.Message;
    end;
  finally
    Table.Free;
  end;
end;

{ Same for the bytes-to-store path: '' means the store was built (and freed
  here). }
function BuildError(const ATable: TBytes; AIncludeDistrusted: Boolean): string;
var
  Store: TCertStore;
begin
  Result := '';
  Store := nil;
  try
    try
      Store := BuildCertStore(ATable, AIncludeDistrusted);
    except
      on E: ECertBundleError do
        Result := E.Message;
    end;
  finally
    Store.Free;
  end;
end;

{--- Decoding a well-formed table ---}

procedure TRootTableTests.TestDecodeEmptyTable;
var
  msg: string;
begin
  { No bytes at all: the header cannot be there, so the input is rejected
    instead of producing an empty table. }
  msg := DecodeError(nil);
  AssertTrue('nil table is rejected', msg <> '');
  AssertTrue('message names the truncation',
    Pos('truncated', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeValidTable;
var
  rsa, ec: TBytes;
  table, payload: TBytes;
  decoded: TRootTable;
  entry: TRootEntry;
  cert: TX509Cert;
  ski: TBytes;
begin
  rsa := LoadFixture(RSA_CA_FIXTURE);
  ec := LoadFixture(EC_CA_FIXTURE);
  table := BuildTwoTable(
    SpecFromCert(rsa, ROOT_TABLE_TRUST_WEB),
    SpecFromCert(ec, ROOT_TABLE_TRUST_WEB or ROOT_TABLE_TRUST_EMAIL));

  decoded := DecodeRootTable(table);
  try
    AssertEquals('count', 2, decoded.Count);
    AssertEquals('version', Int64(ROOT_TABLE_VERSION), Int64(decoded.Version));
    AssertEquals('reserved flags', Int64(0), Int64(decoded.Flags));
    AssertEquals('snapshot days', Int64(TEST_SNAPSHOT_DAYS),
      Int64(decoded.SnapshotUnixDays));
    AssertTrue('snapshot date',
      decoded.SnapshotDate = EncodeDate(TEST_SNAPSHOT_YEAR,
        TEST_SNAPSHOT_MONTH, TEST_SNAPSHOT_DAY));
    AssertEquals('table bytes kept', Int64(Length(table)),
      Int64(Length(decoded.Data)));

    { The header hash is exposed verbatim; that it is really the SHA-256 of
      the payload is checked against an independent computation. }
    payload := Copy(table, ROOT_TABLE_PAYLOAD_OFS,
      Length(table) - ROOT_TABLE_PAYLOAD_OFS);
    AssertEquals('dataSha256 is the payload hash', BytesToHex(SHA256(payload)),
      BytesToHex(decoded.DataSha256));

    entry := decoded.Entry(0);
    AssertEquals('record 0 DER offset',
      Int64(ROOT_TABLE_RECORDS_OFS + 2 * ROOT_TABLE_RECORD_SIZE),
      Int64(entry.DerOffset));
    AssertEquals('record 0 DER length', Int64(Length(rsa)),
      Int64(entry.DerLength));
    AssertTrue('record 0 has web trust', entry.HasTrust(ROOT_TABLE_TRUST_WEB));
    AssertFalse('record 0 is not distrusted', entry.Distrusted);

    cert := ParseCertificate(rsa);
    try
      ski := cert.GetSubjectKeyIdentifier;
      AssertTrue('fixture certificate has a SKI',
        Length(ski) = ROOT_TABLE_SKI_LEN);
      AssertTrue('record 0 SKI is marked present', entry.SkiPresent);
      AssertEquals('record 0 SKI', BytesToHex(ski), BytesToHex(entry.Ski));
    finally
      cert.Free;
    end;

    entry := decoded.Entry(1);
    AssertEquals('record 1 DER length', Int64(Length(ec)),
      Int64(entry.DerLength));
    AssertTrue('record 1 has email trust',
      entry.HasTrust(ROOT_TABLE_TRUST_EMAIL));
    AssertFalse('record 1 has no code trust',
      entry.HasTrust(ROOT_TABLE_TRUST_CODE));

    AssertEquals('record 0 DER bytes', BytesToHex(rsa),
      BytesToHex(decoded.CertificateDer(0)));
    AssertEquals('record 1 DER bytes', BytesToHex(ec),
      BytesToHex(decoded.CertificateDer(1)));
  finally
    decoded.Free;
  end;
end;

procedure TRootTableTests.TestDecodeZeroRecords;
var
  table: TBytes;
  decoded: TRootTable;
  store: TCertStore;
begin
  { A header-only table is valid: an empty bundle is not an error, it is just
    an empty trust store. }
  table := BuildEmptyTable;
  decoded := DecodeRootTable(table);
  try
    AssertEquals('no records', 0, decoded.Count);
    AssertEquals('payload hash present', Int64(ROOT_TABLE_SHA256_LEN),
      Int64(Length(decoded.DataSha256)));
  finally
    decoded.Free;
  end;

  store := BuildCertStore(table);
  try
    AssertEquals('empty store', 0, store.Count);
  finally
    store.Free;
  end;
end;

procedure TRootTableTests.TestDecodeKeepsPrivateCopy;
var
  table, der: TBytes;
  decoded: TRootTable;
  I: Integer;
begin
  der := LoadFixture(RSA_CA_FIXTURE);
  table := BuildOneTable(SpecFromCert(der, ROOT_TABLE_TRUST_WEB));
  decoded := DecodeRootTable(table);
  try
    { The decoded table must own its bytes: scribbling over the caller's
      buffer may not change what CertificateDer returns. }
    for I := 0 to High(table) do
      table[I] := $AA;
    AssertEquals('DER survives a modification of the input',
      BytesToHex(der), BytesToHex(decoded.CertificateDer(0)));
  finally
    decoded.Free;
  end;
end;

procedure TRootTableTests.TestEntryOutOfRange;
var
  decoded: TRootTable;
  entry: TRootEntry;
  raised: Boolean;
begin
  decoded := DecodeRootTable(BuildOneTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB)));
  try
    entry := nil;
    raised := False;
    try
      entry := decoded.Entry(1);
    except
      on E: ECertBundleError do
        raised := True;
    end;
    AssertTrue('index == Count is rejected', raised);

    raised := False;
    try
      entry := decoded.Entry(-1);
    except
      on E: ECertBundleError do
        raised := True;
    end;
    AssertTrue('negative index is rejected', raised);
    AssertNull('no record escaped', entry);
  finally
    decoded.Free;
  end;
end;

{--- Corrupted header ---}

procedure TRootTableTests.TestDecodeTruncatedHeader;
var
  table: TBytes;
  msg: string;
begin
  table := BuildEmptyTable;
  SetLength(table, ROOT_TABLE_HEADER_SIZE - 1);
  msg := DecodeError(table);
  AssertTrue('short header is rejected', msg <> '');
  AssertTrue('message names the truncation',
    Pos('truncated', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeBadMagic;
var
  table: TBytes;
  msg: string;
begin
  table := BuildEmptyTable;
  table[ROOT_TABLE_HDR_MAGIC_OFS] := Ord('X');
  msg := DecodeError(table);
  AssertTrue('wrong magic is rejected', msg <> '');
  AssertTrue('message names the magic', Pos('magic', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeBadVersion;
var
  table: TBytes;
  msg: string;
begin
  table := BuildEmptyTable;
  table[ROOT_TABLE_HDR_VERSION_OFS] := ROOT_TABLE_VERSION + 1;
  msg := DecodeError(table);
  AssertTrue('unknown version is rejected', msg <> '');
  AssertTrue('message names the version', Pos('version', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeReservedFlags;
var
  table: TBytes;
  msg: string;
begin
  { Reserved header flags must stay zero: an unknown flag means the table was
    produced by a newer writer and cannot be trusted. }
  table := BuildEmptyTable;
  table[ROOT_TABLE_HDR_FLAGS_OFS] := 1;
  msg := DecodeError(table);
  AssertTrue('non-zero reserved flags are rejected', msg <> '');
  AssertTrue('message names the flags', Pos('flags', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeCountAboveLimit;
var
  table: TBytes;
  msg: string;
begin
  { The count is checked before any record area arithmetic, so a huge value
    cannot make the reader allocate or index out of bounds. }
  table := BuildEmptyTable;
  PutUInt32(table, ROOT_TABLE_HDR_COUNT_OFS, ROOT_TABLE_MAX_COUNT + 1);
  msg := DecodeError(table);
  AssertTrue('count above the limit is rejected', msg <> '');
  AssertTrue('message names the count', Pos('count', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeRecordAreaExceedsTable;
var
  table: TBytes;
  msg: string;
begin
  table := BuildEmptyTable;
  PutUInt32(table, ROOT_TABLE_HDR_COUNT_OFS, 1);
  msg := DecodeError(table);
  AssertTrue('record area past the end of the table is rejected', msg <> '');
  AssertTrue('message names the records', Pos('records', LowerCase(msg)) > 0);
end;

{--- Corrupted record ---}

procedure TRootTableTests.TestDecodeBadSkiPresent;
var
  table: TBytes;
  msg: string;
begin
  table := BuildOneTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB));
  table[RecordAt(0) + ROOT_TABLE_REC_SKIPRESENT_OFS] := 2;
  msg := DecodeError(table);
  AssertTrue('unknown skiPresent value is rejected', msg <> '');
  AssertTrue('message names skiPresent',
    Pos('skipresent', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeNonZeroSkiWhenAbsent;
var
  spec: TRootRecordSpec;
  table: TBytes;
  msg: string;
begin
  { SkiPresent = False promises 20 zero bytes; anything else would make the
    record ambiguous, so it is rejected instead of being silently ignored. }
  spec := SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB);
  spec.HasSki := False;
  SetLength(spec.Ski, ROOT_TABLE_SKI_LEN);
  FillChar(spec.Ski[0], ROOT_TABLE_SKI_LEN, 1);
  table := BuildOneTable(spec);
  msg := DecodeError(table);
  AssertTrue('non-zero SKI marked absent is rejected', msg <> '');
  AssertTrue('message names the SKI', Pos('ski', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeUnknownTrustBits;
var
  table: TBytes;
  msg: string;
begin
  table := BuildOneTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB));
  table[RecordAt(0) + ROOT_TABLE_REC_TRUST_OFS] := $80;
  msg := DecodeError(table);
  AssertTrue('unknown trust bits are rejected', msg <> '');
  AssertTrue('message names the trust bits', Pos('trust', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeEmptyDerBlob;
var
  spec: TRootRecordSpec;
  msg: string;
begin
  spec := SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB);
  spec.Der := nil;
  msg := DecodeError(BuildOneTable(spec));
  AssertTrue('empty DER blob is rejected', msg <> '');
  AssertTrue('message names the empty blob',
    Pos('empty der', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeDerLengthAboveLimit;
var
  table: TBytes;
  msg: string;
begin
  table := BuildOneTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB));
  PutUInt32(table, RecordAt(0) + ROOT_TABLE_REC_DERLEN_OFS,
    ROOT_TABLE_MAX_DER_LEN + 1);
  msg := DecodeError(table);
  AssertTrue('DER length above the limit is rejected', msg <> '');
  AssertTrue('message names the limit',
    Pos('exceeds the limit', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeDerOffsetOverlapsRecords;
var
  table: TBytes;
  msg: string;
begin
  { The DER blob must start after the whole record area, otherwise a record
    could be made to point at another record's bytes. }
  table := BuildOneTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB));
  PutUInt32(table, RecordAt(0) + ROOT_TABLE_REC_DEROFS_OFS,
    ROOT_TABLE_RECORDS_OFS);
  msg := DecodeError(table);
  AssertTrue('DER blob inside the record area is rejected', msg <> '');
  AssertTrue('message names the overlap', Pos('overlaps', LowerCase(msg)) > 0);
end;

procedure TRootTableTests.TestDecodeDerEndExceedsTable;
var
  table: TBytes;
  msg: string;
begin
  table := BuildOneTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB));
  PutUInt32(table, RecordAt(0) + ROOT_TABLE_REC_DERLEN_OFS,
    LongWord(Length(table)));
  msg := DecodeError(table);
  AssertTrue('DER blob past the end of the table is rejected', msg <> '');
  AssertTrue('message names the table size',
    Pos('exceeds the table', LowerCase(msg)) > 0);
end;

{--- Store building ---}

procedure TRootTableTests.TestBuildStoreFromTable;
var
  rsa, ec: TBytes;
  decoded: TRootTable;
  store: TCertStore;
  rsaSubject, ecSubject: string;
  cert: TX509Cert;
begin
  rsa := LoadFixture(RSA_CA_FIXTURE);
  ec := LoadFixture(EC_CA_FIXTURE);
  decoded := DecodeRootTable(BuildTwoTable(
    SpecFromCert(rsa, ROOT_TABLE_TRUST_WEB),
    SpecFromCert(ec, ROOT_TABLE_TRUST_WEB)));
  try
    store := CertStoreFromTable(decoded);
    try
      AssertEquals('both roots are in the store', 2, store.Count);
      cert := ParseCertificate(rsa);
      try
        rsaSubject := cert.Subject.ToNameString;
      finally
        cert.Free;
      end;
      cert := ParseCertificate(ec);
      try
        ecSubject := cert.Subject.ToNameString;
      finally
        cert.Free;
      end;
      AssertNotNull('RSA root found by subject', store.FindBySubject(rsaSubject));
      AssertNotNull('EC root found by subject', store.FindBySubject(ecSubject));
      AssertNotNull('record 0 is in the store', store.At(0));
    finally
      store.Free;
    end;
  finally
    decoded.Free;
  end;
end;

procedure TRootTableTests.TestBuildStoreVerifiesChain;
var
  table: TBytes;
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  { End-to-end over the reader: a table containing the RSA CA must yield a
    store that VerifyChain accepts for the leaf signed by that CA. }
  table := BuildOneTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB));
  store := BuildCertStore(table);
  try
    leaf := ParseCertificate(LoadFixture(RSA_LEAF_FIXTURE));
    try
      res := VerifyChain(store, leaf);
      AssertTrue('chain verifies via a table-built store: ' + res.Reason,
        res.OK);
      AssertTrue('chain length is reported', res.ChainLen > 0);
    finally
      leaf.Free;
    end;
  finally
    store.Free;
  end;
end;

procedure TRootTableTests.TestBuildStoreSkipsDistrusted;
var
  rsa, ec: TBytes;
  store: TCertStore;
  cert: TX509Cert;
  rsaSubject: string;
begin
  rsa := LoadFixture(RSA_CA_FIXTURE);
  ec := LoadFixture(EC_CA_FIXTURE);
  { A distrusted record must never become a trust anchor, so the default
    build leaves it out of the store. }
  store := BuildCertStore(BuildTwoTable(
    SpecFromCert(rsa, ROOT_TABLE_TRUST_WEB or ROOT_TABLE_TRUST_DISTRUSTED),
    SpecFromCert(ec, ROOT_TABLE_TRUST_WEB)));
  try
    AssertEquals('distrusted root is skipped', 1, store.Count);
    cert := ParseCertificate(rsa);
    try
      rsaSubject := cert.Subject.ToNameString;
    finally
      cert.Free;
    end;
    AssertNull('distrusted root is not findable',
      store.FindBySubject(rsaSubject));
  finally
    store.Free;
  end;
end;

procedure TRootTableTests.TestBuildStoreIncludesDistrusted;
var
  store: TCertStore;
begin
  { AIncludeDistrusted = True is the caller's way to inspect them: the records
    are parsed and added, and the caller decides what to do. }
  store := BuildCertStore(BuildTwoTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE),
      ROOT_TABLE_TRUST_WEB or ROOT_TABLE_TRUST_DISTRUSTED),
    SpecFromCert(LoadFixture(EC_CA_FIXTURE), ROOT_TABLE_TRUST_WEB)), True);
  try
    AssertEquals('distrusted root included on request', 2, store.Count);
  finally
    store.Free;
  end;
end;

procedure TRootTableTests.TestBuildStoreSkipsBrokenDistrustedDer;
var
  broken: TRootRecordSpec;
  store: TCertStore;
begin
  { The distrusted record is skipped before its DER is parsed: a broken
    distrusted certificate cannot fail a bundle whose usable roots are fine. }
  broken := SpecFromCert(LoadFixture(EC_CA_FIXTURE),
    ROOT_TABLE_TRUST_WEB or ROOT_TABLE_TRUST_DISTRUSTED);
  broken.Der := LoadFixture(NOT_A_CERT_FIXTURE);
  broken.HasSki := False;
  broken.Ski := nil;
  store := BuildCertStore(BuildTwoTable(
    broken,
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB)));
  try
    AssertEquals('only the usable root is stored', 1, store.Count);
  finally
    store.Free;
  end;
end;

procedure TRootTableTests.TestBuildStoreBrokenDer;
var
  spec: TRootRecordSpec;
  msg: string;
begin
  { A record that is not marked distrusted must parse: a corrupt DER blob
    fails the whole bundle with a typed error, and no store is returned. }
  spec := SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB);
  spec.Der := LoadFixture(NOT_A_CERT_FIXTURE);
  spec.HasSki := False;
  spec.Ski := nil;
  msg := BuildError(BuildOneTable(spec), False);
  AssertTrue('a DER blob that is not a certificate is rejected', msg <> '');
  AssertTrue('message names the record and the parse failure',
    (Pos('record 0', LowerCase(msg)) > 0) and
    (Pos('cannot be parsed', LowerCase(msg)) > 0));
end;

procedure TRootTableTests.TestBuildStoreNilTable;
var
  store: TCertStore;
  raised: Boolean;
begin
  store := nil;
  raised := False;
  try
    try
      store := CertStoreFromTable(nil);
    except
      on E: ECertBundleError do
        raised := True;
    end;
    AssertTrue('a nil table cannot build a store', raised);
    AssertNull('no store escaped', store);
  finally
    store.Free;
  end;
end;

procedure TRootTableTests.TestBuildCertStoreFromBytes;
var
  store: TCertStore;
begin
  { BuildCertStore is decode + build in one call: the composite entry point
    must agree with the two-step path. }
  store := BuildCertStore(BuildTwoTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB),
    SpecFromCert(LoadFixture(EC_CA_FIXTURE),
      ROOT_TABLE_TRUST_WEB or ROOT_TABLE_TRUST_DISTRUSTED)));
  try
    AssertEquals('distrusted record skipped by default', 1, store.Count);
  finally
    store.Free;
  end;

  store := BuildCertStore(BuildTwoTable(
    SpecFromCert(LoadFixture(RSA_CA_FIXTURE), ROOT_TABLE_TRUST_WEB),
    SpecFromCert(LoadFixture(EC_CA_FIXTURE),
      ROOT_TABLE_TRUST_WEB or ROOT_TABLE_TRUST_DISTRUSTED)), True);
  try
    AssertEquals('both records with AIncludeDistrusted', 2, store.Count);
  finally
    store.Free;
  end;
end;

procedure TRootTableTests.TestBuildCertStoreBadBytes;
var
  table: TBytes;
  msg: string;
begin
  { Corrupted bytes fail before any store exists: the typed error comes out of
    the decoder, not out of a half-built store. }
  table := BuildEmptyTable;
  SetLength(table, ROOT_TABLE_HEADER_SIZE - 1);
  msg := BuildError(table, False);
  AssertTrue('truncated bytes are rejected', msg <> '');
  AssertTrue('message names the truncation',
    Pos('truncated', LowerCase(msg)) > 0);
end;

initialization
  RegisterTest(TRootTableTests);

end.
