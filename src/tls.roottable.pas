{ SPDX-License-Identifier: Apache-2.0 }
unit tls.roottable;

{ Binary format of the embedded root-certificate table.

  Layer 2 (verification). No OS calls and no file access: this unit only
  turns bytes into a structure and (through CertStoreFromTable and
  BuildCertStore) into a TCertStore, so it can be fed from a resource, from
  a stream or from a test literal.

  All integer fields are unsigned little-endian. The table is laid out as:

    header (fixed, ROOT_TABLE_HEADER_SIZE bytes):
      off  0  magic        6 bytes  'TLSROT'
      off  6  version      uint8    ROOT_TABLE_VERSION
      off  7  flags        uint8    reserved, must be 0
      off  8  count        uint32   number of records
      off 12  snapshotDate uint32   snapshot date as Unix days (UTC)
      off 16  dataSha256   32 bytes SHA-256 of everything from
                                    ROOT_TABLE_PAYLOAD_OFFSET to the end
    records (count of them, ROOT_TABLE_RECORD_SIZE bytes each):
      off  0  derOffset    uint32   start of the DER blob, table-relative
      off  4  derLength    uint32   length of the DER blob
      off  8  subjectHash  uint32   hash of the canonical subject name
      off 12  skiPresent   uint8    ROOT_TABLE_SKI_PRESENT / _ABSENT
      off 13  ski          20 bytes SubjectKeyIdentifier (zero when absent)
      off 33  trust        uint8    ROOT_TABLE_TRUST_* bit mask
    DER blobs (count of them, back-to-back, no padding).

  A record marked ROOT_TABLE_TRUST_DISTRUSTED is never used as a trust
  anchor. derOffset is relative to the first byte of the table, so the reader
  must validate it against the actual table size.

  The constants below are the contract shared with tools/rootsgen, which
  writes the table; keep the two in sync. }

{$mode objfpc}{$H+}

interface

uses
  SysUtils,      { TBytes }
  tls.asn1,      { EASN1Error }
  tls.certstore, { TCertStore }
  tls.x509;      { TX509Cert, ParseCertificate }

const
  { Identifies the table and its on-disk format version. }
  ROOT_TABLE_MAGIC = 'TLSROT';
  ROOT_TABLE_MAGIC_LEN = 6;
  ROOT_TABLE_VERSION = 1;

  { Header field offsets and total size. }
  ROOT_TABLE_HDR_MAGIC_OFS = 0;
  ROOT_TABLE_HDR_VERSION_OFS = ROOT_TABLE_HDR_MAGIC_OFS + ROOT_TABLE_MAGIC_LEN;
  ROOT_TABLE_HDR_FLAGS_OFS = ROOT_TABLE_HDR_VERSION_OFS + 1;
  ROOT_TABLE_HDR_COUNT_OFS = ROOT_TABLE_HDR_FLAGS_OFS + 1;
  ROOT_TABLE_HDR_DATE_OFS = ROOT_TABLE_HDR_COUNT_OFS + 4;
  ROOT_TABLE_HDR_SHA256_OFS = ROOT_TABLE_HDR_DATE_OFS + 4;
  ROOT_TABLE_SHA256_LEN = 32;
  ROOT_TABLE_HEADER_SIZE = ROOT_TABLE_HDR_SHA256_OFS + ROOT_TABLE_SHA256_LEN;

  { The hashed region starts right after the header: records plus DER blobs. }
  ROOT_TABLE_PAYLOAD_OFS = ROOT_TABLE_HEADER_SIZE;
  ROOT_TABLE_RECORDS_OFS = ROOT_TABLE_HEADER_SIZE;

  { Record field offsets, SKI size and total size. }
  ROOT_TABLE_REC_DEROFS_OFS = 0;
  ROOT_TABLE_REC_DERLEN_OFS = ROOT_TABLE_REC_DEROFS_OFS + 4;
  ROOT_TABLE_REC_SUBJECTHASH_OFS = ROOT_TABLE_REC_DERLEN_OFS + 4;
  ROOT_TABLE_REC_SKIPRESENT_OFS = ROOT_TABLE_REC_SUBJECTHASH_OFS + 4;
  ROOT_TABLE_REC_SKI_OFS = ROOT_TABLE_REC_SKIPRESENT_OFS + 1;
  ROOT_TABLE_SKI_LEN = 20;
  ROOT_TABLE_REC_TRUST_OFS = ROOT_TABLE_REC_SKI_OFS + ROOT_TABLE_SKI_LEN;
  ROOT_TABLE_RECORD_SIZE = ROOT_TABLE_REC_TRUST_OFS + 1;

  { skiPresent values. }
  ROOT_TABLE_SKI_ABSENT = 0;
  ROOT_TABLE_SKI_PRESENT = 1;

  { trust is a bit mask; Mozilla trust bits plus a local distrust flag. }
  ROOT_TABLE_TRUST_WEB = $01;
  ROOT_TABLE_TRUST_EMAIL = $02;
  ROOT_TABLE_TRUST_CODE = $04;
  ROOT_TABLE_TRUST_DISTRUSTED = $08;
  ROOT_TABLE_TRUST_ALL = ROOT_TABLE_TRUST_WEB or ROOT_TABLE_TRUST_EMAIL or
    ROOT_TABLE_TRUST_CODE or ROOT_TABLE_TRUST_DISTRUSTED;

  { Sanity bounds used by the reader before it trusts any length field.
    ROOT_TABLE_MAX_COUNT is far above the ~150 roots of a current snapshot;
    ROOT_TABLE_MAX_DER_LEN is far above any real CA certificate. }
  ROOT_TABLE_MAX_COUNT = 4096;
  ROOT_TABLE_MAX_DER_LEN = 1 shl 20;

  { Unix days (as stored in snapshotDate) to TDateTime conversion. }
  ROOT_TABLE_SECONDS_PER_DAY = 86400;
  ROOT_TABLE_UNIX_EPOCH_DAYS = 25569; { 1970-01-01 in TDateTime days }

type
  { Typed error for a malformed, truncated or corrupted bundle: the root
    table does not match the format described above, or (raised by
    tls.roots) the embedded resource fails its SHA-256 self-check. No
    caller should ever receive a partially decoded table or store. }
  ECertBundleError = class(Exception);

  { One decoded record of an embedded root table. }
  TRootEntry = class
  private
    FDerOffset: LongWord;
    FDerLength: LongWord;
    FSubjectHash: LongWord;
    FSkiPresent: Boolean;
    FSki: TBytes;
    FTrust: Byte;
    function GetDistrusted: Boolean;
  public
    { Offset of the DER blob, relative to the first byte of the table. }
    property DerOffset: LongWord read FDerOffset;
    property DerLength: LongWord read FDerLength;
    { Hash of the canonical subject name, computed by tools/rootsgen. }
    property SubjectHash: LongWord read FSubjectHash;
    { True when the certificate carries a SubjectKeyIdentifier. }
    property SkiPresent: Boolean read FSkiPresent;
    { 20-byte SubjectKeyIdentifier; all zero when SkiPresent is False. }
    property Ski: TBytes read FSki;
    { ROOT_TABLE_TRUST_* bit mask. }
    property Trust: Byte read FTrust;
    function HasTrust(ABit: Byte): Boolean;
    { True when ROOT_TABLE_TRUST_DISTRUSTED is set: never a trust anchor. }
    property Distrusted: Boolean read GetDistrusted;
  end;

  { Decoded embedded root table: header fields, records and the bytes they
    point into. Instances come from DecodeRootTable only, so every offset and
    length is already validated against the real table size. }
  TRootTable = class
  private
    FData: TBytes;
    FEntries: array of TRootEntry;
    FVersion: Byte;
    FFlags: Byte;
    FSnapshotUnixDays: LongWord;
    FDataSha256: TBytes;
    function GetCount: LongInt;
    function GetSnapshotDate: TDateTime;
  public
    destructor Destroy; override;
    { Number of records (one per DER blob), distrusted ones included. }
    property Count: LongInt read GetCount;
    property Version: Byte read FVersion;
    property Flags: Byte read FFlags;
    { Raw snapshotDate header field: Unix days, UTC. }
    property SnapshotUnixDays: LongWord read FSnapshotUnixDays;
    { Snapshot date as a TDateTime (no time-of-day part). }
    property SnapshotDate: TDateTime read GetSnapshotDate;
    { SHA-256 of the payload region, as stored in the header. The decoder
      only exposes it; whoever reads the table from an untrusted source
      (the resource reader) is responsible for comparing it. }
    property DataSha256: TBytes read FDataSha256;
    { The whole table exactly as decoded (a private copy). }
    property Data: TBytes read FData;
    { Record AIndex; raises when the index is out of range. }
    function Entry(AIndex: LongInt): TRootEntry;
    { Copy of the DER bytes of certificate AIndex. }
    function CertificateDer(AIndex: LongInt): TBytes;
  end;

{ Decode and validate a root table: magic, version, reserved flags, record
  count against ROOT_TABLE_MAX_COUNT, the size of the record area, and every
  record's SKI flag, trust mask, derOffset and derLength against the actual
  table size. Raises ECertBundleError on the first violated invariant; never
  returns a partially decoded table. }
function DecodeRootTable(const ATable: TBytes): TRootTable;

{ Build a trust store from an already decoded table: parse every DER blob
  whose record is not marked ROOT_TABLE_TRUST_DISTRUSTED and hand each
  certificate to a fresh TCertStore, which owns it.

  AIncludeDistrusted = True also includes the distrusted records (they are
  parsed but the caller decides what to do with them); by default they are
  skipped, because a distrusted root must never act as a trust anchor.

  Returns a TCertStore the caller must Free. On error nothing escapes: the
  partially built store and every certificate already in it are freed and
  ECertBundleError is raised (including when a DER blob is not a well-formed
  X.509 certificate), so no partial store is ever returned. }
function CertStoreFromTable(ATable: TRootTable;
  AIncludeDistrusted: Boolean = False): TCertStore;

{ Decode a table (see DecodeRootTable) and build its trust store (see
  CertStoreFromTable) in one call. Returns a TCertStore the caller must Free;
  errors — ECertBundleError. }
function BuildCertStore(const ATable: TBytes;
  AIncludeDistrusted: Boolean = False): TCertStore;

implementation

const
  { Expected magic bytes, in order (kept next to the reader, so the check
    does not depend on the string constant's encoding). }
  ROOT_TABLE_MAGIC_BYTES: array[0..ROOT_TABLE_MAGIC_LEN - 1] of Byte =
    (Ord('T'), Ord('L'), Ord('S'), Ord('R'), Ord('O'), Ord('T'));

  { Bits of the trust byte that no ROOT_TABLE_TRUST_* flag defines; a record
    with any of them set is rejected instead of being silently trusted. }
  ROOT_TABLE_TRUST_UNKNOWN_MASK = $FF - ROOT_TABLE_TRUST_ALL;

{ Every structural violation funnels through here, so that callers can catch
  one typed error (ECertBundleError) instead of inspecting message text. }
procedure BundleError(const AMsg: string);
begin
  raise ECertBundleError.Create('root table: ' + AMsg);
end;

function ReadUInt32LE(const AData: TBytes; AOffset: Integer): LongWord;
begin
  Result := LongWord(AData[AOffset]) or
    (LongWord(AData[AOffset + 1]) shl 8) or
    (LongWord(AData[AOffset + 2]) shl 16) or
    (LongWord(AData[AOffset + 3]) shl 24);
end;

{ TRootEntry }

function TRootEntry.HasTrust(ABit: Byte): Boolean;
begin
  Result := (FTrust and ABit) <> 0;
end;

function TRootEntry.GetDistrusted: Boolean;
begin
  Result := HasTrust(ROOT_TABLE_TRUST_DISTRUSTED);
end;

{ TRootTable }

destructor TRootTable.Destroy;
var
  I: Integer;
begin
  for I := 0 to High(FEntries) do
    FEntries[I].Free;
  FEntries := nil;
  FData := nil;
  FDataSha256 := nil;
  inherited Destroy;
end;

function TRootTable.GetCount: LongInt;
begin
  Result := Length(FEntries);
end;

function TRootTable.GetSnapshotDate: TDateTime;
begin
  Result := FSnapshotUnixDays + ROOT_TABLE_UNIX_EPOCH_DAYS;
end;

function TRootTable.Entry(AIndex: LongInt): TRootEntry;
begin
  if (AIndex < 0) or (AIndex >= Length(FEntries)) then
    BundleError(Format('record index %d is out of range 0..%d',
      [AIndex, Length(FEntries) - 1]));
  Result := FEntries[AIndex];
end;

function TRootTable.CertificateDer(AIndex: LongInt): TBytes;
var
  Rec: TRootEntry;
begin
  Rec := Entry(AIndex);
  Result := Copy(FData, Integer(Rec.DerOffset), Integer(Rec.DerLength));
end;

{ DecodeRootTable }

function DecodeRootTable(const ATable: TBytes): TRootTable;
var
  TableLen, Count, I, J, RecBase: Integer;
  RawCount: LongWord;
  RecsEnd, DerStart, DerEnd: Int64;
  Rec: TRootEntry;
  SkiFlag, Trust: Byte;
  MagicOk, SkiZero: Boolean;
begin
  Result := nil;
  TableLen := Length(ATable);
  if TableLen < ROOT_TABLE_HEADER_SIZE then
    BundleError(Format('table is truncated: %d bytes, the header needs %d',
      [TableLen, ROOT_TABLE_HEADER_SIZE]));

  MagicOk := True;
  for J := 0 to ROOT_TABLE_MAGIC_LEN - 1 do
    if ATable[ROOT_TABLE_HDR_MAGIC_OFS + J] <> ROOT_TABLE_MAGIC_BYTES[J] then
      MagicOk := False;
  if not MagicOk then
    BundleError('bad magic, this is not a ' + ROOT_TABLE_MAGIC + ' table');

  if ATable[ROOT_TABLE_HDR_VERSION_OFS] <> ROOT_TABLE_VERSION then
    BundleError(Format('unsupported version %d, expected %d',
      [ATable[ROOT_TABLE_HDR_VERSION_OFS], ROOT_TABLE_VERSION]));

  if ATable[ROOT_TABLE_HDR_FLAGS_OFS] <> 0 then
    BundleError(Format('reserved header flags must be zero, got $%s',
      [IntToHex(ATable[ROOT_TABLE_HDR_FLAGS_OFS], 2)]));

  RawCount := ReadUInt32LE(ATable, ROOT_TABLE_HDR_COUNT_OFS);
  if RawCount > LongWord(ROOT_TABLE_MAX_COUNT) then
    BundleError(Format('record count %u exceeds the limit of %d',
      [Int64(RawCount), ROOT_TABLE_MAX_COUNT]));
  Count := Integer(RawCount);

  RecsEnd := Int64(ROOT_TABLE_RECORDS_OFS) +
    Int64(Count) * ROOT_TABLE_RECORD_SIZE;
  if RecsEnd > TableLen then
    BundleError(Format('%d records need %d bytes, the table has %d',
      [Count, RecsEnd, TableLen]));

  { The table is built field by field; on any error it must not escape: free
    it and re-raise, otherwise a malformed bundle leaks the table and every
    record decoded into it so far. }
  Result := TRootTable.Create;
  try
    Result.FData := Copy(ATable, 0, TableLen);
    Result.FVersion := ATable[ROOT_TABLE_HDR_VERSION_OFS];
    Result.FFlags := ATable[ROOT_TABLE_HDR_FLAGS_OFS];
    Result.FSnapshotUnixDays := ReadUInt32LE(ATable, ROOT_TABLE_HDR_DATE_OFS);
    Result.FDataSha256 := Copy(ATable, ROOT_TABLE_HDR_SHA256_OFS,
      ROOT_TABLE_SHA256_LEN);
    SetLength(Result.FEntries, Count);

    for I := 0 to Count - 1 do
    begin
      RecBase := Integer(ROOT_TABLE_RECORDS_OFS + Int64(I) * ROOT_TABLE_RECORD_SIZE);
      Rec := TRootEntry.Create;
      try
        Rec.FDerOffset := ReadUInt32LE(ATable, RecBase + ROOT_TABLE_REC_DEROFS_OFS);
        Rec.FDerLength := ReadUInt32LE(ATable, RecBase + ROOT_TABLE_REC_DERLEN_OFS);
        Rec.FSubjectHash := ReadUInt32LE(ATable, RecBase +
          ROOT_TABLE_REC_SUBJECTHASH_OFS);

        SkiFlag := ATable[RecBase + ROOT_TABLE_REC_SKIPRESENT_OFS];
        if (SkiFlag <> ROOT_TABLE_SKI_ABSENT) and
          (SkiFlag <> ROOT_TABLE_SKI_PRESENT) then
          BundleError(Format('record %d: bad skiPresent value %d', [I, SkiFlag]));
        Rec.FSkiPresent := SkiFlag = ROOT_TABLE_SKI_PRESENT;
        Rec.FSki := Copy(ATable, RecBase + ROOT_TABLE_REC_SKI_OFS,
          ROOT_TABLE_SKI_LEN);
        if not Rec.FSkiPresent then
        begin
          SkiZero := True;
          for J := 0 to ROOT_TABLE_SKI_LEN - 1 do
            if Rec.FSki[J] <> 0 then
              SkiZero := False;
          if not SkiZero then
            BundleError(Format('record %d: SKI must be zero when it is marked absent',
              [I]));
        end;

        Trust := ATable[RecBase + ROOT_TABLE_REC_TRUST_OFS];
        if (Trust and ROOT_TABLE_TRUST_UNKNOWN_MASK) <> 0 then
          BundleError(Format('record %d: unknown trust bits $%s', [I,
            IntToHex(Trust, 2)]));
        Rec.FTrust := Trust;

        if Rec.FDerLength = 0 then
          BundleError(Format('record %d: empty DER blob', [I]));
        if Rec.FDerLength > LongWord(ROOT_TABLE_MAX_DER_LEN) then
          BundleError(Format('record %d: DER blob of %u bytes exceeds the limit of %d',
            [I, Int64(Rec.FDerLength), ROOT_TABLE_MAX_DER_LEN]));

        DerStart := Rec.FDerOffset;
        if DerStart < RecsEnd then
          BundleError(Format('record %d: DER blob at %d overlaps the record area ' +
            'ending at %d', [I, DerStart, RecsEnd]));
        DerEnd := DerStart + Int64(Rec.FDerLength);
        if DerEnd > TableLen then
          BundleError(Format('record %d: DER blob %d..%d exceeds the table size %d',
            [I, DerStart, DerEnd, TableLen]));
      except
        Rec.Free;
        raise;
      end;
      Result.FEntries[I] := Rec;
    end;
  except
    Result.Free;
    Result := nil;
    raise;
  end;
end;

{ CertStoreFromTable }

function CertStoreFromTable(ATable: TRootTable;
  AIncludeDistrusted: Boolean): TCertStore;
var
  I: LongInt;
  Rec: TRootEntry;
  Cert: TX509Cert;
begin
  if ATable = nil then
    BundleError('cannot build a certificate store: no decoded table');

  Result := TCertStore.Create;
  try
    for I := 0 to ATable.Count - 1 do
    begin
      Rec := ATable.Entry(I);
      { A distrusted record is never a trust anchor: skip it before its DER
        blob is parsed, so a broken distrusted certificate cannot fail a
        bundle whose usable roots are all fine. }
      if Rec.Distrusted and not AIncludeDistrusted then
        Continue;

      try
        Cert := ParseCertificate(ATable.CertificateDer(I));
      except
        { The record offsets are already validated, so a parse failure means
          the DER blob itself is corrupt: report it with the record index
          instead of letting a bare EASN1Error escape from a bundle reader. }
        on E: EASN1Error do
          BundleError(Format('record %d: certificate cannot be parsed: %s',
            [I, E.Message]));
      end;
      Result.AddOwnedCert(Cert);
    end;
  except
    Result.Free;
    raise;
  end;
end;

{ BuildCertStore }

function BuildCertStore(const ATable: TBytes;
  AIncludeDistrusted: Boolean): TCertStore;
var
  Table: TRootTable;
begin
  Table := DecodeRootTable(ATable);
  try
    Result := CertStoreFromTable(Table, AIncludeDistrusted);
  finally
    Table.Free;
  end;
end;

end.
