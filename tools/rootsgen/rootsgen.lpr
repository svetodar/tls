{ SPDX-License-Identifier: Apache-2.0 }
program rootsgen;

{ Generator of the embedded root-certificate table (task 19,
  docs/tasks/19-embedded-roots.md).

  Standalone developer tool: it is not part of the test run and is never
  linked into the library. It turns the committed PEM snapshot into the
  binary table defined in src/tls.roottable.pas.

  Inputs:
    certs/roots.pem       one -----BEGIN CERTIFICATE----- block per root
    certs/roots.date      a single YYYY-MM-DD line: the snapshot date
    certs/distrusted.txt  SHA-256 fingerprints (hex) of roots marked
                          distrusted in Mozilla certdata.txt; '#' starts a
                          comment, the file may be absent or empty

  Outputs:
    build/roots/roots.bin   the DER table itself
    build/roots/tlsroots.rc the resource script: TLSROOTS RCDATA "<table>"
    src/tlsroots.res        the compiled resource that tls.roots pulls in
                            with the $R directive; fpcres builds it, so the
                            library needs no resource compiler at run time

  The tool is pure Pascal on top of this library (base64, DER, X.509,
  SHA-256): no openssl, no python, so `make roots` works on every host the
  library targets. The only external program it starts is fpcres, the FPC
  resource compiler; pass --fpcres PATH when it is not on PATH.

  Usage: rootsgen [--pem PATH] [--date PATH] [--distrusted PATH]
                  [--out PATH] [--rc PATH] [--res PATH] [--fpcres PATH]
                  [--help]
  Exit code: 0 on success, 1 on malformed input, on a write error or when
  fpcres fails. }

{$mode objfpc}{$H+}

uses
  Classes, Process, SysUtils,
  tls.asn1,      { EASN1Error }
  tls.roottable, { ROOT_TABLE_* format constants }
  tls.sha2,      { SHA256, TSHA256, BytesToHex }
  tls.x509;      { ParseCertificate, TX509Cert }

const
  { Default locations, relative to the repository root (make runs there). }
  DEFAULT_PEM_PATH = 'certs/roots.pem';
  DEFAULT_DATE_PATH = 'certs/roots.date';
  DEFAULT_DISTRUSTED_PATH = 'certs/distrusted.txt';
  DEFAULT_OUT_PATH = 'build/roots/roots.bin';
  DEFAULT_RC_PATH = 'build/roots/tlsroots.rc';
  DEFAULT_RES_PATH = 'src/tlsroots.res';
  DEFAULT_FPCRES = 'fpcres';

  { Name of the resource inside the .res file. src/tls.roots.pas pulls that
    same resource in with its own compiler directive, so keep the two names
    in sync. }
  RC_RESOURCE_NAME = 'TLSROOTS';

  { fpcres output format: the FPC "res" stream, which the resource reader of
    both the Windows and the Unix targets understands. }
  RC_RES_OUTPUT_FORMAT = 'res';

  { Surrounding markers of one PEM block; the base64 text sits between them. }
  PEM_BEGIN = '-----BEGIN CERTIFICATE-----';
  PEM_END = '-----END CERTIFICATE-----';

  { FNV-1a, 32 bit. subjectHash is a lookup hint in the table, not a security
    boundary, so a fast non-cryptographic hash is enough; it only has to be
    computed identically by every producer of the table. }
  SUBJECT_HASH_BASIS = LongWord(2166136261);
  SUBJECT_HASH_PRIME = LongWord(16777619);

  { A SHA-256 fingerprint is 64 hex digits. }
  FINGERPRINT_HEX_LEN = 64;

type
  { Typed error for malformed input (bad PEM, bad date, bad fingerprint) and
    for write failures: the tool exits non-zero instead of emitting a table
    that would not decode. }
  ERootsGenError = class(Exception);

  { One root on its way into the table. }
  TRootGenEntry = record
    Der: TBytes;       { DER certificate, stored verbatim }
    DerSha256: TBytes; { SHA-256 of Der: the pointer in the distrusted list
                         and the final tie-break of the record order }
    Subject: string;   { canonical subject name, for the report only }
    SubjectHash: LongWord;
    Ski: TBytes;       { exactly ROOT_TABLE_SKI_LEN bytes, zero when absent }
    SkiPresent: Boolean;
    Trust: Byte;       { ROOT_TABLE_TRUST_* mask }
  end;
  TRootGenEntries = array of TRootGenEntry;

  { Base64 texts of the PEM blocks, in file order. }
  TRawStrings = array of RawByteString;

{ --- Small helpers --- }

procedure Warn(const AMessage: string);
begin
  WriteLn(StdErr, 'rootsgen: warning: ', AMessage);
end;

{ 1-based position of ANeedle in AHaystack at or after AStart, 0 when absent.
  PosEx is not available on every FPC target (see AGENTS.md). }
function FindFrom(const AHaystack, ANeedle: RawByteString;
  AStart: SizeInt): SizeInt;
var
  I, Last: SizeInt;
begin
  Result := 0;
  if (ANeedle = '') or (AStart < 1) then
    Exit;
  Last := Length(AHaystack) - Length(ANeedle) + 1;
  I := AStart;
  while I <= Last do
  begin
    if (AHaystack[I] = ANeedle[1]) and
      (Copy(AHaystack, I, Length(ANeedle)) = ANeedle) then
    begin
      Result := I;
      Exit;
    end;
    Inc(I);
  end;
end;

{ Whole file as bytes; errors are reported with the path. }
function ReadWholeFile(const APath: string): RawByteString;
var
  Stream: TFileStream;
  Size: Int64;
begin
  try
    Stream := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
  except
    on E: Exception do
      raise ERootsGenError.CreateFmt('cannot open %s: %s', [APath, E.Message]);
  end;
  try
    Size := Stream.Size;
    if Size > High(LongInt) then
      raise ERootsGenError.CreateFmt('%s: file of %d bytes is too large',
        [APath, Size]);
    SetLength(Result, Size);
    if Size > 0 then
      Stream.ReadBuffer(Result[1], Size);
  finally
    Stream.Free;
  end;
end;

{ Base64 digit value, -1 for anything outside the alphabet. }
function Base64Value(AChar: Char): Integer;
begin
  case AChar of
    'A'..'Z': Result := Ord(AChar) - Ord('A');
    'a'..'z': Result := Ord(AChar) - Ord('a') + 26;
    '0'..'9': Result := Ord(AChar) - Ord('0') + 52;
    '+': Result := 62;
    '/': Result := 63;
  else
    Result := -1;
  end;
end;

{ Strict base64 decoder for the text of one PEM block: whitespace is dropped,
  the padding must be a single '=' or '==' at the very end, and every other
  character must belong to the alphabet. Raises ERootsGenError. }
function Base64DecodeStrict(const AText: RawByteString): TBytes;
var
  S: RawByteString;
  I, J, OutLen, Padding, K, N: LongInt;
  V: array[0..3] of LongInt;
  C: Char;
  Triple: LongInt;
begin
  { Line breaks in PEM are formatting, not data. }
  SetLength(S, Length(AText));
  J := 0;
  for I := 1 to Length(AText) do
    if not (AText[I] in [' ', #9, #10, #13]) then
    begin
      Inc(J);
      S[J] := AText[I];
    end;
  SetLength(S, J);

  if S = '' then
    raise ERootsGenError.Create('PEM: empty certificate block');
  if Length(S) mod 4 <> 0 then
    raise ERootsGenError.CreateFmt(
      'base64: text length %d is not a multiple of 4', [Length(S)]);

  SetLength(Result, (Length(S) div 4) * 3);
  OutLen := 0;
  I := 1;
  while I <= Length(S) do
  begin
    V[0] := 0;
    V[1] := 0;
    V[2] := 0;
    V[3] := 0;
    Padding := 0;
    for K := 0 to 3 do
    begin
      C := S[I + K];
      if C = '=' then
      begin
        { Padding is only legal at the end of the text, never in the first
          two positions of a quartet. }
        if (I + 3 <> Length(S)) or (K < 2) then
          raise ERootsGenError.Create('base64: misplaced padding');
        Inc(Padding);
        Continue;
      end;
      if Padding > 0 then
        raise ERootsGenError.Create('base64: data after padding');
      N := Base64Value(C);
      if N < 0 then
        raise ERootsGenError.CreateFmt('base64: invalid character #%d',
          [Ord(C)]);
      V[K] := N;
    end;

    Triple := (V[0] shl 18) or (V[1] shl 12) or (V[2] shl 6) or V[3];
    Result[OutLen] := Byte(Triple shr 16);
    Inc(OutLen);
    if Padding < 2 then
    begin
      Result[OutLen] := Byte(Triple shr 8);
      Inc(OutLen);
    end;
    if Padding < 1 then
    begin
      Result[OutLen] := Byte(Triple);
      Inc(OutLen);
    end;
    Inc(I, 4);
  end;
  SetLength(Result, OutLen);
end;

{ Split the PEM snapshot into the base64 texts of its certificate blocks.
  Text outside the markers (comments, blank lines) is ignored; a missing
  -----END CERTIFICATE----- is an error, because the rest of the file cannot
  be trusted to be block-aligned afterwards. }
function ExtractPEMBlocks(const APEM: RawByteString): TRawStrings;
var
  P, Q: SizeInt;
  Blocks: LongInt;
begin
  Result := nil;
  Blocks := 0;
  P := 1;
  while True do
  begin
    P := FindFrom(APEM, PEM_BEGIN, P);
    if P = 0 then
      Break;
    Inc(P, Length(PEM_BEGIN));
    Q := FindFrom(APEM, PEM_END, P);
    if Q = 0 then
      raise ERootsGenError.CreateFmt(
        'PEM: certificate block opened at byte %d is not terminated', [P]);
    Inc(Blocks);
    SetLength(Result, Blocks);
    Result[Blocks - 1] := Copy(APEM, P, Q - P);
    P := Q + Length(PEM_END);
  end;
end;

{ Lower-case, with every run of blanks collapsed to one space and the ends
  trimmed: the canonical form of a subject name that subjectHash is computed
  over. Chain building compares names after the same normalisation, so this
  function is a copy of tls.certstore.CanonicalSubjectName kept local to keep
  the tool free of the store unit; the two must stay identical. }
function CanonicalSubjectName(const AName: string): string;
var
  I: LongInt;
  PendingBlank: Boolean;
begin
  Result := '';
  PendingBlank := False;
  for I := 1 to Length(AName) do
  begin
    if AName[I] in [' ', #9, #10, #13] then
    begin
      { A blank is only kept once something preceded it: this also drops the
        leading and trailing ones. }
      if Result <> '' then
        PendingBlank := True;
      Continue;
    end;
    if PendingBlank then
    begin
      Result := Result + ' ';
      PendingBlank := False;
    end;
    Result := Result + LowerCase(AName[I]);
  end;
end;

{ FNV-1a over the canonical subject name; see SUBJECT_HASH_BASIS. }
function SubjectHashOf(const ACanonicalName: string): LongWord;
var
  I: LongInt;
begin
  Result := SUBJECT_HASH_BASIS;
  for I := 1 to Length(ACanonicalName) do
  begin
    Result := Result xor LongWord(Ord(ACanonicalName[I]));
    Result := Result * SUBJECT_HASH_PRIME;
  end;
end;

{ "2026-10-22" → Unix days as stored in the table header. Strict: exactly one
  YYYY-MM-DD line and a real calendar date. }
function ParseSnapshotDate(const AText, APath: string): LongWord;
var
  S: string;
  I: LongInt;
  Year, Month, Day: Word;
  Date: TDateTime;
begin
  S := Trim(AText);
  if Length(S) <> 10 then
    raise ERootsGenError.CreateFmt(
      '%s: expected one YYYY-MM-DD line, got "%s"', [APath, S]);
  for I := 1 to Length(S) do
    if (I <> 5) and (I <> 8) and not (S[I] in ['0'..'9']) then
      raise ERootsGenError.CreateFmt(
        '%s: expected one YYYY-MM-DD line, got "%s"', [APath, S]);
  if (S[5] <> '-') or (S[8] <> '-') then
    raise ERootsGenError.CreateFmt(
      '%s: expected one YYYY-MM-DD line, got "%s"', [APath, S]);

  Year := StrToInt(Copy(S, 1, 4));
  Month := StrToInt(Copy(S, 6, 2));
  Day := StrToInt(Copy(S, 9, 2));
  if not TryEncodeDate(Year, Month, Day, Date) then
    raise ERootsGenError.CreateFmt('%s: "%s" is not a calendar date',
      [APath, S]);
  if Trunc(Date) < ROOT_TABLE_UNIX_EPOCH_DAYS then
    raise ERootsGenError.CreateFmt('%s: "%s" is before 1970-01-01',
      [APath, S]);
  Result := LongWord(Trunc(Date) - ROOT_TABLE_UNIX_EPOCH_DAYS);
end;

{ The Unix days of the header back to YYYY-MM-DD, for the report. }
function UnixDaysToText(AUnixDays: LongWord): string;
begin
  Result := FormatDateTime('yyyy-mm-dd',
    AUnixDays + ROOT_TABLE_UNIX_EPOCH_DAYS);
end;

{ One line of certs/distrusted.txt → 64 lower-case hex digits, or '' for a
  blank/comment line. Colons and blanks inside a fingerprint (the shapes
  openssl prints) are accepted; any other character is an error. }
function NormalizeFingerprint(const ALine: string): string;
var
  I: LongInt;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(ALine) do
  begin
    C := ALine[I];
    case C of
      '0'..'9', 'a'..'f': Result := Result + C;
      'A'..'F': Result := Result + LowerCase(C);
      ':', ' ', #9, #13: ; { separators }
    else
      raise ERootsGenError.CreateFmt('unexpected character "%s" in a ' +
        'fingerprint', [C]);
    end;
  end;
end;

{ Fingerprints of the roots that must never be used as trust anchors. A
  missing file means "no distrusted roots"; a malformed line is an error,
  because silently ignoring it would silently trust a distrusted CA. }
function LoadDistrustedFingerprints(const APath: string): TStringList;
var
  Raw: TStringList;
  I, HashPos: LongInt;
  Line: string;
begin
  Result := TStringList.Create;
  Result.Sorted := True;
  Result.Duplicates := dupIgnore;
  if not FileExists(APath) then
    Exit;
  Raw := TStringList.Create;
  try
    try
      Raw.LoadFromFile(APath);
    except
      on E: Exception do
        raise ERootsGenError.CreateFmt('cannot read %s: %s',
          [APath, E.Message]);
    end;
    for I := 0 to Raw.Count - 1 do
    begin
      Line := Raw[I];
      HashPos := Pos('#', Line);
      if HashPos > 0 then
        Line := Copy(Line, 1, HashPos - 1);
      Line := NormalizeFingerprint(Line);
      if Line = '' then
        Continue;
      if Length(Line) <> FINGERPRINT_HEX_LEN then
        raise ERootsGenError.CreateFmt('%s: line %d: a SHA-256 fingerprint ' +
          'has %d hex digits, got %d', [APath, I + 1, FINGERPRINT_HEX_LEN,
          Length(Line)]);
      Result.Add(Line);
    end;
  finally
    Raw.Free;
  end;
end;

{ Read the PEM snapshot and turn every block into a table entry: DER bytes,
  subject hash, SKI and trust bits. Errors name the block, so a broken
  certificate in the snapshot is easy to find. }
function LoadEntries(const APath: string;
  ADistrusted: TStringList): TRootGenEntries;
var
  Blocks: TRawStrings;
  I, Count: LongInt;
  Der: TBytes;
  Cert: TX509Cert;
  Ski: TBytes;
  Fingerprint: string;
begin
  Result := nil;
  Blocks := ExtractPEMBlocks(ReadWholeFile(APath));
  if Length(Blocks) = 0 then
    raise ERootsGenError.CreateFmt('%s: no "%s" block found',
      [APath, PEM_BEGIN]);

  SetLength(Result, Length(Blocks));
  Count := 0;
  for I := 0 to High(Blocks) do
  begin
    Der := Base64DecodeStrict(Blocks[I]);
    if Length(Der) = 0 then
      raise ERootsGenError.CreateFmt('%s: block %d: empty DER',
        [APath, I + 1]);
    { The reader rejects longer blobs, so do not write them in the first
      place. }
    if Length(Der) > ROOT_TABLE_MAX_DER_LEN then
      raise ERootsGenError.CreateFmt(
        '%s: block %d: %d-byte DER exceeds the table limit of %d bytes',
        [APath, I + 1, Length(Der), ROOT_TABLE_MAX_DER_LEN]);

    try
      Cert := ParseCertificate(Der);
    except
      on E: EASN1Error do
        raise ERootsGenError.CreateFmt('%s: block %d: %s',
          [APath, I + 1, E.Message]);
    end;
    try
      Result[Count].Der := Der;
      Result[Count].Subject := CanonicalSubjectName(Cert.Subject.ToNameString);
      Result[Count].SubjectHash := SubjectHashOf(Result[Count].Subject);

      { The record has room for exactly one SHA-1 sized SKI (RFC 5280
        §4.2.1.2, 20 bytes). A root whose SKI has any other length is stored
        as absent: a padded or truncated copy could never match an AKI. }
      Ski := Cert.GetSubjectKeyIdentifier;
      Result[Count].SkiPresent := Length(Ski) = ROOT_TABLE_SKI_LEN;
      SetLength(Result[Count].Ski, ROOT_TABLE_SKI_LEN);
      FillChar(Result[Count].Ski[0], ROOT_TABLE_SKI_LEN, 0);
      if Result[Count].SkiPresent then
        Move(Ski[0], Result[Count].Ski[0], ROOT_TABLE_SKI_LEN)
      else if Length(Ski) > 0 then
        Warn(Format('%s: SKI is %d bytes, stored as absent',
          [Result[Count].Subject, Length(Ski)]));

      { Mozilla trust bits live in certdata.txt, which this snapshot does not
        carry: every root in certifi's bundle is a web root, and the
        distrusted ones are listed in certs/distrusted.txt. The digest is
        kept: the table order uses it as its final key. }
      Result[Count].DerSha256 := SHA256(Der);
      if Length(Result[Count].DerSha256) <> ROOT_TABLE_SHA256_LEN then
        raise ERootsGenError.CreateFmt('SHA-256 produced %d bytes, expected %d',
          [Length(Result[Count].DerSha256), ROOT_TABLE_SHA256_LEN]);
      Fingerprint := BytesToHex(Result[Count].DerSha256);
      if ADistrusted.IndexOf(Fingerprint) >= 0 then
        Result[Count].Trust := ROOT_TABLE_TRUST_DISTRUSTED
      else
        Result[Count].Trust := ROOT_TABLE_TRUST_WEB;

      Inc(Count);
    finally
      Cert.Free;
    end;
  end;
  SetLength(Result, Count);
end;

{ Lexicographic order of two SHA-256 digests: <0, 0, >0. }
function CompareDigests(const A, B: TBytes): Integer;
var
  I, N: LongInt;
begin
  N := Length(A);
  if Length(B) < N then
    N := Length(B);
  for I := 0 to N - 1 do
    if A[I] <> B[I] then
    begin
      if A[I] < B[I] then
        Exit(-1)
      else
        Exit(1);
    end;
  if Length(A) < Length(B) then
    Exit(-1);
  if Length(A) > Length(B) then
    Exit(1);
  Result := 0;
end;

{ The record order: subjectHash first (it groups the entries the way
  TCertStore's subject index will), then SHA-256 of the DER blob, so that the
  order does not depend on the order of the PEM blocks. }
function CompareEntries(const A, B: TRootGenEntry): Integer;
begin
  if A.SubjectHash < B.SubjectHash then
    Exit(-1);
  if A.SubjectHash > B.SubjectHash then
    Exit(1);
  Result := CompareDigests(A.DerSha256, B.DerSha256);
end;

{ Deterministic record order, so that the same inputs always produce a
  byte-identical table and a byte-identical dataSha256. Insertion sort is
  stable, so two byte-identical certificates keep their PEM order as the
  final tie-break; a snapshot holds a few hundred roots, so the quadratic
  comparison count is irrelevant. }
procedure OrderEntries(var AEntries: TRootGenEntries);
var
  I, J: LongInt;
  Key: TRootGenEntry;
begin
  for I := 1 to High(AEntries) do
  begin
    Key := AEntries[I];
    J := I;
    while (J > 0) and (CompareEntries(AEntries[J - 1], Key) > 0) do
    begin
      AEntries[J] := AEntries[J - 1];
      Dec(J);
    end;
    AEntries[J] := Key;
  end;
end;

procedure PutUInt32LE(var ABuf: TBytes; AOffset: LongInt; AValue: LongWord);
begin
  ABuf[AOffset] := Byte(AValue and $FF);
  ABuf[AOffset + 1] := Byte((AValue shr 8) and $FF);
  ABuf[AOffset + 2] := Byte((AValue shr 16) and $FF);
  ABuf[AOffset + 3] := Byte((AValue shr 24) and $FF);
end;

{ Serialise the table exactly as src/tls.roottable.pas decodes it: fixed
  header, all records, then the DER blobs back to back. The SHA-256 of the
  payload is written last, once every byte it covers is in place. }
function BuildTable(const AEntries: TRootGenEntries;
  ASnapshotUnixDays: LongWord): TBytes;
var
  I, RecBase, DerPos: LongInt;
  PayloadLen, TotalLen: Int64;
  Hasher: TSHA256;
  Digest: TBytes;
begin
  if Length(AEntries) = 0 then
    raise ERootsGenError.Create('refusing to write a table without roots');
  if Length(AEntries) > ROOT_TABLE_MAX_COUNT then
    raise ERootsGenError.CreateFmt('%d roots exceed the table limit of %d',
      [Length(AEntries), ROOT_TABLE_MAX_COUNT]);

  PayloadLen := Int64(Length(AEntries)) * ROOT_TABLE_RECORD_SIZE;
  for I := 0 to High(AEntries) do
    Inc(PayloadLen, Length(AEntries[I].Der));
  TotalLen := Int64(ROOT_TABLE_HEADER_SIZE) + PayloadLen;
  { Every offset in the table is a 32-bit field and the reader works on
    LongInt offsets, so a table above 2 GB could not be described. }
  if TotalLen > High(LongInt) then
    raise ERootsGenError.CreateFmt('the table would be %d bytes, above the ' +
      '2 GB limit', [TotalLen]);

  SetLength(Result, TotalLen);
  FillChar(Result[0], TotalLen, 0);

  for I := 1 to ROOT_TABLE_MAGIC_LEN do
    Result[ROOT_TABLE_HDR_MAGIC_OFS + I - 1] := Byte(Ord(ROOT_TABLE_MAGIC[I]));
  Result[ROOT_TABLE_HDR_VERSION_OFS] := ROOT_TABLE_VERSION;
  Result[ROOT_TABLE_HDR_FLAGS_OFS] := 0;
  PutUInt32LE(Result, ROOT_TABLE_HDR_COUNT_OFS, LongWord(Length(AEntries)));
  PutUInt32LE(Result, ROOT_TABLE_HDR_DATE_OFS, ASnapshotUnixDays);

  DerPos := ROOT_TABLE_RECORDS_OFS + Length(AEntries) * ROOT_TABLE_RECORD_SIZE;
  for I := 0 to High(AEntries) do
  begin
    RecBase := ROOT_TABLE_RECORDS_OFS + I * ROOT_TABLE_RECORD_SIZE;
    PutUInt32LE(Result, RecBase + ROOT_TABLE_REC_DEROFS_OFS,
      LongWord(DerPos));
    PutUInt32LE(Result, RecBase + ROOT_TABLE_REC_DERLEN_OFS,
      LongWord(Length(AEntries[I].Der)));
    PutUInt32LE(Result, RecBase + ROOT_TABLE_REC_SUBJECTHASH_OFS,
      AEntries[I].SubjectHash);
    if AEntries[I].SkiPresent then
      Result[RecBase + ROOT_TABLE_REC_SKIPRESENT_OFS] := ROOT_TABLE_SKI_PRESENT
    else
      Result[RecBase + ROOT_TABLE_REC_SKIPRESENT_OFS] := ROOT_TABLE_SKI_ABSENT;
    Move(AEntries[I].Ski[0], Result[RecBase + ROOT_TABLE_REC_SKI_OFS],
      ROOT_TABLE_SKI_LEN);
    Result[RecBase + ROOT_TABLE_REC_TRUST_OFS] := AEntries[I].Trust;

    Move(AEntries[I].Der[0], Result[DerPos], Length(AEntries[I].Der));
    Inc(DerPos, Length(AEntries[I].Der));
  end;

  Hasher := TSHA256.Create;
  try
    Hasher.Update(Result, ROOT_TABLE_PAYLOAD_OFS, PayloadLen);
    Hasher.Final(Digest);
  finally
    Hasher.Free;
  end;
  if Length(Digest) <> ROOT_TABLE_SHA256_LEN then
    raise ERootsGenError.CreateFmt('SHA-256 produced %d bytes, expected %d',
      [Length(Digest), ROOT_TABLE_SHA256_LEN]);
  Move(Digest[0], Result[ROOT_TABLE_HDR_SHA256_OFS], ROOT_TABLE_SHA256_LEN);
end;

{ Create the directory a generated file lives in; --out and --rc may point
  into a directory that does not exist yet (build/roots on a fresh clone). }
procedure EnsureParentDirectory(const APath: string);
var
  Dir: string;
begin
  Dir := ExtractFileDir(ExpandFileName(APath));
  if (Dir <> '') and not ForceDirectories(Dir) then
    raise ERootsGenError.CreateFmt('cannot create the directory %s', [Dir]);
end;

procedure SaveFile(const APath: string; const AData: TBytes);
var
  Stream: TFileStream;
begin
  EnsureParentDirectory(APath);
  try
    Stream := TFileStream.Create(APath, fmCreate);
  except
    on E: Exception do
      raise ERootsGenError.CreateFmt('cannot create %s: %s',
        [APath, E.Message]);
  end;
  try
    if Length(AData) > 0 then
      Stream.WriteBuffer(AData[0], Length(AData));
  finally
    Stream.Free;
  end;
end;

{ Byte-for-byte text output: no BOM, no line-ending translation, so the .rc is
  identical on every host and two runs on the same inputs produce the same
  bytes. }
procedure SaveTextFile(const APath, AText: RawByteString);
var
  Stream: TFileStream;
begin
  EnsureParentDirectory(APath);
  try
    Stream := TFileStream.Create(APath, fmCreate);
  except
    on E: Exception do
      raise ERootsGenError.CreateFmt('cannot create %s: %s',
        [APath, E.Message]);
  end;
  try
    if Length(AText) > 0 then
      Stream.WriteBuffer(AText[1], Length(AText));
  finally
    Stream.Free;
  end;
end;

{ Size of a file in bytes; used for the report only. }
function FileSizeBytes(const APath: string): Int64;
var
  Stream: TFileStream;
begin
  Stream := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
  try
    Result := Stream.Size;
  finally
    Stream.Free;
  end;
end;

{ The table path as the .rc must spell it. fpcres resolves a relative data
  file against the directory of the .rc file, not against the working
  directory, so a table that sits next to the script is named by its base name
  and anything else by a relative path. '/' separators are accepted on every
  host (the Windows C runtime takes them too). }
function RcDataFileName(const ADataPath, ARcPath: string): string;
var
  DataFull, RcDir: string;
begin
  DataFull := ExpandFileName(ADataPath);
  RcDir := ExtractFileDir(ExpandFileName(ARcPath));
  if SameFileName(ExtractFileDir(DataFull), RcDir) then
    Result := ExtractFileName(DataFull)
  else
    { Different directories (or even drives): ExtractRelativePath falls back
      to the absolute name when no relative one exists. }
    Result := ExtractRelativePath(IncludeTrailingPathDelimiter(RcDir), DataFull);
  Result := StringReplace(Result, '\', '/', [rfReplaceAll]);
end;

{ The resource script that fpcres compiles. One RCDATA resource: the binary
  table is not text, so it must not go through any preprocessing. }
function BuildRcText(const ADataFileName: string): RawByteString;
begin
  Result := RC_RESOURCE_NAME + ' RCDATA "' + ADataFileName + '"' + #10;
end;

{ Everything the child wrote; fpcres reports errors on stderr and we merge the
  two streams, so one reader is enough. The volume is a line or two, far below
  the pipe buffer. }
function ReadPipeToEnd(AStream: TStream): RawByteString;
var
  Buf: array[0..4095] of Byte;
  N: LongInt;
  Chunk: RawByteString;
begin
  Result := '';
  repeat
    N := AStream.Read(Buf[0], SizeOf(Buf));
    if N > 0 then
    begin
      SetLength(Chunk, N);
      Move(Buf[0], Chunk[1], N);
      Result := Result + Chunk;
    end;
  until N <= 0;
end;

{ Compile the .rc into the .res with fpcres. A non-zero exit code or a missing
  output file is an error: the library would then be built without the table
  the task promises, so there is no silent fallback. }
procedure RunFpcRes(const AExecutable, ARcPath, AResPath: string);
var
  Proc: TProcess;
  Output: RawByteString;
begin
  { fpcres will not create the directory it writes into. }
  EnsureParentDirectory(AResPath);
  Proc := TProcess.Create(nil);
  try
    Proc.Executable := AExecutable;
    Proc.Parameters.Add(ARcPath);
    Proc.Parameters.Add('-o');
    Proc.Parameters.Add(AResPath);
    Proc.Parameters.Add('-of');
    Proc.Parameters.Add(RC_RES_OUTPUT_FORMAT);
    { Merge stderr into stdout so a failure message reaches the user. }
    Proc.Options := [poUsePipes, poStderrToOutPut];
    try
      Proc.Execute;
    except
      on E: Exception do
        raise ERootsGenError.CreateFmt('cannot run %s: %s ' +
          '(install FPC''s fpcres or pass --fpcres PATH)',
          [AExecutable, E.Message]);
    end;
    { Blocks until the child closes its end of the pipe: fpcres needs no
      input from us. The pipe can reach EOF a moment before the process is
      fully reaped, and ExitStatus is only valid after that; without the
      WaitOnExit a fast fpcres intermittently reports -1 despite succeeding. }
    Output := ReadPipeToEnd(Proc.Output);
    Proc.WaitOnExit;
    if Proc.ExitStatus <> 0 then
      raise ERootsGenError.CreateFmt('%s failed with exit code %d: %s',
        [AExecutable, Proc.ExitStatus, Trim(Output)]);
  finally
    Proc.Free;
  end;

  if not FileExists(AResPath) then
    raise ERootsGenError.CreateFmt('%s reported success but %s is missing',
      [AExecutable, AResPath]);
end;

procedure WriteUsage;
begin
  WriteLn('rootsgen — build the embedded root-certificate table');
  WriteLn;
  WriteLn('Usage: rootsgen [options]');
  WriteLn('  --pem PATH         PEM snapshot (default: ' + DEFAULT_PEM_PATH + ')');
  WriteLn('  --date PATH        snapshot date file (default: ' +
    DEFAULT_DATE_PATH + ')');
  WriteLn('  --distrusted PATH  distrusted fingerprints (default: ' +
    DEFAULT_DISTRUSTED_PATH + ')');
  WriteLn('  --out PATH         output table (default: ' + DEFAULT_OUT_PATH +
    ')');
  WriteLn('  --rc PATH          resource script (default: ' + DEFAULT_RC_PATH +
    ')');
  WriteLn('  --res PATH         compiled resource (default: ' +
    DEFAULT_RES_PATH + ')');
  WriteLn('  --fpcres PATH      resource compiler (default: ' + DEFAULT_FPCRES +
    ', searched on PATH)');
  WriteLn('  -h, --help         this text');
  WriteLn;
  WriteLn('The table format is described in src/tls.roottable.pas; the');
  WriteLn('.rc script names the ' + RC_RESOURCE_NAME + ' RCDATA resource that');
  WriteLn('src/tls.roots.pas includes with {$R}.');
end;

{ Value of an option that takes an argument: "rootsgen --pem FILE". }
function OptionValue(const AName: string; var AIndex: LongInt): string;
begin
  if AIndex >= ParamCount then
    raise ERootsGenError.CreateFmt('%s needs a value', [AName]);
  Inc(AIndex);
  Result := ParamStr(AIndex);
end;

var
  I: LongInt;
  Arg: string;
  PEMPath, DatePath, DistrustedPath: string;
  OutPath, RcPath, ResPath, FpcResPath: string;
  RcText: RawByteString;
  Entries: TRootGenEntries;
  Distrusted: TStringList;
  SnapshotUnixDays: LongWord;
  Table: TBytes;
  DerBytes, SkiAbsent, DistrustedCount: LongInt;
begin
  PEMPath := DEFAULT_PEM_PATH;
  DatePath := DEFAULT_DATE_PATH;
  DistrustedPath := DEFAULT_DISTRUSTED_PATH;
  OutPath := DEFAULT_OUT_PATH;
  RcPath := DEFAULT_RC_PATH;
  ResPath := DEFAULT_RES_PATH;
  FpcResPath := DEFAULT_FPCRES;

  try
    I := 1;
    while I <= ParamCount do
    begin
      Arg := ParamStr(I);
      if (Arg = '-h') or (Arg = '--help') or (Arg = '/?') then
      begin
        WriteUsage;
        Exit;
      end
      else if Arg = '--pem' then
        PEMPath := OptionValue(Arg, I)
      else if Arg = '--date' then
        DatePath := OptionValue(Arg, I)
      else if Arg = '--distrusted' then
        DistrustedPath := OptionValue(Arg, I)
      else if Arg = '--out' then
        OutPath := OptionValue(Arg, I)
      else if Arg = '--rc' then
        RcPath := OptionValue(Arg, I)
      else if Arg = '--res' then
        ResPath := OptionValue(Arg, I)
      else if Arg = '--fpcres' then
        FpcResPath := OptionValue(Arg, I)
      else
        raise ERootsGenError.CreateFmt('unknown argument "%s" (try --help)',
          [Arg]);
      Inc(I);
    end;

    SnapshotUnixDays := ParseSnapshotDate(ReadWholeFile(DatePath), DatePath);
    Distrusted := LoadDistrustedFingerprints(DistrustedPath);
    try
      Entries := LoadEntries(PEMPath, Distrusted);
    finally
      Distrusted.Free;
    end;
    if Length(Entries) = 0 then
      raise ERootsGenError.CreateFmt('%s: no certificates loaded', [PEMPath]);

    OrderEntries(Entries);
    Table := BuildTable(Entries, SnapshotUnixDays);
    SaveFile(OutPath, Table);

    { The .rc is generated next to the table and points at it, so the pair can
      be inspected by hand; fpcres then compiles it into the .res that
      tls.roots includes. }
    RcText := BuildRcText(RcDataFileName(OutPath, RcPath));
    SaveTextFile(RcPath, RcText);
    RunFpcRes(FpcResPath, RcPath, ResPath);

    DerBytes := 0;
    SkiAbsent := 0;
    DistrustedCount := 0;
    for I := 0 to High(Entries) do
    begin
      Inc(DerBytes, Length(Entries[I].Der));
      if not Entries[I].SkiPresent then
        Inc(SkiAbsent);
      if (Entries[I].Trust and ROOT_TABLE_TRUST_DISTRUSTED) <> 0 then
        Inc(DistrustedCount);
    end;

    WriteLn(Format('rootsgen: %d roots (%d distrusted, %d without SKI), ' +
      '%d bytes of DER',
      [Length(Entries), DistrustedCount, SkiAbsent, DerBytes]));
    WriteLn(Format('rootsgen: snapshot %s (Unix days %d)',
      [UnixDaysToText(SnapshotUnixDays), Int64(SnapshotUnixDays)]));
    WriteLn(Format('rootsgen: dataSha256 %s',
      [BytesToHex(Copy(Table, ROOT_TABLE_HDR_SHA256_OFS,
        ROOT_TABLE_SHA256_LEN))]));
    WriteLn(Format('rootsgen: wrote %s (%d bytes)',
      [OutPath, Int64(Length(Table))]));
    WriteLn(Format('rootsgen: wrote %s (%d bytes)',
      [RcPath, Int64(Length(RcText))]));
    WriteLn(Format('rootsgen: wrote %s (%d bytes)',
      [ResPath, FileSizeBytes(ResPath)]));
  except
    on E: Exception do
    begin
      WriteLn(StdErr, 'rootsgen: error: ', E.Message);
      Halt(1);
    end;
  end;
end.
