unit test_asn1;

{ Tests for DER/ASN.1 parser (tls.asn1): ParseDER, EncodeDER, ReadOID,
  ReadTime, ReadInteger, edge cases (truncation, indefinite length,
  multi-byte tags, empty structures, recursion). }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TASN1Tests = class(TTestCase)
  published
    procedure TestParseBool;
    procedure TestParseNull;
    procedure TestParseOctetString;
    procedure TestParseOctetEmpty;
    procedure TestParseInteger;
    procedure TestParseBitString;
    procedure TestParseStrings;
    procedure TestParseSequence;
    procedure TestParseSequenceEmpty;
    procedure TestParseSet;
    procedure TestParseNested;
    procedure TestParseContextSpecific;
    procedure TestParseContextConstructed;
    procedure TestParseApplication;
    procedure TestParseTruncated;
    procedure TestParseTruncated2;
    procedure TestParseIndefiniteLength;
    procedure TestParseSingleByte;
    procedure TestParseExtraBytes;
    procedure TestParseEmptyBuffer;
    procedure TestParseRealCert;
    procedure TestParseOpenSSLCert;
    procedure TestEncodeRoundTrip;
    procedure TestEncodePrimitives;
    procedure TestEncodeLongLength;
    procedure TestEncodeMultiByteTag;
    procedure TestReadOID;
    procedure TestReadOIDError;
    procedure TestReadUTCTime;
    procedure TestReadGeneralizedTime;
    procedure TestReadTimeError;
    procedure TestReadInteger;
    procedure TestReadIntegerError;
    procedure TestUniversalTagOf;
    procedure TestTagName;
    procedure TestToDebugString;
  end;

implementation

uses
  SysUtils, Classes, DateUtils,
  tls.asn1, tls.bn;

function LoadFixture(const Name: string): TBytes;
var
  fs: TFileStream;
  path: string;
begin
  path := ExtractFilePath(ParamStr(0)) + '..' + PathDelim + 'tests' + PathDelim + 'fixtures' + PathDelim + Name;
  if not FileExists(path) then
    path := 'tests' + PathDelim + 'fixtures' + PathDelim + Name;
  fs := TFileStream.Create(path, fmOpenRead);
  try
    fs.Position := 0;
    Result := nil;
    SetLength(Result, fs.Size);
    if fs.Size > 0 then
      fs.ReadBuffer(Result[0], fs.Size);
  finally
    fs.Free;
  end;
end;

function MakeIntNode(const D: TBytes): TASN1Node;
begin
  Result := TASN1Node.Create(tcUniversal, Ord(atInteger), False);
  Result.Data := D;
end;

function MakeOIDNode(const D: TBytes): TASN1Node;
begin
  Result := TASN1Node.Create(tcUniversal, Ord(atObjectIdentifier), False);
  Result.Data := D;
end;

function MakeUTCTimeNode(const S: string): TASN1Node;
var
  i: LongInt;
  d: TBytes;
begin
  Result := TASN1Node.Create(tcUniversal, Ord(atUTCTime), False);
  SetLength(d, Length(S));
  for i := 1 to Length(S) do
    d[i - 1] := Ord(S[i]);
  Result.Data := d;
end;

function MakeGTNode(const S: string): TASN1Node;
var
  i: LongInt;
  d: TBytes;
begin
  Result := TASN1Node.Create(tcUniversal, Ord(atGeneralizedTime), False);
  SetLength(d, Length(S));
  for i := 1 to Length(S) do
    d[i - 1] := Ord(S[i]);
  Result.Data := d;
end;

function BytesEqual(A, B: TBytes): Boolean;
var
  i: LongInt;
begin
  if Length(A) <> Length(B) then Exit(False);
  for i := 0 to High(A) do
    if A[i] <> B[i] then Exit(False);
  Result := True;
end;
function BytesToStr(const B: TBytes): string;
var
  i: LongInt;
begin
  SetLength(Result, Length(B));
  for i := 0 to High(B) do
    Result[i + 1] := Char(B[i]);
end;


{--- ParseDER: primitives ---}

procedure TASN1Tests.TestParseBool;
var
  node: TASN1Node;
  buf: TBytes;
begin
  buf := LoadFixture('der_bool_true.der');
  AssertEquals('bool_true size', 3, Length(buf));
  node := ParseDER(buf);
  try
    AssertEquals('bool tag', Integer(atBoolean), Integer(node.Tag));
    AssertEquals('bool class', Integer(tcUniversal), Integer(node.TagClass));
    AssertEquals('bool not constructor', 0, Ord(node.IsConstructor));
    AssertEquals('bool len', 1, node.DataLength);
    AssertEquals('bool value', $FF, Integer(node.Data[0]));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_bool_false.der');
  node := ParseDER(buf);
  try
    AssertEquals('bool_false value', $00, Integer(node.Data[0]));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseNull;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_null.der'));
  try
    AssertEquals('null tag', Integer(atNull), Integer(node.Tag));
    AssertEquals('null len', 0, node.DataLength);
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseOctetString;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_octet_hello.der'));
  try
    AssertEquals('octet tag', Integer(atOctetString), Integer(node.Tag));
    AssertEquals('octet len', 5, node.DataLength);
    AssertEquals('octet data', 'hello', BytesToStr(node.Data));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseOctetEmpty;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_octet_empty.der'));
  try
    AssertEquals('octet_empty tag', Integer(atOctetString), Integer(node.Tag));
    AssertEquals('octet_empty len', 0, node.DataLength);
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseInteger;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_int_zero.der'));
  try
    AssertEquals('int0 tag', Integer(atInteger), Integer(node.Tag));
    AssertEquals('int0 len', 1, node.DataLength);
    AssertEquals('int0 value', $00, Integer(node.Data[0]));
  finally
    node.Free;
  end;

  node := ParseDER(LoadFixture('der_int_127.der'));
  try
    AssertEquals('int127 value', $7F, Integer(node.Data[0]));
  finally
    node.Free;
  end;

  node := ParseDER(LoadFixture('der_int_128.der'));
  try
    AssertEquals('int128 len', 2, node.DataLength);
    AssertEquals('int128 b0', $00, Integer(node.Data[0]));
    AssertEquals('int128 b1', $80, Integer(node.Data[1]));
  finally
    node.Free;
  end;

  node := ParseDER(LoadFixture('der_int_neg1.der'));
  try
    AssertEquals('int-1 value', $FF, Integer(node.Data[0]));
  finally
    node.Free;
  end;

  node := ParseDER(LoadFixture('der_int_long.der'));
  try
    AssertEquals('int_long tag', Integer(atInteger), Integer(node.Tag));
    AssertEquals('int_long len', 128, node.DataLength);
    AssertEquals('int_long first byte', $01, Integer(node.Data[0]));
    AssertEquals('int_long last byte', $01, Integer(node.Data[127]));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseBitString;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_bitstring.der'));
  try
    AssertEquals('bitstring tag', Integer(atBitString), Integer(node.Tag));
    AssertEquals('bitstring len', 2, node.DataLength);
    AssertEquals('bitstring unused bits', $01, Integer(node.Data[0]));
    AssertEquals('bitstring value', $5A, Integer(node.Data[1]));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseStrings;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_ia5.der'));
  try
    AssertEquals('ia5 tag', Integer(atIA5String), Integer(node.Tag));
    AssertEquals('ia5 len', 15, node.DataLength);
  finally
    node.Free;
  end;

  node := ParseDER(LoadFixture('der_printable.der'));
  try
    AssertEquals('printable tag', Integer(atPrintableString), Integer(node.Tag));
    AssertEquals('printable len', 11, node.DataLength);
  finally
    node.Free;
  end;

  node := ParseDER(LoadFixture('der_utf8.der'));
  try
    AssertEquals('utf8 tag', Integer(atUtf8String), Integer(node.Tag));
    AssertEquals('utf8 len', 6, node.DataLength);
  finally
    node.Free;
  end;
end;

{--- ParseDER: constructors ---}

procedure TASN1Tests.TestParseSequence;
var
  node, child: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_seq_two_ints.der'));
  try
    AssertEquals('seq tag', Integer(atSequence), Integer(node.Tag));
    AssertEquals('seq constructor', 1, Ord(node.IsConstructor));
    AssertEquals('seq children', 2, node.ChildCount);
    child := node.ChildAt(0);
    AssertEquals('seq[0] tag', Integer(atInteger), Integer(child.Tag));
    AssertEquals('seq[0] value', $01, Integer(child.Data[0]));
    child := node.ChildAt(1);
    AssertEquals('seq[1] tag', Integer(atInteger), Integer(child.Tag));
    AssertEquals('seq[1] value', $02, Integer(child.Data[0]));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseSequenceEmpty;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_seq_empty.der'));
  try
    AssertEquals('seq_empty tag', Integer(atSequence), Integer(node.Tag));
    AssertEquals('seq_empty children', 0, node.ChildCount);
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseSet;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_set_two_ints.der'));
  try
    AssertEquals('set tag', Integer(atSet), Integer(node.Tag));
    AssertEquals('set constructor', 1, Ord(node.IsConstructor));
    AssertEquals('set children', 2, node.ChildCount);
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseNested;
var
  node, inner, child: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_nested_seq.der'));
  try
    AssertEquals('nested tag', Integer(atSequence), Integer(node.Tag));
    AssertEquals('nested children', 2, node.ChildCount);
    inner := node.ChildAt(0);
    AssertEquals('inner tag', Integer(atSequence), Integer(inner.Tag));
    AssertEquals('inner children', 1, inner.ChildCount);
    child := inner.ChildAt(0);
    AssertEquals('inner[0] tag', Integer(atInteger), Integer(child.Tag));
    AssertEquals('inner[0] value', $2A, Integer(child.Data[0]));
    child := node.ChildAt(1);
    AssertEquals('outer[1] tag', Integer(atNull), Integer(child.Tag));
  finally
    node.Free;
  end;
end;

{--- ParseDER: context and application tags ---}

procedure TASN1Tests.TestParseContextSpecific;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_ctx0.der'));
  try
    AssertEquals('ctx0 class', Integer(tcContextSpecific), Integer(node.TagClass));
    AssertEquals('ctx0 tag number', 0, node.TagNumber);
    AssertEquals('ctx0 not constructor', 0, Ord(node.IsConstructor));
    AssertEquals('ctx0 len', 3, node.DataLength);
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseContextConstructed;
var
  node, child: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_ctx0_constructed.der'));
  try
    AssertEquals('ctx0c class', Integer(tcContextSpecific), Integer(node.TagClass));
    AssertEquals('ctx0c tag number', 0, node.TagNumber);
    AssertEquals('ctx0c constructor', 1, Ord(node.IsConstructor));
    AssertEquals('ctx0c children', 1, node.ChildCount);
    child := node.ChildAt(0);
    AssertEquals('ctx0c[0] tag', Integer(atInteger), Integer(child.Tag));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseApplication;
var
  node: TASN1Node;
begin
  node := ParseDER(LoadFixture('der_app12.der'));
  try
    AssertEquals('app class', Integer(tcApplication), Integer(node.TagClass));
    AssertEquals('app tag number', 12, node.TagNumber);
    AssertEquals('app not constructor', 0, Ord(node.IsConstructor));
  finally
    node.Free;
  end;
end;

{--- ParseDER: errors ---}

procedure TASN1Tests.TestParseTruncated;
var
  buf: TBytes;
  raised: Boolean;
begin
  buf := LoadFixture('der_truncated.der');
  AssertEquals('trunc size', 5, Length(buf));
  raised := False;
  try
    ParseDER(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('truncated SEQUENCE raises', raised);
end;

procedure TASN1Tests.TestParseTruncated2;
var
  buf: TBytes;
  raised: Boolean;
begin
  buf := LoadFixture('der_trunc2.der');
  AssertEquals('trunc2 size', 4, Length(buf));
  raised := False;
  try
    ParseDER(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('truncated INTEGER raises', raised);
end;

procedure TASN1Tests.TestParseIndefiniteLength;
var
  buf: TBytes;
  raised: Boolean;
begin
  buf := LoadFixture('der_indefinite.der');
  raised := False;
  try
    ParseDER(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('indefinite length raises', raised);
end;

procedure TASN1Tests.TestParseSingleByte;
var
  buf: TBytes;
  raised: Boolean;
begin
  buf := LoadFixture('der_single_byte.der');
  raised := False;
  try
    ParseDER(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('single byte raises', raised);
end;

procedure TASN1Tests.TestParseExtraBytes;
var
  buf: TBytes;
  raised: Boolean;
begin
  SetLength(buf, 3);
  buf[0] := $05; buf[1] := $00; buf[2] := $00;
  raised := False;
  try
    ParseDER(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('extra bytes raises', raised);
end;

procedure TASN1Tests.TestParseEmptyBuffer;
var
  buf: TBytes;
  raised: Boolean;
begin
  SetLength(buf, 0);
  raised := False;
  try
    ParseDER(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('empty buffer raises', raised);
end;

{--- ParseDER: real certificates ---}

procedure TASN1Tests.TestParseRealCert;
var
  node: TASN1Node;
  buf: TBytes;
begin
  buf := LoadFixture('leaf_rsa.der');
  node := ParseDER(buf);
  try
    AssertEquals('cert tag', Integer(atSequence), Integer(node.Tag));
    AssertEquals('cert constructor', 1, Ord(node.IsConstructor));
    AssertEquals('cert children', 3, node.ChildCount);
    AssertEquals('tbs tag', Integer(atSequence), Integer(node.ChildAt(0).Tag));
    AssertEquals('sigAlg tag', Integer(atSequence), Integer(node.ChildAt(1).Tag));
    AssertEquals('sigValue tag', Integer(atBitString), Integer(node.ChildAt(2).Tag));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestParseOpenSSLCert;
var
  node: TASN1Node;
  buf: TBytes;
begin
  buf := LoadFixture('openssl_ca.der');
  node := ParseDER(buf);
  try
    AssertEquals('openssl_ca tag', Integer(atSequence), Integer(node.Tag));
    AssertEquals('openssl_ca children', 3, node.ChildCount);
  finally
    node.Free;
  end;
end;

{--- EncodeDER: round-trip ---}

procedure TASN1Tests.TestEncodeRoundTrip;
var
  buf, enc: TBytes;
  node: TASN1Node;
begin
  buf := LoadFixture('der_bool_true.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('bool_true round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_null.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('null round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_octet_hello.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('octet round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_seq_two_ints.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('seq round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_nested_seq.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('nested round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_oid_sha256_rsa.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('oid round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_ctx0_constructed.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('ctx0c round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_int_long.der');
  node := ParseDER(buf);
  try
    enc := EncodeDER(node);
    AssertTrue('int_long round-trip', BytesEqual(buf, enc));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestEncodePrimitives;
var
  node: TASN1Node;
  enc, buf, d: TBytes;
begin
  node := TASN1Node.Create(tcUniversal, Ord(atBoolean), False);
  SetLength(d, 1); d[0] := $FF;
  node.Data := d;
  enc := EncodeDER(node);
  SetLength(buf, 3);
  buf[0] := $01; buf[1] := $01; buf[2] := $FF;
  AssertTrue('encode bool true', BytesEqual(buf, enc));
  node.Free;

  node := TASN1Node.Create(tcUniversal, Ord(atNull), False);
  enc := EncodeDER(node);
  SetLength(buf, 2);
  buf[0] := $05; buf[1] := $00;
  AssertTrue('encode null', BytesEqual(buf, enc));
  node.Free;

  node := TASN1Node.Create(tcUniversal, Ord(atInteger), False);
  SetLength(d, 1); d[0] := $00;
  node.Data := d;
  enc := EncodeDER(node);
  SetLength(buf, 3);
  buf[0] := $02; buf[1] := $01; buf[2] := $00;
  AssertTrue('encode int 0', BytesEqual(buf, enc));
  node.Free;
end;

procedure TASN1Tests.TestEncodeLongLength;
var
  node: TASN1Node;
  enc, d: TBytes;
  i: LongInt;
begin
  node := TASN1Node.Create(tcUniversal, Ord(atOctetString), False);
  SetLength(d, 200);
  for i := 0 to 199 do
    d[i] := Byte(i);
  node.Data := d;
  enc := EncodeDER(node);
  AssertEquals('long len total', 203, Length(enc));
  AssertEquals('long len tag', $04, Integer(enc[0]));
   AssertEquals('long len marker', $81, Integer(enc[1]));
   AssertEquals('long len lo', $C8, Integer(enc[2]));
  node.Free;
end;

procedure TASN1Tests.TestEncodeMultiByteTag;
var
  node: TASN1Node;
  enc, d: TBytes;
begin
  node := TASN1Node.Create(tcContextSpecific, 127, False);
  SetLength(d, 1); d[0] := $00;
  node.Data := d;
  enc := EncodeDER(node);
  AssertEquals('multi tag b0', $9F, Integer(enc[0]));
  AssertEquals('multi tag b1', $7F, Integer(enc[1]));
  AssertEquals('multi len', $01, Integer(enc[2]));
  node.Free;
end;

{--- ReadOID ---}

procedure TASN1Tests.TestReadOID;
var
  node: TASN1Node;
  buf: TBytes;
  d: TBytes;
begin
  buf := LoadFixture('der_oid_1_2_840.der');
  node := ParseDER(buf);
  try
    AssertEquals('oid 1.2.840', '1.2.840', ReadOID(node));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_oid_1_2_3_4_1.der');
  node := ParseDER(buf);
  try
    AssertEquals('oid 1.2.3.4.1', '1.2.3.4.1', ReadOID(node));
  finally
    node.Free;
  end;

  buf := LoadFixture('der_oid_sha256_rsa.der');
  node := ParseDER(buf);
  try
    AssertEquals('oid sha256rsa', '1.2.840.113549.1.1.15', ReadOID(node));
  finally
    node.Free;
  end;

  SetLength(d, 2);
  d[0] := $85; d[1] := $17;
  node := MakeOIDNode(d);
  try
    AssertEquals('oid 2.583', '2.583', ReadOID(node));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestReadOIDError;
var
  node: TASN1Node;
  raised: Boolean;
  d: TBytes;
begin
  node := TASN1Node.Create(tcUniversal, Ord(atInteger), False);
  SetLength(d, 1); d[0] := $01;
  node.Data := d;
  raised := False;
  try
    ReadOID(node);
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('ReadOID on INTEGER raises', raised);
  node.Free;

  node := TASN1Node.Create(tcUniversal, Ord(atObjectIdentifier), False);
  raised := False;
  try
    ReadOID(node);
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('ReadOID empty raises', raised);
  node.Free;
end;

{--- ReadTime ---}

procedure TASN1Tests.TestReadUTCTime;
var
  node: TASN1Node;
  dt: TDateTime;
begin
  node := MakeUTCTimeNode('121220165000Z');
  try
    dt := ReadTime(node);
    AssertEquals('utc year', 2012, YearOf(dt));
    AssertEquals('utc month', 12, MonthOf(dt));
    AssertEquals('utc day', 20, DayOf(dt));
    AssertEquals('utc hour', 16, HourOf(dt));
    AssertEquals('utc min', 50, MinuteOf(dt));
    AssertEquals('utc sec', 0, Trunc(Frac(dt) * 86400) mod 60);
  finally
    node.Free;
  end;

  node := MakeUTCTimeNode('991231235959Z');
  try
    dt := ReadTime(node);
    AssertEquals('utc99 year', 1999, YearOf(dt));
    AssertEquals('utc99 month', 12, MonthOf(dt));
    AssertEquals('utc99 day', 31, DayOf(dt));
    AssertEquals('utc99 hour', 23, HourOf(dt));
  finally
    node.Free;
  end;

  node := MakeUTCTimeNode('000101000000Z');
  try
    dt := ReadTime(node);
    AssertEquals('utc00 year', 2000, YearOf(dt));
    AssertEquals('utc00 month', 1, MonthOf(dt));
    AssertEquals('utc00 day', 1, DayOf(dt));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestReadGeneralizedTime;
var
  node: TASN1Node;
  dt: TDateTime;
begin
  node := MakeGTNode('21201213201650Z');
  try
    dt := ReadTime(node);
    AssertEquals('gt year', 2120, YearOf(dt));
    AssertEquals('gt month', 12, MonthOf(dt));
    AssertEquals('gt day', 13, DayOf(dt));
    AssertEquals('gt hour', 20, HourOf(dt));
    AssertEquals('gt min', 16, MinuteOf(dt));
    AssertEquals('gt sec', 50, Trunc(Frac(dt) * 86400) mod 60);
  finally
    node.Free;
  end;

  node := MakeGTNode('20250601120000.500Z');
  try
    dt := ReadTime(node);
    AssertEquals('gt frac year', 2025, YearOf(dt));
    AssertEquals('gt frac month', 6, MonthOf(dt));
    AssertEquals('gt frac day', 1, DayOf(dt));
    AssertEquals('gt frac hour', 12, HourOf(dt));
    AssertEquals('gt frac min', 0, MinuteOf(dt));
    AssertEquals('gt frac sec', 0, Trunc(Frac(dt) * 86400) mod 60);
    AssertTrue('gt frac value', Abs(Frac(dt) - (12 * 3600 + 0.5) / 86400) < 1e-6);
  finally
    node.Free;
  end;

  node := MakeGTNode('20250601120000+0530');
  try
    dt := ReadTime(node);
    AssertEquals('gt tz year', 2025, YearOf(dt));
    AssertEquals('gt tz hour', 6, HourOf(dt));
    AssertEquals('gt tz min', 30, MinuteOf(dt));
  finally
    node.Free;
  end;

  node := MakeGTNode('20250601120000-0530');
  try
    dt := ReadTime(node);
    AssertEquals('gt tz- year', 2025, YearOf(dt));
    AssertEquals('gt tz- hour', 17, HourOf(dt));
    AssertEquals('gt tz- min', 30, MinuteOf(dt));
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestReadTimeError;
var
  node: TASN1Node;
  raised: Boolean;
  d: TBytes;
begin
  node := MakeUTCTimeNode('2012122016500');
  try
    raised := False;
    try
      ReadTime(node);
    except
      on E: EASN1Error do raised := True;
    end;
    AssertTrue('UTCTime no Z raises', raised);
  finally
    node.Free;
  end;

  node := MakeUTCTimeNode('201212201650');
  try
    raised := False;
    try
      ReadTime(node);
    except
      on E: EASN1Error do raised := True;
    end;
    AssertTrue('UTCTime wrong len raises', raised);
  finally
    node.Free;
  end;

  node := MakeGTNode('20250601');
  try
    raised := False;
    try
      ReadTime(node);
    except
      on E: EASN1Error do raised := True;
    end;
    AssertTrue('GT too short raises', raised);
  finally
    node.Free;
  end;

  node := TASN1Node.Create(tcUniversal, Ord(atInteger), False);
  SetLength(d, 1); d[0] := $01;
  node.Data := d;
  raised := False;
  try
    ReadTime(node);
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('ReadTime on INTEGER raises', raised);
  node.Free;

  node := MakeUTCTimeNode('201313201650Z');
  try
    raised := False;
    try
      ReadTime(node);
    except
      on E: EASN1Error do raised := True;
    end;
    AssertTrue('UTCTime month=13 raises', raised);
  finally
    node.Free;
  end;
end;

{--- ReadInteger ---}

procedure TASN1Tests.TestReadInteger;
var
  node: TASN1Node;
  bn: TBN;
  d: TBytes;
begin
  SetLength(d, 1); d[0] := $00;
  node := MakeIntNode(d);
  try
    bn := ReadInteger(node);
    AssertEquals('int 0', '0', bn.ToString);
  finally
    node.Free;
  end;

  SetLength(d, 1); d[0] := $7F;
  node := MakeIntNode(d);
  try
    bn := ReadInteger(node);
    AssertEquals('int 127', '127', bn.ToString);
  finally
    node.Free;
  end;

  SetLength(d, 2); d[0] := $00; d[1] := $80;
  node := MakeIntNode(d);
  try
    bn := ReadInteger(node);
    AssertEquals('int 128', '128', bn.ToString);
  finally
    node.Free;
  end;

  SetLength(d, 1); d[0] := $FF;
  node := MakeIntNode(d);
  try
    bn := ReadInteger(node);
    AssertEquals('int -1 abs', '1', bn.ToString);
  finally
    node.Free;
  end;

  SetLength(d, 1); d[0] := $80;
  node := MakeIntNode(d);
  try
    bn := ReadInteger(node);
    AssertEquals('int -128 abs', '128', bn.ToString);
  finally
    node.Free;
  end;

  SetLength(d, 2); d[0] := $00; d[1] := $FF;
  node := MakeIntNode(d);
  try
    bn := ReadInteger(node);
    AssertEquals('int 255', '255', bn.ToString);
  finally
    node.Free;
  end;

  SetLength(d, 2); d[0] := $FF; d[1] := $00;
  node := MakeIntNode(d);
  try
    bn := ReadInteger(node);
    AssertEquals('int -256 abs', '256', bn.ToString);
  finally
    node.Free;
  end;
end;

procedure TASN1Tests.TestReadIntegerError;
var
  node: TASN1Node;
  raised: Boolean;
begin
  node := TASN1Node.Create(tcUniversal, Ord(atNull), False);
  raised := False;
  try
    ReadInteger(node);
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('ReadInteger on NULL raises', raised);
  node.Free;

  node := TASN1Node.Create(tcUniversal, Ord(atInteger), False);
  raised := False;
  try
    ReadInteger(node);
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('ReadInteger empty raises', raised);
  node.Free;
end;

{--- Helpers ---}

procedure TASN1Tests.TestUniversalTagOf;
begin
  AssertEquals('tag 1', Integer(atBoolean), Integer(UniversalTagOf(1)));
  AssertEquals('tag 2', Integer(atInteger), Integer(UniversalTagOf(2)));
  AssertEquals('tag 3', Integer(atBitString), Integer(UniversalTagOf(3)));
  AssertEquals('tag 4', Integer(atOctetString), Integer(UniversalTagOf(4)));
  AssertEquals('tag 5', Integer(atNull), Integer(UniversalTagOf(5)));
  AssertEquals('tag 6', Integer(atObjectIdentifier), Integer(UniversalTagOf(6)));
  AssertEquals('tag 16', Integer(atSequence), Integer(UniversalTagOf(16)));
  AssertEquals('tag 17', Integer(atSet), Integer(UniversalTagOf(17)));
  AssertEquals('tag 23', Integer(atUTCTime), Integer(UniversalTagOf(23)));
  AssertEquals('tag 24', Integer(atGeneralizedTime), Integer(UniversalTagOf(24)));
  AssertEquals('tag 7', Integer(atUnknown), Integer(UniversalTagOf(7)));
  AssertEquals('tag 0', Integer(atUnknown), Integer(UniversalTagOf(0)));
  AssertEquals('tag 31', Integer(atUnknown), Integer(UniversalTagOf(31)));
end;

procedure TASN1Tests.TestTagName;
begin
  AssertEquals('name bool', 'BOOLEAN', TagName(atBoolean));
  AssertEquals('name int', 'INTEGER', TagName(atInteger));
  AssertEquals('name seq', 'SEQUENCE', TagName(atSequence));
  AssertEquals('name oid', 'OID', TagName(atObjectIdentifier));
  AssertEquals('name utc', 'UTCTime', TagName(atUTCTime));
  AssertEquals('name unknown', 'UNKNOWN', TagName(atUnknown));
end;

procedure TASN1Tests.TestToDebugString;
var
  node: TASN1Node;
  buf: TBytes;
  s: string;
begin
  node := TASN1Node.Create(tcUniversal, Ord(atNull), False);
  s := node.ToDebugString;
  AssertEquals('debug null', 'NULL len=0', s);
  node.Free;

  SetLength(buf, 5);
  buf[0] := $30; buf[1] := $03; buf[2] := $02; buf[3] := $01; buf[4] := $01;
  node := ParseDER(buf);
  try
    s := node.ToDebugString;
    AssertEquals('debug seq', 'SEQUENCE (1) {INTEGER len=1}', s);
  finally
    node.Free;
  end;
end;

initialization
  RegisterTest(TASN1Tests);

end.
