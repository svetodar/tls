{ SPDX-License-Identifier: Apache-2.0 }
unit tls.asn1;

{' DER (Distinguished Encoding Rules) ASN.1 parser — layer 2 (certificates).
  TASN1Node — DER tree node: tag (class + number), length, content
  (primitive — bytes, constructed — list of child nodes).
  ParseDER — recursive parsing: tag (universal and context [n],
  including multi-byte tag numbers), short/long length, content.
  EXPLICIT/IMPLICIT semantics of context tags differ by caller
  (X.509 layer): the parser returns tag class and number as-is.
  No external dependencies (docs/tasks/09-asn1.md). '}

{$mode objfpc}{$H+}

interface

uses
  SysUtils,
  DateUtils,
  tls.bn;

type
  EASN1Error = class(Exception);

  {' Tag class (first 2 bits of the tag byte). '}
  TASN1TagClass = (tcUniversal, tcApplication, tcContextSpecific, tcPrivate);

  {' Universal tag number (PDU). Ord(T) = tag number (atUnknown = 0). '}
  TASN1Tag = (
    atUnknown = 0,
    atBoolean = 1,
    atInteger = 2,
    atBitString = 3,
    atOctetString = 4,
    atNull = 5,
    atObjectIdentifier = 6,
    atExternal = 8,
    atReal = 9,
    atEnumerated = 10,
    atSequence = 16,
    atSet = 17,
    atUtf8String = 18,
    atPrintableString = 19,
    atIA5String = 22,
    atUTCTime = 23,
    atGeneralizedTime = 24
  );

  {' DER node. For primitives — Data, for constructed — Children. '}
  TASN1Node = class
  private
    FTag: TASN1Tag;
    FTagClass: TASN1TagClass;
    FTagNumber: LongInt;
    FIsConstructor: Boolean;
    FData: TBytes;
    FChildren: array of TASN1Node;
    FParent: TASN1Node;
    function GetLength: LongInt;
    function GetChildCount: LongInt;
    function GetHasChildren: Boolean;
    procedure SetData(const AData: TBytes);
  public
    constructor Create(ATagClass: TASN1TagClass; ATagNumber: LongInt;
      AIsConstructor: Boolean = False);
    destructor Destroy; override;

    {' Tag '}
    property Tag: TASN1Tag read FTag;
    property TagClass: TASN1TagClass read FTagClass;
    property TagNumber: LongInt read FTagNumber;
    property IsConstructor: Boolean read FIsConstructor;
    {' Context tag number ([n]); meaningful when TagClass = tcContextSpecific. '}
    property ContextTag: LongInt read FTagNumber;

    {' Content '}
    property Data: TBytes read FData write SetData;
    {' Content length in bytes. '}
    property DataLength: LongInt read GetLength;
    property HasChildren: Boolean read GetHasChildren;
    property ChildCount: LongInt read GetChildCount;
    function ChildAt(i: LongInt): TASN1Node;
    function FirstChild: TASN1Node;
    property Parent: TASN1Node read FParent;

    {' Search '}
    {' Direct children: by class + tag number. '}
    function FindByTag(ATagClass: TASN1TagClass; ATagNumber: LongInt): TASN1Node;
    {' Direct children: by universal tag. '}
    function FindByUniversal(ATag: TASN1Tag): TASN1Node;
    {' Recursive search (first found in DFS traversal). '}
    function FindByTagDeep(ATagClass: TASN1TagClass; ATagNumber: LongInt): TASN1Node;

    {' Debug string. '}
    function ToDebugString: string;
  end;

  {' Parse a complete DER structure from the start of Buf.
    If bytes remain after the structure — EASN1Error. '}
  function ParseDER(const Buf: TBytes): TASN1Node;
  {' Parse a structure from Off (0-based), no longer than Len bytes.
    EndOff — offset of the first byte after the structure. '}
  function ParseDERAt(const Buf: TBytes; Off, Len: LongInt;
    out EndOff: LongInt): TASN1Node;

  {' Tag number → universal tag (atUnknown if no name). '}
  function UniversalTagOf(N: LongInt): TASN1Tag;
  {' Tag → name (for debugging). '}
  function TagName(ATag: TASN1Tag): string;

  {' DER serializer (for tests/generation): encodes a node to DER. '}
  function EncodeDER(const Node: TASN1Node): TBytes;

  {' Helper: INTEGER → TBN (value modulus; DER INTEGER is two's
    complement, leading sign zero byte is accounted for). '}
  function ReadInteger(const Node: TASN1Node): TBN;
  {' Helper: OBJECT IDENTIFIER → canonical string "1.2.840.113549...". '}
  function ReadOID(const Node: TASN1Node): string;
  { Helper: UTCTime/GeneralizedTime → TDateTime (UTC). }
  function ReadTime(const Node: TASN1Node): TDateTime;

implementation

const
  { Garbage protection: maximum content length of a single structure. }
  ASN1_MAX_LEN = 100 * 1024 * 1024;

{--- TASN1Node ---}

constructor TASN1Node.Create(ATagClass: TASN1TagClass; ATagNumber: LongInt;
  AIsConstructor: Boolean);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNumber := ATagNumber;
  FIsConstructor := AIsConstructor;
  if ATagClass = tcUniversal then
    FTag := UniversalTagOf(ATagNumber)
  else
    FTag := atUnknown;
end;

destructor TASN1Node.Destroy;
var
  i: LongInt;
begin
  for i := 0 to GetChildCount - 1 do
    FChildren[i].Free;
  FChildren := nil;
  inherited Destroy;
end;

function TASN1Node.GetLength: LongInt;
begin
  Result := Length(FData);
end;

function TASN1Node.GetChildCount: LongInt;
begin
  Result := Length(FChildren);
end;

function TASN1Node.GetHasChildren: Boolean;
begin
  Result := FChildren <> nil;
end;

procedure TASN1Node.SetData(const AData: TBytes);
begin
  FData := AData;
end;

function TASN1Node.ChildAt(i: LongInt): TASN1Node;
begin
  if (i < 0) or (i >= GetChildCount) then
    raise EASN1Error.CreateFmt('TASN1Node.ChildAt: index %d out of range', [i]);
  Result := FChildren[i];
end;

function TASN1Node.FirstChild: TASN1Node;
begin
  Result := nil;
  if GetChildCount > 0 then
    Result := FChildren[0];
end;

function TASN1Node.FindByTag(ATagClass: TASN1TagClass; ATagNumber: LongInt): TASN1Node;
var
  i: LongInt;
  c: TASN1Node;
begin
  Result := nil;
  for i := 0 to GetChildCount - 1 do
  begin
    c := FChildren[i];
    if (c.TagClass = ATagClass) and (c.TagNumber = ATagNumber) then
    begin
      Result := c;
      Break;
    end;
  end;
end;

function TASN1Node.FindByUniversal(ATag: TASN1Tag): TASN1Node;
begin
  Result := FindByTag(tcUniversal, Ord(ATag));
end;

function TASN1Node.FindByTagDeep(ATagClass: TASN1TagClass; ATagNumber: LongInt): TASN1Node;
var
  i: LongInt;
  c: TASN1Node;
begin
  Result := nil;
  if (TagClass = ATagClass) and (TagNumber = ATagNumber) then
    Exit(Self);
  for i := 0 to GetChildCount - 1 do
  begin
    c := FChildren[i].FindByTagDeep(ATagClass, ATagNumber);
    if c <> nil then
    begin
      Result := c;
      Break;
    end;
  end;
end;

function TASN1Node.ToDebugString: string;
var
  i: LongInt;
  s: string;
  c: TASN1Node;
begin
  s := TagName(Tag);
  if TagClass <> tcUniversal then
    s := s + ' [' + IntToStr(TagNumber) + ']';
  if IsConstructor then
  begin
    s := s + ' (' + IntToStr(GetChildCount) + ') {';
    for i := 0 to GetChildCount - 1 do
    begin
      c := FChildren[i];
      if i > 0 then
        s := s + ' ';
      s := s + c.ToDebugString;
    end;
    s := s + '}';
  end
  else
    s := s + ' len=' + IntToStr(GetLength);
  Result := s;
end;

{--- Tags ---}

function UniversalTagOf(N: LongInt): TASN1Tag;
begin
  case N of
    1: Result := atBoolean;
    2: Result := atInteger;
    3: Result := atBitString;
    4: Result := atOctetString;
    5: Result := atNull;
    6: Result := atObjectIdentifier;
    8: Result := atExternal;
    9: Result := atReal;
    10: Result := atEnumerated;
    16: Result := atSequence;
    17: Result := atSet;
    18: Result := atUtf8String;
    19: Result := atPrintableString;
    22: Result := atIA5String;
    23: Result := atUTCTime;
    24: Result := atGeneralizedTime;
  else
    Result := atUnknown;
  end;
end;

function TagName(ATag: TASN1Tag): string;
begin
  case ATag of
    atBoolean: Result := 'BOOLEAN';
    atInteger: Result := 'INTEGER';
    atBitString: Result := 'BIT STRING';
    atOctetString: Result := 'OCTET STRING';
    atNull: Result := 'NULL';
    atObjectIdentifier: Result := 'OID';
    atExternal: Result := 'EXTERNAL';
    atReal: Result := 'REAL';
    atEnumerated: Result := 'ENUMERATED';
    atSequence: Result := 'SEQUENCE';
    atSet: Result := 'SET';
    atUtf8String: Result := 'UTF8String';
    atPrintableString: Result := 'PrintableString';
    atIA5String: Result := 'IA5String';
    atUTCTime: Result := 'UTCTime';
    atGeneralizedTime: Result := 'GeneralizedTime';
  else
    Result := 'UNKNOWN';
  end;
end;

{--- Parser ---}

function ParseDERAt(const Buf: TBytes; Off, Len: LongInt;
  out EndOff: LongInt): TASN1Node;
var
  p, endPos, contentEnd, tagByte, cls, pdu, n, i, lenBytes: LongInt;
  node, child: TASN1Node;
begin
  if (Off < 0) or (Len < 0) or (Off + Len > Length(Buf)) then
    raise EASN1Error.Create('ParseDERAt: range outside buffer');
  p := Off;
  endPos := Off + Len;

  { --- Tag --- }
  if p >= endPos then
    raise EASN1Error.Create('ParseDERAt: no tag');
  tagByte := Buf[p];
  Inc(p);
  cls := (tagByte shr 6) and 3;
  pdu := tagByte and $1F;
  if pdu = 31 then
  begin
    { Multi-byte tag number: base-128, high bit = continuation }
    n := 0;
    i := 0;
    repeat
      if p >= endPos then
        raise EASN1Error.Create('ParseDERAt: truncated multi-byte tag');
      if i >= 5 then
        raise EASN1Error.Create('ParseDERAt: tag number too long');
      n := (n shl 7) or (Buf[p] and $7F);
      Inc(p);
      Inc(i);
    until (Buf[p - 1] and $80) = 0;
    pdu := n;
  end;

  { --- Length --- }
  if p >= endPos then
    raise EASN1Error.Create('ParseDERAt: no length');
  n := Buf[p];
  Inc(p);
  if n = $80 then
    raise EASN1Error.Create('ParseDERAt: indefinite length is not DER');
  if n >= $80 then
  begin
    lenBytes := n and $7F;
    if lenBytes > 8 then
      raise EASN1Error.Create('ParseDERAt: length too long');
    if p + lenBytes > endPos then
      raise EASN1Error.Create('ParseDERAt: truncated long length');
    n := 0;
    for i := 0 to lenBytes - 1 do
    begin
      n := (n shl 8) or Buf[p];
      Inc(p);
    end;
  end;
  if n > ASN1_MAX_LEN then
    raise EASN1Error.Create('ParseDERAt: length too large');
  if p + n > endPos then
    raise EASN1Error.Create('ParseDERAt: content goes beyond buffer');
  contentEnd := p + n;

  { --- Node --- }
  node := TASN1Node.Create(TASN1TagClass(cls), pdu, (tagByte and $20) <> 0);
  try
    if node.IsConstructor then
    begin
      { Recursively parse children until content is exhausted }
      while p < contentEnd do
      begin
        child := ParseDERAt(Buf, p, endPos - p, p);
        child.FParent := node;
        SetLength(node.FChildren, node.GetChildCount + 1);
        node.FChildren[node.GetChildCount - 1] := child;
      end;
      if p <> contentEnd then
        raise EASN1Error.Create('ParseDERAt: constructor content not exhausted');
    end
    else
    begin
      SetLength(node.FData, n);
      if n > 0 then
        Move(Buf[p], node.FData[0], n);
      p := contentEnd;
    end;
  except
    node.Free;
    raise;
  end;
  Result := node;
  EndOff := p;
end;

function ParseDER(const Buf: TBytes): TASN1Node;
var
  endOff: LongInt;
begin
  Result := ParseDERAt(Buf, 0, Length(Buf), endOff);
  if endOff <> Length(Buf) then
    raise EASN1Error.Create('ParseDER: bytes after structure');
end;

{--- Serializer ---}

{ Tag number → DER bytes (1 byte if <= 31, otherwise base-128). }
function ASN1_EncodeTagNumber(n: LongInt): TBytes;
var
  groups: array[0..8] of Byte;
  cnt, i: LongInt;
begin
  Result := nil;
  if n <= 31 then
  begin
    SetLength(Result, 1);
    Result[0] := Byte(n);
    Exit;
  end;
  cnt := 0;
  while n > 0 do
  begin
    groups[cnt] := Byte(n and $7F);
    n := n shr 7;
    Inc(cnt);
  end;
  { First byte: 11111, then base-128 groups (high bit — continuation) }
  SetLength(Result, cnt + 1);
  Result[0] := $1F;
  for i := 0 to cnt - 1 do
  begin
    Result[i + 1] := groups[cnt - 1 - i];
    if i < cnt - 1 then
      Result[i + 1] := Result[i + 1] or $80;
  end;
end;

{ Concatenation of byte arrays (operator + for TBytes in this FPC build
  is not overloaded). }
function ASN1_BytesConcat(A, B: TBytes): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

function EncodeDER(const Node: TASN1Node): TBytes;
var
  tb, lb, content: TBytes;
  i, n, m: LongInt;
  c: TASN1Node;
begin
  {' Tag '}
  tb := ASN1_EncodeTagNumber(Node.TagNumber);
  tb[0] := tb[0] or Byte(Ord(Node.TagClass) shl 6);
  if Node.IsConstructor then
    tb[0] := tb[0] or $20;

  {' Content '}
  if Node.IsConstructor then
  begin
    content := nil;
    for i := 0 to Node.GetChildCount - 1 do
    begin
      c := Node.FChildren[i];
      content := ASN1_BytesConcat(content, EncodeDER(c));
    end;
  end
  else
    content := Node.Data;

  { Length (minimal representation) }
  n := Length(content);
  if n < $80 then
  begin
    SetLength(lb, 1);
    lb[0] := Byte(n);
  end
  else
  begin
    { 0x80|N + N length bytes (big-endian) }
    m := 0;
    while n > 0 do
    begin
      Inc(m);
      n := n shr 8;
    end;
    n := Length(content);
    SetLength(lb, m + 1);
    lb[0] := Byte($80 + m);
    for i := 0 to m - 1 do
      lb[i + 1] := Byte((n shr ((m - 1 - i) * 8)) and $FF);
  end;

  Result := ASN1_BytesConcat(ASN1_BytesConcat(tb, lb), content);
end;

{--- Helpers ---}

{ TBytes → string (ASCII). }
function ASN1_BytesToString(const B: TBytes): string;
begin
  SetLength(Result, Length(B));
  if Length(B) > 0 then
    Move(B[0], PChar(Result)^, Length(B));
end;

{ INTEGER → TBN. DER INTEGER — two's complement code; result — modulus
  of the value (leading zero sign byte is taken into account). }
function ReadInteger(const Node: TASN1Node): TBN;
var
  d: TBytes;
  i: LongInt;
begin
  if (Node = nil) or (Node.TagClass <> tcUniversal) or
     (Node.TagNumber <> Ord(atInteger)) or Node.IsConstructor then
    raise EASN1Error.Create('ReadInteger: node is not INTEGER');
  d := Node.Data;
  if Length(d) = 0 then
    raise EASN1Error.Create('ReadInteger: empty INTEGER content');
  if (d[0] and $80) <> 0 then
  begin
    { Negative: two's complement — bit inversion and +1 }
    for i := 0 to High(d) do
      d[i] := not d[i];
    i := High(d);
    while i >= 0 do
    begin
      Inc(d[i]);
      if d[i] <> 0 then
        Break;
      Dec(i);
    end;
  end;
  { Strip leading zeros }
  i := 0;
  while (i < Length(d) - 1) and (d[i] = 0) do
    Inc(i);
  if i > 0 then
  begin
    Move(d[i], d[0], Length(d) - i);
    SetLength(d, Length(d) - i);
  end;
  Result := TBN.FromBytes(d, True);
end;
{ Read base-128 group from position i (i is var, advanced past the group). }
function ASN1_ReadBase128(const d: TBytes; var i: LongInt): Int64;
var
  acc: Int64;
begin
  acc := 0;
  repeat
    if i >= Length(d) then
      raise EASN1Error.Create('ReadOID: truncated base-128 group');
    if acc >= $100000000 then
      raise EASN1Error.Create('ReadOID: OID component too large');
    acc := (acc shl 7) or (d[i] and $7F);
    Inc(i);
  until (d[i - 1] and $80) = 0;
  Result := acc;
end;

{ OBJECT IDENTIFIER → canonical string "1.2.840.113549...".
  First base-128 group: < 80 → arc1 = g div 40, arc2 = g mod 40;
  >= 80 → arc1 = 2, arc2 = g - 80 (X.690 §12.5, as in OpenSSL). }
function ReadOID(const Node: TASN1Node): string;
var
  d: TBytes;
  i: LongInt;
  first: Int64;
  s: string;
begin
  if (Node = nil) or (Node.TagClass <> tcUniversal) or
     (Node.TagNumber <> Ord(atObjectIdentifier)) or Node.IsConstructor then
    raise EASN1Error.Create('ReadOID: node is not OBJECT IDENTIFIER');
  d := Node.Data;
  if Length(d) = 0 then
    raise EASN1Error.Create('ReadOID: empty OID content');
  i := 0;
  first := ASN1_ReadBase128(d, i);
  if first < 80 then
    s := IntToStr(first div 40) + '.' + IntToStr(first mod 40)
  else
    s := '2.' + IntToStr(first - 80);
  while i < Length(d) do
    s := s + '.' + IntToStr(ASN1_ReadBase128(d, i));
  Result := s;
end;

{ Digits s[i..i+n-1] → number; non-digit character — error. }
function ASN1_ParseDigits(const s: string; i, n: LongInt): LongInt;
var
  j: LongInt;
begin
  Result := 0;
  for j := i to i + n - 1 do
  begin
    if (j > Length(s)) or (s[j] < '0') or (s[j] > '9') then
      raise EASN1Error.CreateFmt('ASN1: non-digit character at position %d', [j]);
    Result := Result * 10 + (Ord(s[j]) - Ord('0'));
  end;
end;

{ Gregorian date → TDateTime (UTC). TDateTime epoch — 30.12.1899. }
function ASN1_CivilToTDateTime(Y, M, D, H, Mi, S: LongInt; Frac: Double): TDateTime;
begin
  Result := EncodeDate(Y, M, D) + (H * 3600 + Mi * 60 + S + Frac) / 86400;
end;

{ UTCTime/GeneralizedTime → TDateTime (UTC).
  UTCTime: YYMMDDHHMMSSZ (YY: 00-49 → 20YY, 50-99 → 19YY, RFC 5280).
  GeneralizedTime: YYYYMMDDHHMMSS[.frac][Z|±HHMM]. }
function ReadTime(const Node: TASN1Node): TDateTime;
var
  str: string;
  i, j, L: LongInt;
  Y, M, D, H, Mi, S: LongInt;
  frac, div10: Double;
  fracNum, fracCnt: LongInt;
  zh, zm: LongInt;
  c: Char;
begin
  if (Node = nil) or (Node.TagClass <> tcUniversal) or Node.IsConstructor then
    raise EASN1Error.Create('ReadTime: node is not UTCTime/GeneralizedTime');
  if (Node.TagNumber <> Ord(atUTCTime)) and (Node.TagNumber <> Ord(atGeneralizedTime)) then
    raise EASN1Error.Create('ReadTime: node is not UTCTime/GeneralizedTime');
  str := ASN1_BytesToString(Node.Data);
  L := Length(str);

  if Node.TagNumber = Ord(atUTCTime) then
  begin
    if (L <> 13) or (str[13] <> 'Z') then
      raise EASN1Error.CreateFmt('ReadTime: UTCTime: invalid format "%s"', [str]);
    Y := ASN1_ParseDigits(str, 1, 2);
    M := ASN1_ParseDigits(str, 3, 2);
    D := ASN1_ParseDigits(str, 5, 2);
    H := ASN1_ParseDigits(str, 7, 2);
    Mi := ASN1_ParseDigits(str, 9, 2);
    S := ASN1_ParseDigits(str, 11, 2);
    if Y <= 49 then
      Inc(Y, 2000)
    else
      Inc(Y, 1900);
    frac := 0;
    zh := 0;
    zm := 0;
  end
  else
  begin
    if L < 14 then
      raise EASN1Error.CreateFmt('ReadTime: GeneralizedTime: string too short "%s"', [str]);
    Y := ASN1_ParseDigits(str, 1, 4);
    M := ASN1_ParseDigits(str, 5, 2);
    D := ASN1_ParseDigits(str, 7, 2);
    H := ASN1_ParseDigits(str, 9, 2);
    Mi := ASN1_ParseDigits(str, 11, 2);
    S := ASN1_ParseDigits(str, 13, 2);
    frac := 0;
    i := 15;
    if (i <= L) and (str[i] = '.') then
    begin
      Inc(i);
      fracNum := 0;
      fracCnt := 0;
      while (i <= L) and (str[i] >= '0') and (str[i] <= '9') do
      begin
        fracNum := fracNum * 10 + (Ord(str[i]) - Ord('0'));
        Inc(fracCnt);
        Inc(i);
      end;
      if fracCnt = 0 then
        raise EASN1Error.Create('ReadTime: GeneralizedTime: empty fractional part');
      div10 := 1;
      for j := 1 to fracCnt do
        div10 := div10 * 10;
      frac := fracNum / div10;
    end;
    zh := 0;
    zm := 0;
    if i <= L then
    begin
      c := str[i];
      if c = 'Z' then
      begin
        if i <> L then
          raise EASN1Error.Create('ReadTime: GeneralizedTime: bytes after Z');
      end
      else if (c = '+') or (c = '-') then
      begin
        if (L - i + 1) <> 5 then
          raise EASN1Error.Create('ReadTime: GeneralizedTime: invalid zone format');
        zh := ASN1_ParseDigits(str, i + 1, 2);
        zm := ASN1_ParseDigits(str, i + 3, 2);
        if c = '-' then
        begin
          zh := -zh;
          zm := -zm;
        end;
      end
      else
        raise EASN1Error.CreateFmt('ReadTime: GeneralizedTime: unknown zone character "%s"', [c]);
    end;
  end;

  if (M < 1) or (M > 12) or (D < 1) or (D > 31) or (H > 23) or (Mi > 59) or (S > 60) then
    raise EASN1Error.CreateFmt('ReadTime: invalid date/time %04d-%02d-%02d %02d:%02d:%02d',
      [Y, M, D, H, Mi, S]);

  Result := ASN1_CivilToTDateTime(Y, M, D, H, Mi, S, frac);
  if (zh <> 0) or (zm <> 0) then
    Result := Result - (zh * 3600 + zm * 60) / 86400;
end;
end.
