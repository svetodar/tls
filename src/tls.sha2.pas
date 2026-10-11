unit tls.sha2;

{ SHA-256 / SHA-384 / SHA-512 (FIPS 180-4) in pure Pascal.
  Incremental input (Update/Final) and one-shot (SHA256/SHA384/SHA512).
  SHA-384 is the same SHA-512 with a different IV and a 48-byte digest.
  Utilities: BytesToHex / HexToBytes. }

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

type
  { Base SHA-2 class: block buffering, padding, message length. }
  TSHA2Base = class abstract
  protected
    FBuf: TBytes;
    FBufLen: LongWord;
    FTotalLen: QWord;
    FFinalized: Boolean;
    FOutLen: Integer;
    FBlockLen: Integer;
    procedure ProcessBlock(const Block: array of Byte); virtual; abstract;
    procedure WriteDigest(var Digest: TBytes); virtual; abstract;
  public
    constructor Create;
    procedure Update(const Data: TBytes);
    procedure Update(const Data: TBytes; Offset, Count: Integer);
    procedure Final(var Digest: TBytes);
  end;

  TSHA256 = class(TSHA2Base)
  protected
    FState: array[0..7] of LongWord;
    procedure ProcessBlock(const Block: array of Byte); override;
    procedure WriteDigest(var Digest: TBytes); override;
  public
    constructor Create;
  end;

  TSHA512 = class(TSHA2Base)
  protected
    FState: array[0..7] of QWord;
    procedure ProcessBlock(const Block: array of Byte); override;
    procedure WriteDigest(var Digest: TBytes); override;
  public
    constructor Create;
  end;

  { SHA-384 = SHA-512 with a different IV and a 48-byte digest. }
  TSHA384 = class(TSHA512)
  public
    constructor Create;
  end;

function SHA256(const Data: TBytes): TBytes;
function SHA256Str(const S: string): TBytes;
function SHA384(const Data: TBytes): TBytes;
function SHA384Str(const S: string): TBytes;
function SHA512(const Data: TBytes): TBytes;
function SHA512Str(const S: string): TBytes;

{ Hex representation: Count = 0 — all bytes, otherwise the first Count bytes. }
function BytesToHex(const B: TBytes; Count: Integer = 0): string;
function HexToBytes(const S: string): TBytes;

implementation

function Ror32(x: LongWord; n: LongInt): LongWord;
begin
  Result := (x shr n) or (x shl (32 - n));
end;

function Ror64(x: QWord; n: LongInt): QWord;
begin
  Result := (x shr n) or (x shl (64 - n));
end;

{--- TSHA2Base ---}

constructor TSHA2Base.Create;
begin
  inherited Create;
  FBufLen := 0;
  FTotalLen := 0;
  FFinalized := False;
end;

procedure TSHA2Base.Update(const Data: TBytes);
begin
  Update(Data, 0, Length(Data));
end;

procedure TSHA2Base.Update(const Data: TBytes; Offset, Count: Integer);
var
  i, n: LongWord;
begin
  if FFinalized then
    raise Exception.Create('TSHA2: Update after Final');
  if (Offset < 0) or (Count < 0) or (Offset + Count > Length(Data)) then
    raise Exception.Create('TSHA2: Update: invalid range');
  i := 0;
  while i < Count do
  begin
    if FBufLen = FBlockLen then
    begin
      ProcessBlock(FBuf);
      FBufLen := 0;
    end;
    n := FBlockLen - FBufLen;
    if n > Count - i then
      n := Count - i;
    Move(PByte(Data)[Offset + i], FBuf[FBufLen], n);
    Inc(FBufLen, n);
    Inc(i, n);
  end;
  Inc(FTotalLen, Count);
end;

procedure TSHA2Base.Final(var Digest: TBytes);
var
  bitLen: QWord;
  i: LongWord;
begin
  if FFinalized then
    raise Exception.Create('TSHA2: Final called twice');
  FFinalized := True;
  bitLen := FTotalLen * 8;
  { If Update ended exactly on a block boundary, the block has not yet been processed:
    process it before writing byte $80 (otherwise the write would go past FBuf). }
  if FBufLen = FBlockLen then
  begin
    ProcessBlock(FBuf);
    FBufLen := 0;
  end;
  FBuf[FBufLen] := $80;
  Inc(FBufLen);
  if FBufLen > FBlockLen - 8 then
  begin
    while FBufLen < FBlockLen do
    begin
      FBuf[FBufLen] := 0;
      Inc(FBufLen);
    end;
    ProcessBlock(FBuf);
    FBufLen := 0;
  end;
  while FBufLen < FBlockLen - 8 do
  begin
    FBuf[FBufLen] := 0;
    Inc(FBufLen);
  end;
  for i := 0 to 7 do
    FBuf[FBlockLen - 8 + i] := Byte(bitLen shr (56 - 8 * i));
  ProcessBlock(FBuf);
  WriteDigest(Digest);
end;


{--- TSHA256 ---}

constructor TSHA256.Create;
begin
  inherited Create;
  FBlockLen := 64;
  FOutLen := 32;
  SetLength(FBuf, 64);
  FState[0] := $6A09E667;
  FState[1] := $BB67AE85;
  FState[2] := $3C6EF372;
  FState[3] := $A54FF53A;
  FState[4] := $510E527F;
  FState[5] := $9B05688C;
  FState[6] := $1F83D9AB;
  FState[7] := $5BE0CD19;
end;

procedure TSHA256.ProcessBlock(const Block: array of Byte);
const
  K: array[0..63] of LongWord = (
    $428A2F98, $71374491, $B5C0FBCF, $E9B5DBA5, $3956C25B, $59F111F1, $923F82A4, $AB1C5ED5,
    $D807AA98, $12835B01, $243185BE, $550C7DC3, $72BE5D74, $80DEB1FE, $9BDC06A7, $C19BF174,
    $E49B69C1, $EFBE4786, $0FC19DC6, $240CA1CC, $2DE92C6F, $4A7484AA, $5CB0A9DC, $76F988DA,
    $983E5152, $A831C66D, $B00327C8, $BF597FC7, $C6E00BF3, $D5A79147, $06CA6351, $14292967,
    $27B70A85, $2E1B2138, $4D2C6DFC, $53380D13, $650A7354, $766A0ABB, $81C2C92E, $92722C85,
    $A2BFE8A1, $A81A664B, $C24B8B70, $C76C51A3, $D192E819, $D6990624, $F40E3585, $106AA070,
    $19A4C116, $1E376C08, $2748774C, $34B0BCB5, $391C0CB3, $4ED8AA4A, $5B9CCA4F, $682E6FF3,
    $748F82EE, $78A5636F, $84C87814, $8CC70208, $90BEFFFA, $A4506CEB, $BEF9A3F7, $C67178F2);
var
  W: array[0..63] of LongWord;
  a, b, c, d, e, f, g, h, t1, t2: LongWord;
  i: Integer;
begin
  for i := 0 to 15 do
    W[i] := (LongWord(Block[4 * i]) shl 24) or
            (LongWord(Block[4 * i + 1]) shl 16) or
            (LongWord(Block[4 * i + 2]) shl 8) or
            LongWord(Block[4 * i + 3]);
  for i := 16 to 63 do
    W[i] := W[i - 16]
          + (Ror32(W[i - 15], 7) xor Ror32(W[i - 15], 18) xor (W[i - 15] shr 3))
           + W[i - 7]
          + (Ror32(W[i - 2], 17) xor Ror32(W[i - 2], 19) xor (W[i - 2] shr 10));
  a := FState[0]; b := FState[1]; c := FState[2]; d := FState[3];
  e := FState[4]; f := FState[5]; g := FState[6]; h := FState[7];
  for i := 0 to 63 do
  begin
    t1 := h + (Ror32(e, 6) xor Ror32(e, 11) xor Ror32(e, 25))
        + (LongWord(e and f) xor (LongWord(not e) and g))
        + K[i] + W[i];
    t2 := (Ror32(a, 2) xor Ror32(a, 13) xor Ror32(a, 22))
        + (LongWord(a and b) xor LongWord(a and c) xor LongWord(b and c));
    h := g; g := f; f := e; e := d + t1;
    d := c; c := b; b := a; a := t1 + t2;
  end;
  FState[0] := FState[0] + a;
  FState[1] := FState[1] + b;
  FState[2] := FState[2] + c;
  FState[3] := FState[3] + d;
  FState[4] := FState[4] + e;
  FState[5] := FState[5] + f;
  FState[6] := FState[6] + g;
  FState[7] := FState[7] + h;
end;

procedure TSHA256.WriteDigest(var Digest: TBytes);
var
  i: Integer;
begin
  SetLength(Digest, 32);
  for i := 0 to 7 do
  begin
    Digest[i * 4]     := Byte(FState[i] shr 24);
    Digest[i * 4 + 1] := Byte(FState[i] shr 16);
    Digest[i * 4 + 2] := Byte(FState[i] shr 8);
    Digest[i * 4 + 3] := Byte(FState[i]);
  end;
end;

{--- TSHA512 ---}

constructor TSHA512.Create;
begin
  inherited Create;
  FBlockLen := 128;
  FOutLen := 64;
  SetLength(FBuf, 128);
  FState[0] := $6A09E667F3BCC908;
  FState[1] := $BB67AE8584CAA73B;
  FState[2] := $3C6EF372FE94F82B;
  FState[3] := $A54FF53A5F1D36F1;
  FState[4] := $510E527FADE682D1;
  FState[5] := $9B05688C2B3E6C1F;
  FState[6] := $1F83D9ABFB41BD6B;
  FState[7] := $5BE0CD19137E2179;
end;

procedure TSHA512.ProcessBlock(const Block: array of Byte);
const
  K: array[0..79] of QWord = (
    $428A2F98D728AE22, $7137449123EF65CD, $B5C0FBCFEC4D3B2F, $E9B5DBA58189DBBC,
    $3956C25BF348B538, $59F111F1B605D019, $923F82A4AF194F9B, $AB1C5ED5DA6D8118,
    $D807AA98A3030242, $12835B0145706FBE, $243185BE4EE4B28C, $550C7DC3D5FFB4E2,
    $72BE5D74F27B896F, $80DEB1FE3B1696B1, $9BDC06A725C71235, $C19BF174CF692694,
    $E49B69C19EF14AD2, $EFBE4786384F25E3, $0FC19DC68B8CD5B5, $240CA1CC77AC9C65,
    $2DE92C6F592B0275, $4A7484AA6EA6E483, $5CB0A9DCBD41FBD4, $76F988DA831153B5,
    $983E5152EE66DFAB, $A831C66D2DB43210, $B00327C898FB213F, $BF597FC7BEEF0EE4,
    $C6E00BF33DA88FC2, $D5A79147930AA725, $06CA6351E003826F, $142929670A0E6E70,
    $27B70A8546D22FFC, $2E1B21385C26C926, $4D2C6DFC5AC42AED, $53380D139D95B3DF,
    $650A73548BAF63DE, $766A0ABB3C77B2A8, $81C2C92E47EDAEE6, $92722C851482353B,
    $A2BFE8A14CF10364, $A81A664BBC423001, $C24B8B70D0F89791, $C76C51A30654BE30,
    $D192E819D6EF5218, $D69906245565A910, $F40E35855771202A, $106AA07032BBD1B8,
    $19A4C116B8D2D0C8, $1E376C085141AB53, $2748774CDF8EEB99, $34B0BCB5E19B48A8,
    $391C0CB3C5C95A63, $4ED8AA4AE3418ACB, $5B9CCA4F7763E373, $682E6FF3D6B2B8A3,
    $748F82EE5DEFB2FC, $78A5636F43172F60, $84C87814A1F0AB72, $8CC702081A6439EC,
    $90BEFFFA23631E28, $A4506CEBDE82BDE9, $BEF9A3F7B2C67915, $C67178F2E372532B,
    $CA273ECEEA26619C, $D186B8C721C0C207, $EADA7DD6CDE0EB1E, $F57D4F7FEE6ED178,
    $06F067AA72176FBA, $0A637DC5A2C898A6, $113F9804BEF90DAE, $1B710B35131C471B,
    $28DB77F523047D84, $32CAAB7B40C72493, $3C9EBE0A15C9BEBC, $431D67C49C100D4C,
    $4CC5D4BECB3E42B6, $597F299CFC657E2A, $5FCB6FAB3AD6FAEC, $6C44198C4A475817);
var
  W: array[0..79] of QWord;
  a, b, c, d, e, f, g, h, t1, t2: QWord;
  i: Integer;
begin
  for i := 0 to 15 do
    W[i] := (QWord(Block[8 * i]) shl 56) or
            (QWord(Block[8 * i + 1]) shl 48) or
            (QWord(Block[8 * i + 2]) shl 40) or
            (QWord(Block[8 * i + 3]) shl 32) or
            (QWord(Block[8 * i + 4]) shl 24) or
            (QWord(Block[8 * i + 5]) shl 16) or
            (QWord(Block[8 * i + 6]) shl 8) or
            QWord(Block[8 * i + 7]);
  for i := 16 to 79 do
    W[i] := W[i - 16]
          + (Ror64(W[i - 15], 1) xor Ror64(W[i - 15], 8) xor (W[i - 15] shr 7))
          + W[i - 7]
          + (Ror64(W[i - 2], 19) xor Ror64(W[i - 2], 61) xor (W[i - 2] shr 6));
  a := FState[0]; b := FState[1]; c := FState[2]; d := FState[3];
  e := FState[4]; f := FState[5]; g := FState[6]; h := FState[7];
  for i := 0 to 79 do
  begin
    t1 := h + (Ror64(e, 14) xor Ror64(e, 18) xor Ror64(e, 41))
        + (QWord(e and f) xor (QWord(not e) and g))
        + K[i] + W[i];
    t2 := (Ror64(a, 28) xor Ror64(a, 34) xor Ror64(a, 39))
        + (QWord(a and b) xor QWord(a and c) xor QWord(b and c));
    h := g; g := f; f := e; e := d + t1;
    d := c; c := b; b := a; a := t1 + t2;
  end;
  FState[0] := FState[0] + a;
  FState[1] := FState[1] + b;
  FState[2] := FState[2] + c;
  FState[3] := FState[3] + d;
  FState[4] := FState[4] + e;
  FState[5] := FState[5] + f;
  FState[6] := FState[6] + g;
  FState[7] := FState[7] + h;
end;

procedure TSHA512.WriteDigest(var Digest: TBytes);
var
  i: Integer;
begin
  SetLength(Digest, FOutLen);
  for i := 0 to FOutLen div 8 - 1 do
  begin
    Digest[i * 8]     := Byte(FState[i] shr 56);
    Digest[i * 8 + 1] := Byte(FState[i] shr 48);
    Digest[i * 8 + 2] := Byte(FState[i] shr 40);
    Digest[i * 8 + 3] := Byte(FState[i] shr 32);
    Digest[i * 8 + 4] := Byte(FState[i] shr 24);
    Digest[i * 8 + 5] := Byte(FState[i] shr 16);
    Digest[i * 8 + 6] := Byte(FState[i] shr 8);
    Digest[i * 8 + 7] := Byte(FState[i]);
  end;
end;

{--- TSHA384 ---}

constructor TSHA384.Create;
begin
  inherited Create;
  FOutLen := 48;
  FState[0] := $CBBB9D5DC1059ED8;
  FState[1] := $629A292A367CD507;
  FState[2] := $9159015A3070DD17;
  FState[3] := $152FECD8F70E5939;
  FState[4] := $67332667FFC00B31;
  FState[5] := $8EB44A8768581511;
  FState[6] := $DB0C2E0D64F98FA7;
  FState[7] := $47B5481DBEFA4FA4;
end;

{--- one-shot ---}

function SHA256(const Data: TBytes): TBytes;
var
  H: TSHA256;
begin
  H := TSHA256.Create;
  try
    H.Update(Data);
    H.Final(Result);
  finally
    H.Free;
  end;
end;

function SHA256Str(const S: string): TBytes;
begin
  Result := SHA256(TEncoding.UTF8.GetBytes(S));
end;

function SHA384(const Data: TBytes): TBytes;
var
  H: TSHA384;
begin
  H := TSHA384.Create;
  try
    H.Update(Data);
    H.Final(Result);
  finally
    H.Free;
  end;
end;

function SHA384Str(const S: string): TBytes;
begin
  Result := SHA384(TEncoding.UTF8.GetBytes(S));
end;

function SHA512(const Data: TBytes): TBytes;
var
  H: TSHA512;
begin
  H := TSHA512.Create;
  try
    H.Update(Data);
    H.Final(Result);
  finally
    H.Free;
  end;
end;

function SHA512Str(const S: string): TBytes;
begin
  Result := SHA512(TEncoding.UTF8.GetBytes(S));
end;

{--- hex ---}

const
  HexDigits = '0123456789abcdef';

function BytesToHex(const B: TBytes; Count: Integer = 0): string;
var
  i, n: Integer;
begin
  if Count = 0 then
    n := Length(B)
  else
    n := Count;
  if n > Length(B) then
    n := Length(B);
  SetLength(Result, n * 2);
  for i := 0 to n - 1 do
  begin
    Result[2 * i + 1] := HexDigits[Integer(B[i] shr 4) + 1];
    Result[2 * i + 2] := HexDigits[Integer(B[i] and $0F) + 1];
  end;
end;

function HexToBytes(const S: string): TBytes;
var
  i: Integer;
  function HexVal(c: Char): Integer;
  begin
    if (c >= '0') and (c <= '9') then
      Result := Ord(c) - Ord('0')
    else if (c >= 'a') and (c <= 'f') then
      Result := Ord(c) - Ord('a') + 10
    else if (c >= 'A') and (c <= 'F') then
      Result := Ord(c) - Ord('A') + 10
    else
      raise Exception.Create('HexToBytes: invalid char "' + c + '"');
  end;
begin
  if Length(S) mod 2 <> 0 then
    raise Exception.Create('HexToBytes: odd length');
  SetLength(Result, Length(S) div 2);
  for i := 0 to Length(Result) - 1 do
    Result[i] := HexVal(S[2 * i + 1]) * 16 + HexVal(S[2 * i + 2]);
end;

end.
