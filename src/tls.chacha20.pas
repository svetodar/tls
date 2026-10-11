unit tls.chacha20;

{ ChaCha20 (RFC 8439), Poly1305 (RFC 8439) and AEAD ChaCha20-Poly1305.
 Used in TLS 1.3 (TLS_CHACHA20_POLY1305_SHA256) and as
 a fallback AEAD.

 Implementation for task 05 (docs/tasks/05-chacha20.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

{ One 64-byte ChaCha20 block. Key — 32 bytes, Nonce — 12 bytes. }
function ChaCha20Block(const Key, Nonce: TBytes; Counter: LongWord): TBytes;
{ ChaCha20 stream (encrypt == decrypt). Counter — initial block number. }
function ChaCha20Xor(const Key, Nonce: TBytes; Counter: LongWord;
  const Data: TBytes): TBytes;

{ Poly1305: Key — 32 bytes, MAC — 16 bytes. }
function Poly1305(const Key, Data: TBytes): TBytes;

{ AEAD ChaCha20-Poly1305 (RFC 8439 §2.8). }
procedure ChaCha20Poly1305Encrypt(const Key, Nonce, AAD, Plain: TBytes;
  out Cipher, Tag: TBytes);
function ChaCha20Poly1305Decrypt(const Key, Nonce, AAD, Cipher, Tag: TBytes;
  out Plain: TBytes): Boolean;

type
  { Incremental Poly1305: Create(key) -> Update(data) -> Final. }
  TPoly1305 = class
  private
    FR: array[0..4] of LongWord;
    FH: array[0..4] of LongWord;
    FPad: array[0..3] of LongWord;
    FBuffer: array[0..15] of Byte;
    FLeftover: Integer;
    procedure Blocks(const M: array of Byte; Offset, Count: Integer; Final: Boolean);
  public
    constructor Create(const Key: TBytes);
    procedure Update(const Data: TBytes);
    function Final: TBytes;
  end;

implementation

function RotL32(x: LongWord; n: Integer): LongWord; inline;
begin
  Result := (x shl n) or (x shr (32 - n));
end;

function LoadLE32(const B: array of Byte; Off: Integer): LongWord; inline;
begin
  Result := LongWord(B[Off]) or (LongWord(B[Off + 1]) shl 8) or
            (LongWord(B[Off + 2]) shl 16) or (LongWord(B[Off + 3]) shl 24);
end;

procedure StoreLE32(var B: TBytes; Off: Integer; V: LongWord); inline;
begin
  B[Off] := Byte(V);
  B[Off + 1] := Byte(V shr 8);
  B[Off + 2] := Byte(V shr 16);
  B[Off + 3] := Byte(V shr 24);
end;

{--- ChaCha20 ---}

procedure QR(var a, b, c, d: LongWord); inline;
begin
  a := a + b; d := RotL32(d xor a, 16);
  c := c + d; b := RotL32(b xor c, 12);
  a := a + b; d := RotL32(d xor a, 8);
  c := c + d; b := RotL32(b xor c, 7);
end;

function ChaCha20Block(const Key, Nonce: TBytes; Counter: LongWord): TBytes;
var
  Init, X: array[0..15] of LongWord;
  i, Round: Integer;
begin
  if Length(Key) <> 32 then
    raise EArgumentException.Create('ChaCha20: key is not 32 bytes');
  if Length(Nonce) <> 12 then
    raise EArgumentException.Create('ChaCha20: nonce is not 12 bytes');

  Init[0] := $61707865;
  Init[1] := $3320646e;
  Init[2] := $79622d32;
  Init[3] := $6b206574;
  for i := 0 to 7 do
    Init[4 + i] := LoadLE32(Key, 4 * i);
  Init[12] := Counter;
  for i := 0 to 2 do
    Init[13 + i] := LoadLE32(Nonce, 4 * i);

  X := Init;
  for Round := 0 to 9 do
  begin
    QR(X[0], X[4], X[8], X[12]);
    QR(X[1], X[5], X[9], X[13]);
    QR(X[2], X[6], X[10], X[14]);
    QR(X[3], X[7], X[11], X[15]);
    QR(X[0], X[5], X[10], X[15]);
    QR(X[1], X[6], X[11], X[12]);
    QR(X[2], X[7], X[8], X[13]);
    QR(X[3], X[4], X[9], X[14]);
  end;

  SetLength(Result, 64);
  for i := 0 to 15 do
    StoreLE32(Result, 4 * i, X[i] + Init[i]);
end;

function ChaCha20Xor(const Key, Nonce: TBytes; Counter: LongWord;
  const Data: TBytes): TBytes;
var
  Block: TBytes;
  off, n, i: Integer;
  ctr: LongWord;
begin
  SetLength(Result, Length(Data));
  off := 0;
  ctr := Counter;
  while off < Length(Data) do
  begin
    Block := ChaCha20Block(Key, Nonce, ctr);
    n := 16 * 4;
    if n > Length(Data) - off then
      n := Length(Data) - off;
    for i := 0 to n - 1 do
      Result[off + i] := Data[off + i] xor Block[i];
    Inc(off, 64);
    Inc(ctr);
  end;
end;

{--- Poly1305 ---}

constructor TPoly1305.Create(const Key: TBytes);
begin
  inherited Create;
  if Length(Key) <> 32 then
    raise EArgumentException.Create('Poly1305: key is not 32 bytes');
  FR[0] := LoadLE32(Key, 0) and $3ffffff;
  FR[1] := (LoadLE32(Key, 3) shr 2) and $3ffff03;
  FR[2] := (LoadLE32(Key, 6) shr 4) and $3ffc0ff;
  FR[3] := (LoadLE32(Key, 9) shr 6) and $3f03fff;
  FR[4] := (LoadLE32(Key, 12) shr 8) and $00fffff;
  FPad[0] := LoadLE32(Key, 16);
  FPad[1] := LoadLE32(Key, 20);
  FPad[2] := LoadLE32(Key, 24);
  FPad[3] := LoadLE32(Key, 28);
  FLeftover := 0;
  FillChar(FH, SizeOf(FH), 0);
end;

procedure TPoly1305.Blocks(const M: array of Byte; Offset, Count: Integer;
  Final: Boolean);
var
  Hibit, r0, r1, r2, r3, r4, s1, s2, s3, s4: LongWord;
  h0, h1, h2, h3, h4, t0, t1, t2, t3, c: LongWord;
  d0, d1, d2, d3, d4: QWord;
  Off: Integer;
begin
  Hibit := 0;
  if not Final then
    Hibit := 1 shl 24;
  r0 := FR[0]; r1 := FR[1]; r2 := FR[2]; r3 := FR[3]; r4 := FR[4];
  s1 := r1 * 5; s2 := r2 * 5; s3 := r3 * 5; s4 := r4 * 5;
  h0 := FH[0]; h1 := FH[1]; h2 := FH[2]; h3 := FH[3]; h4 := FH[4];

  Off := Offset;
  while Count >= 16 do
  begin
    t0 := LoadLE32(M, Off);
    t1 := LoadLE32(M, Off + 4);
    t2 := LoadLE32(M, Off + 8);
    t3 := LoadLE32(M, Off + 12);
    h0 := h0 + (t0 and $3ffffff);
    h1 := h1 + (((t0 shr 26) or (t1 shl 6)) and $3ffffff);
    h2 := h2 + (((t1 shr 20) or (t2 shl 12)) and $3ffffff);
    h3 := h3 + (((t2 shr 14) or (t3 shl 18)) and $3ffffff);
    h4 := h4 + ((t3 shr 8) or Hibit);

    d0 := QWord(h0) * r0 + QWord(h1) * s4 + QWord(h2) * s3 +
          QWord(h3) * s2 + QWord(h4) * s1;
    d1 := QWord(h0) * r1 + QWord(h1) * r0 + QWord(h2) * s4 +
          QWord(h3) * s3 + QWord(h4) * s2;
    d2 := QWord(h0) * r2 + QWord(h1) * r1 + QWord(h2) * r0 +
          QWord(h3) * s4 + QWord(h4) * s3;
    d3 := QWord(h0) * r3 + QWord(h1) * r2 + QWord(h2) * r1 +
          QWord(h3) * r0 + QWord(h4) * s4;
    d4 := QWord(h0) * r4 + QWord(h1) * r3 + QWord(h2) * r2 +
          QWord(h3) * r1 + QWord(h4) * r0;

    c := LongWord(d0 shr 26); h0 := LongWord(d0) and $3ffffff; d1 := d1 + c;
    c := LongWord(d1 shr 26); h1 := LongWord(d1) and $3ffffff; d2 := d2 + c;
    c := LongWord(d2 shr 26); h2 := LongWord(d2) and $3ffffff; d3 := d3 + c;
    c := LongWord(d3 shr 26); h3 := LongWord(d3) and $3ffffff; d4 := d4 + c;
    c := LongWord(d4 shr 26); h4 := LongWord(d4) and $3ffffff;
    h0 := h0 + c * 5;
    c := h0 shr 26; h0 := h0 and $3ffffff; h1 := h1 + c;

    Inc(Off, 16);
    Dec(Count, 16);
  end;

  FH[0] := h0; FH[1] := h1; FH[2] := h2; FH[3] := h3; FH[4] := h4;
end;

procedure TPoly1305.Update(const Data: TBytes);
var
  i, full, take: Integer;
  rest: TBytes;
begin
  if Length(Data) = 0 then
    Exit;
  rest := Data;
  if FLeftover > 0 then
  begin
    take := 16 - FLeftover;
    if take > Length(rest) then
      take := Length(rest);
    Move(rest[0], FBuffer[FLeftover], take);
    Inc(FLeftover, take);
    if FLeftover = 16 then
    begin
      Blocks(FBuffer, 0, 16, False);
      FLeftover := 0;
    end;
    rest := Copy(rest, take, Length(rest) - take);
    if Length(rest) = 0 then
      Exit;
  end;
  full := (Length(rest) div 16) * 16;
  if full > 0 then
    Blocks(rest, 0, full, False);
  i := Length(rest) - full;
  if i > 0 then
  begin
    FLeftover := i;
    Move(rest[full], FBuffer[0], i);
  end;
end;

function TPoly1305.Final: TBytes;
var
  h0, h1, h2, h3, h4, g0, g1, g2, g3, g4, c, mask: LongWord;
  f: QWord;
  i: Integer;
begin
  if FLeftover > 0 then
  begin
    FBuffer[FLeftover] := 1;
    for i := FLeftover + 1 to 15 do
      FBuffer[i] := 0;
    Blocks(FBuffer, 0, 16, True);
  end;

  h0 := FH[0]; h1 := FH[1]; h2 := FH[2]; h3 := FH[3]; h4 := FH[4];
  { Full carry addition. }
  c := h1 shr 26; h1 := h1 and $3ffffff; h2 := h2 + c;
  c := h2 shr 26; h2 := h2 and $3ffffff; h3 := h3 + c;
  c := h3 shr 26; h3 := h3 and $3ffffff; h4 := h4 + c;
  c := h4 shr 26; h4 := h4 and $3ffffff; h0 := h0 + c * 5;
  c := h0 shr 26; h0 := h0 and $3ffffff; h1 := h1 + c;

  { h + (-p). }
  g0 := h0 + 5; c := g0 shr 26; g0 := g0 and $3ffffff;
  g1 := h1 + c; c := g1 shr 26; g1 := g1 and $3ffffff;
  g2 := h2 + c; c := g2 shr 26; g2 := g2 and $3ffffff;
  g3 := h3 + c; c := g3 shr 26; g3 := g3 and $3ffffff;
  g4 := h4 + c - (1 shl 26);

  { If h < p — keep h, otherwise h + (-p). }
  mask := (g4 shr 31) - 1;
  g0 := g0 and mask; g1 := g1 and mask; g2 := g2 and mask;
  g3 := g3 and mask; g4 := g4 and mask;
  mask := not mask;
  h0 := (h0 and mask) or g0;
  h1 := (h1 and mask) or g1;
  h2 := (h2 and mask) or g2;
  h3 := (h3 and mask) or g3;
  h4 := (h4 and mask) or g4;

  { h mod 2^128. }
  h0 := h0 or (h1 shl 26);
  h1 := (h1 shr 6) or (h2 shl 20);
  h2 := (h2 shr 12) or (h3 shl 14);
  h3 := (h3 shr 18) or (h4 shl 8);

  { (h + pad) mod 2^128. }
  f := QWord(h0) + FPad[0]; h0 := LongWord(f);
  f := QWord(h1) + FPad[1] + (f shr 32); h1 := LongWord(f);
  f := QWord(h2) + FPad[2] + (f shr 32); h2 := LongWord(f);
  f := QWord(h3) + FPad[3] + (f shr 32); h3 := LongWord(f);

  SetLength(Result, 16);
  StoreLE32(Result, 0, h0);
  StoreLE32(Result, 4, h1);
  StoreLE32(Result, 8, h2);
  StoreLE32(Result, 12, h3);
end;

function Poly1305(const Key, Data: TBytes): TBytes;
var
  P: TPoly1305;
begin
  P := TPoly1305.Create(Key);
  try
    P.Update(Data);
    Result := P.Final;
  finally
    P.Free;
  end;
end;

{--- AEAD ---}

function Pad16(const Data: TBytes): TBytes;
var
  n: Integer;
begin
  n := Length(Data) mod 16;
  if n = 0 then
    Exit(nil);
  SetLength(Result, 16 - n);
  FillChar(Result[0], Length(Result), 0);
end;

procedure Append(var Dst: TBytes; const Src: TBytes);
var
  old: Integer;
begin
  old := Length(Dst);
  SetLength(Dst, old + Length(Src));
  if Length(Src) > 0 then
    Move(Src[0], Dst[old], Length(Src));
end;

function AeadMacData(const AAD, Cipher: TBytes): TBytes;
var
  i: Integer;
begin
  Result := nil;
  Append(Result, AAD);
  Append(Result, Pad16(AAD));
  Append(Result, Cipher);
  Append(Result, Pad16(Cipher));
  SetLength(Result, Length(Result) + 16);
  for i := 0 to 7 do
  begin
    Result[Length(Result) - 16 + i] := Byte(QWord(Length(AAD)) shr (8 * i));
    Result[Length(Result) - 8 + i] := Byte(QWord(Length(Cipher)) shr (8 * i));
  end;
end;

procedure ChaCha20Poly1305Encrypt(const Key, Nonce, AAD, Plain: TBytes;
  out Cipher, Tag: TBytes);
var
  Otk, PolyKey, MacData: TBytes;
begin
  Otk := ChaCha20Block(Key, Nonce, 0);
  PolyKey := Copy(Otk, 0, 32);
  Cipher := ChaCha20Xor(Key, Nonce, 1, Plain);
  MacData := AeadMacData(AAD, Cipher);
  Tag := Poly1305(PolyKey, MacData);
end;

function ConstantTimeEq(const A, B: TBytes): Boolean;
var
  i: Integer;
  d: Byte;
begin
  Result := False;
  if Length(A) <> Length(B) then
    Exit;
  d := 0;
  for i := 0 to Length(A) - 1 do
    d := d or (A[i] xor B[i]);
  Result := d = 0;
end;

function ChaCha20Poly1305Decrypt(const Key, Nonce, AAD, Cipher, Tag: TBytes;
  out Plain: TBytes): Boolean;
var
  Otk, PolyKey, MacData, Tag2: TBytes;
begin
  Otk := ChaCha20Block(Key, Nonce, 0);
  PolyKey := Copy(Otk, 0, 32);
  MacData := AeadMacData(AAD, Cipher);
  Tag2 := Poly1305(PolyKey, MacData);
  Result := ConstantTimeEq(Tag, Tag2);
  if Result then
    Plain := ChaCha20Xor(Key, Nonce, 1, Cipher)
  else
    Plain := nil;
end;

end.
