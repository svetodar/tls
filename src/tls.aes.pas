{ SPDX-License-Identifier: Apache-2.0 }
unit tls.aes;

{ AES-128/192/256: core (FIPS-197), modes CBC (SP 800-38A) and
  GCM (SP 800-38D). Used in TLS suites AES-CBC/AES-GCM.

  API:
    TAES.EncryptBlock / DecryptBlock — one block (ECB);
    AESCBCEncrypt / AESCBCDecrypt — CBC with PKCS#7;
    AESCBCEncryptNoPad / AESCBCDecryptNoPad — CBC without padding (TLS record);
    AESGCMEncrypt / AESGCMDecrypt — AEAD with AAD and 16-byte tag.

  Implementation for task 04 (docs/tasks/04-aes.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

type
  EAESError = class(Exception);

  { AES class with precomputed round keys. }
  TAES = class
  private
    FRounds: Integer;
    FRK: array[0..59] of LongWord;
    procedure ExpandKey(const Key: TBytes);
    procedure AddRoundKey(const State: TBytes; Round: Integer);
  public
    constructor Create(const Key: TBytes);
    { One 16-byte block. }
    procedure EncryptBlock(const InBlock: TBytes; out OutBlock: TBytes);
    procedure DecryptBlock(const InBlock: TBytes; out OutBlock: TBytes);
  end;

{ ECB helpers. }
function AESBlockEncrypt(const Key, Block: TBytes): TBytes;
function AESBlockDecrypt(const Key, Block: TBytes): TBytes;
function AESKeySizeValid(const Key: TBytes): Boolean;

{ CBC with PKCS#7 padding. }
function AESCBCEncrypt(const Key, IV, Plain: TBytes): TBytes;
function AESCBCDecrypt(const Key, IV, Cipher: TBytes): TBytes;

{ CBC without padding: data length must be a multiple of 16. }
function AESCBCEncryptNoPad(const Key, IV, Plain: TBytes): TBytes;
function AESCBCDecryptNoPad(const Key, IV, Cipher: TBytes): TBytes;

{ GCM: Cipher and Tag with 16-byte tag. }
procedure AESGCMEncrypt(const Key, IV, AAD, Plain: TBytes;
  out Cipher, Tag: TBytes);
{ True on successful tag verification. }
function AESGCMDecrypt(const Key, IV, AAD, Cipher, Tag: TBytes;
  out Plain: TBytes): Boolean;

implementation

const
  SBox: array[0..255] of Byte = (
    $63,$7c,$77,$7b,$f2,$6b,$6f,$c5,$30,$01,$67,$2b,$fe,$d7,$ab,$76,
    $ca,$82,$c9,$7d,$fa,$59,$47,$f0,$ad,$d4,$a2,$af,$9c,$a4,$72,$c0,
    $b7,$fd,$93,$26,$36,$3f,$f7,$cc,$34,$a5,$e5,$f1,$71,$d8,$31,$15,
    $04,$c7,$23,$c3,$18,$96,$05,$9a,$07,$12,$80,$e2,$eb,$27,$b2,$75,
    $09,$83,$2c,$1a,$1b,$6e,$5a,$a0,$52,$3b,$d6,$b3,$29,$e3,$2f,$84,
    $53,$d1,$00,$ed,$20,$fc,$b1,$5b,$6a,$cb,$be,$39,$4a,$4c,$58,$cf,
    $d0,$ef,$aa,$fb,$43,$4d,$33,$85,$45,$f9,$02,$7f,$50,$3c,$9f,$a8,
    $51,$a3,$40,$8f,$92,$9d,$38,$f5,$bc,$b6,$da,$21,$10,$ff,$f3,$d2,
    $cd,$0c,$13,$ec,$5f,$97,$44,$17,$c4,$a7,$7e,$3d,$64,$5d,$19,$73,
    $60,$81,$4f,$dc,$22,$2a,$90,$88,$46,$ee,$b8,$14,$de,$5e,$0b,$db,
    $e0,$32,$3a,$0a,$49,$06,$24,$5c,$c2,$d3,$ac,$62,$91,$95,$e4,$79,
    $e7,$c8,$37,$6d,$8d,$d5,$4e,$a9,$6c,$56,$f4,$ea,$65,$7a,$ae,$08,
    $ba,$78,$25,$2e,$1c,$a6,$b4,$c6,$e8,$dd,$74,$1f,$4b,$bd,$8b,$8a,
    $70,$3e,$b5,$66,$48,$03,$f6,$0e,$61,$35,$57,$b9,$86,$c1,$1d,$9e,
    $e1,$f8,$98,$11,$69,$d9,$8e,$94,$9b,$1e,$87,$e9,$ce,$55,$28,$df,
    $8c,$a1,$89,$0d,$bf,$e6,$42,$68,$41,$99,$2d,$0f,$b0,$54,$bb,$16);

  InvSBox: array[0..255] of Byte = (
    $52,$09,$6a,$d5,$30,$36,$a5,$38,$bf,$40,$a3,$9e,$81,$f3,$d7,$fb,
    $7c,$e3,$39,$82,$9b,$2f,$ff,$87,$34,$8e,$43,$44,$c4,$de,$e9,$cb,
    $54,$7b,$94,$32,$a6,$c2,$23,$3d,$ee,$4c,$95,$0b,$42,$fa,$c3,$4e,
    $08,$2e,$a1,$66,$28,$d9,$24,$b2,$76,$5b,$a2,$49,$6d,$8b,$d1,$25,
    $72,$f8,$f6,$64,$86,$68,$98,$16,$d4,$a4,$5c,$cc,$5d,$65,$b6,$92,
    $6c,$70,$48,$50,$fd,$ed,$b9,$da,$5e,$15,$46,$57,$a7,$8d,$9d,$84,
    $90,$d8,$ab,$00,$8c,$bc,$d3,$0a,$f7,$e4,$58,$05,$b8,$b3,$45,$06,
    $d0,$2c,$1e,$8f,$ca,$3f,$0f,$02,$c1,$af,$bd,$03,$01,$13,$8a,$6b,
    $3a,$91,$11,$41,$4f,$67,$dc,$ea,$97,$f2,$cf,$ce,$f0,$b4,$e6,$73,
    $96,$ac,$74,$22,$e7,$ad,$35,$85,$e2,$f9,$37,$e8,$1c,$75,$df,$6e,
    $47,$f1,$1a,$71,$1d,$29,$c5,$89,$6f,$b7,$62,$0e,$aa,$18,$be,$1b,
    $fc,$56,$3e,$4b,$c6,$d2,$79,$20,$9a,$db,$c0,$fe,$78,$cd,$5a,$f4,
    $1f,$dd,$a8,$33,$88,$07,$c7,$31,$b1,$12,$10,$59,$27,$80,$ec,$5f,
    $60,$51,$7f,$a9,$19,$b5,$4a,$0d,$2d,$e5,$7a,$9f,$93,$c9,$9c,$ef,
    $a0,$e0,$3b,$4d,$ae,$2a,$f5,$b0,$c8,$eb,$bb,$3c,$83,$53,$99,$61,
    $17,$2b,$04,$7e,$ba,$77,$d6,$26,$e1,$69,$14,$63,$55,$21,$0c,$7d);

  Rcon: array[0..13] of LongWord = (
    $01000000, $02000000, $04000000, $08000000, $10000000, $20000000,
    $40000000, $80000000, $1b000000, $36000000, $6c000000, $d8000000,
    $ab000000, $4d000000);

function AESKeySizeValid(const Key: TBytes): Boolean;
begin
  Result := (Length(Key) = 16) or (Length(Key) = 24) or (Length(Key) = 32);
end;

function XTime(b: Byte): Byte; inline;
begin
  Result := (b shl 1) xor (Byte(-(b shr 7)) and $1B);
end;

{--- TAES ---}

procedure TAES.ExpandKey(const Key: TBytes);
var
  Nk, Nr, i: Integer;
  Temp: LongWord;
  W: array[0..59] of LongWord;
begin
  if not AESKeySizeValid(Key) then
    raise EAESError.CreateFmt('AES: invalid key size %d', [Length(Key)]);
  Nk := Length(Key) div 4;
  Nr := Nk + 6;
  FRounds := Nr;
  for i := 0 to Nk - 1 do
  begin
    W[i] := (LongWord(Key[4 * i]) shl 24) or
            (LongWord(Key[4 * i + 1]) shl 16) or
            (LongWord(Key[4 * i + 2]) shl 8) or
            LongWord(Key[4 * i + 3]);
  end;
  for i := Nk to 4 * (Nr + 1) - 1 do
  begin
    Temp := W[i - 1];
    if i mod Nk = 0 then
      Temp := (LongWord(SBox[(Temp shr 16) and $FF]) shl 24) or
              (LongWord(SBox[(Temp shr 8) and $FF]) shl 16) or
              (LongWord(SBox[Temp and $FF]) shl 8) or
              LongWord(SBox[(Temp shr 24) and $FF]) xor
              Rcon[i div Nk - 1]
    else if (Nk > 6) and (i mod Nk = 4) then
      Temp := (LongWord(SBox[(Temp shr 24) and $FF]) shl 24) or
              (LongWord(SBox[(Temp shr 16) and $FF]) shl 16) or
              (LongWord(SBox[(Temp shr 8) and $FF]) shl 8) or
              LongWord(SBox[Temp and $FF]);
    W[i] := W[i - Nk] xor Temp;
  end;
  for i := 0 to 4 * (Nr + 1) - 1 do
    FRK[i] := W[i];
end;

procedure TAES.AddRoundKey(const State: TBytes; Round: Integer);
var
  c: Integer;
  w: LongWord;
begin
  for c := 0 to 3 do
  begin
    w := FRK[Round * 4 + c];
    State[4 * c + 0] := State[4 * c + 0] xor Byte(w shr 24);
    State[4 * c + 1] := State[4 * c + 1] xor Byte(w shr 16);
    State[4 * c + 2] := State[4 * c + 2] xor Byte(w shr 8);
    State[4 * c + 3] := State[4 * c + 3] xor Byte(w);
  end;
end;

constructor TAES.Create(const Key: TBytes);
begin
  inherited Create;
  ExpandKey(Key);
end;

procedure TAES.EncryptBlock(const InBlock: TBytes; out OutBlock: TBytes);
var
  State, Tmp: TBytes;
  Round, r, c, i: Integer;
  a0, a1, a2, a3, t, u: Byte;
begin
  if Length(InBlock) <> 16 then
    raise EAESError.Create('AES.EncryptBlock: block is not 16 bytes');
  State := Copy(InBlock, 0, 16);
  AddRoundKey(State, 0);
  for Round := 1 to FRounds - 1 do
  begin
    { SubBytes. }
    for i := 0 to 15 do
      State[i] := SBox[State[i]];
    { ShiftRows: row r is shifted left by r. }
    Tmp := Copy(State, 0, 16);
    for r := 0 to 3 do
      for c := 0 to 3 do
        State[4 * c + r] := Tmp[4 * ((c + r) mod 4) + r];
    { MixColumns. }
    for c := 0 to 3 do
    begin
      a0 := State[4 * c + 0];
      a1 := State[4 * c + 1];
      a2 := State[4 * c + 2];
      a3 := State[4 * c + 3];
      t := a0 xor a1 xor a2 xor a3;
      u := a0;
      State[4 * c + 0] := a0 xor t xor XTime(a0 xor a1);
      State[4 * c + 1] := a1 xor t xor XTime(a1 xor a2);
      State[4 * c + 2] := a2 xor t xor XTime(a2 xor a3);
      State[4 * c + 3] := a3 xor t xor XTime(a3 xor u);
    end;
    AddRoundKey(State, Round);
  end;
  { Last round without MixColumns. }
  for i := 0 to 15 do
    State[i] := SBox[State[i]];
  Tmp := Copy(State, 0, 16);
  for r := 0 to 3 do
    for c := 0 to 3 do
      State[4 * c + r] := Tmp[4 * ((c + r) mod 4) + r];
  AddRoundKey(State, FRounds);
  OutBlock := State;
end;

function GMul(a, b: Byte): Byte;
var
  p: Byte;
  i: Integer;
begin
  p := 0;
  for i := 0 to 7 do
  begin
    if (b and 1) <> 0 then
      p := p xor a;
    b := b shr 1;
    a := XTime(a);
  end;
  Result := p;
end;

procedure TAES.DecryptBlock(const InBlock: TBytes; out OutBlock: TBytes);
var
  State, Tmp: TBytes;
  Round, r, c, i: Integer;
  a0, a1, a2, a3: Byte;
begin
  if Length(InBlock) <> 16 then
    raise EAESError.Create('AES.DecryptBlock: block is not 16 bytes');
  State := Copy(InBlock, 0, 16);
  AddRoundKey(State, FRounds);
  for Round := FRounds - 1 downto 1 do
  begin
    { InvShiftRows: row r is shifted right by r. }
    Tmp := Copy(State, 0, 16);
    for r := 0 to 3 do
      for c := 0 to 3 do
        State[4 * c + r] := Tmp[4 * ((c - r + 4) mod 4) + r];
    for i := 0 to 15 do
      State[i] := InvSBox[State[i]];
    AddRoundKey(State, Round);
    { InvMixColumns. }
    for c := 0 to 3 do
    begin
      a0 := State[4 * c + 0];
      a1 := State[4 * c + 1];
      a2 := State[4 * c + 2];
      a3 := State[4 * c + 3];
      State[4 * c + 0] := GMul(a0, $0E) xor GMul(a1, $0B) xor GMul(a2, $0D) xor GMul(a3, $09);
      State[4 * c + 1] := GMul(a0, $09) xor GMul(a1, $0E) xor GMul(a2, $0B) xor GMul(a3, $0D);
      State[4 * c + 2] := GMul(a0, $0D) xor GMul(a1, $09) xor GMul(a2, $0E) xor GMul(a3, $0B);
      State[4 * c + 3] := GMul(a0, $0B) xor GMul(a1, $0D) xor GMul(a2, $09) xor GMul(a3, $0E);
    end;
  end;
  Tmp := Copy(State, 0, 16);
  for r := 0 to 3 do
    for c := 0 to 3 do
      State[4 * c + r] := Tmp[4 * ((c - r + 4) mod 4) + r];
  for i := 0 to 15 do
    State[i] := InvSBox[State[i]];
  AddRoundKey(State, 0);
  OutBlock := State;
end;

{--- ECB ---}

function AESBlockEncrypt(const Key, Block: TBytes): TBytes;
var
  A: TAES;
begin
  A := TAES.Create(Key);
  try
    A.EncryptBlock(Block, Result);
  finally
    A.Free;
  end;
end;

function AESBlockDecrypt(const Key, Block: TBytes): TBytes;
var
  A: TAES;
begin
  A := TAES.Create(Key);
  try
    A.DecryptBlock(Block, Result);
  finally
    A.Free;
  end;
end;

{--- CBC ---}

function AESCBCEncryptNoPad(const Key, IV, Plain: TBytes): TBytes;
var
  A: TAES;
  i, n, off: Integer;
  Prev, Tmp: TBytes;
begin
  if Length(IV) <> 16 then
    raise EAESError.Create('AESCBC: IV is not 16 bytes');
  if Length(Plain) mod 16 <> 0 then
    raise EAESError.Create('AESCBC: length is not a multiple of 16');
  A := TAES.Create(Key);
  try
    SetLength(Result, Length(Plain));
    Prev := Copy(IV, 0, 16);
    SetLength(Tmp, 16);
    off := 0;
    while off < Length(Plain) do
    begin
      for i := 0 to 15 do
        Tmp[i] := Plain[off + i] xor Prev[i];
      A.EncryptBlock(Tmp, Prev);
      Move(Prev[0], Result[off], 16);
      Inc(off, 16);
    end;
  finally
    A.Free;
  end;
end;

function AESCBCDecryptNoPad(const Key, IV, Cipher: TBytes): TBytes;
var
  A: TAES;
  i, off: Integer;
  Prev, Cur, Dec: TBytes;
begin
  if Length(IV) <> 16 then
    raise EAESError.Create('AESCBC: IV is not 16 bytes');
  if Length(Cipher) mod 16 <> 0 then
    raise EAESError.Create('AESCBC: length is not a multiple of 16');
  A := TAES.Create(Key);
  try
    SetLength(Result, Length(Cipher));
    Prev := Copy(IV, 0, 16);
    off := 0;
    while off < Length(Cipher) do
    begin
      Cur := Copy(Cipher, off, 16);
      A.DecryptBlock(Cur, Dec);
      for i := 0 to 15 do
        Result[off + i] := Dec[i] xor Prev[i];
      Prev := Cur;
      Inc(off, 16);
    end;
  finally
    A.Free;
  end;
end;

function AESCBCEncrypt(const Key, IV, Plain: TBytes): TBytes;
var
  Padded: TBytes;
  n, i: Integer;
begin
  n := 16 - (Length(Plain) mod 16);
  SetLength(Padded, Length(Plain) + n);
  if Length(Plain) > 0 then
    Move(Plain[0], Padded[0], Length(Plain));
  for i := 0 to n - 1 do
    Padded[Length(Plain) + i] := Byte(n);
  Result := AESCBCEncryptNoPad(Key, IV, Padded);
end;

function AESCBCDecrypt(const Key, IV, Cipher: TBytes): TBytes;
var
  Raw: TBytes;
  n: Integer;
begin
  Raw := AESCBCDecryptNoPad(Key, IV, Cipher);
  if Length(Raw) = 0 then
    raise EAESError.Create('AESCBC: empty ciphertext');
  n := Raw[Length(Raw) - 1];
  if (n < 1) or (n > 16) or (n > Length(Raw)) then
    raise EAESError.Create('AESCBC: invalid padding');
  Result := Copy(Raw, 0, Length(Raw) - n);
end;

{--- GCM ---}

type
  TGcm = record
    Hi, Lo: QWord;
  end;

function GcmZero: TGcm;
begin
  Result.Hi := 0;
  Result.Lo := 0;
end;

function GcmXor(const A, B: TGcm): TGcm;
begin
  Result.Hi := A.Hi xor B.Hi;
  Result.Lo := A.Lo xor B.Lo;
end;

function GcmFromBytes(const B: TBytes; Offset: Integer): TGcm;
var
  i: Integer;
begin
  Result.Hi := 0;
  Result.Lo := 0;
  for i := 0 to 7 do
  begin
    Result.Hi := (Result.Hi shl 8) or QWord(B[Offset + i]);
    Result.Lo := (Result.Lo shl 8) or QWord(B[Offset + 8 + i]);
  end;
end;

procedure GcmToBytes(const V: TGcm; var B: TBytes; Offset: Integer);
var
  i: Integer;
begin
  for i := 0 to 7 do
  begin
    B[Offset + i] := Byte(V.Hi shr (56 - 8 * i));
    B[Offset + 8 + i] := Byte(V.Lo shr (56 - 8 * i));
  end;
end;

function GcmBit(const X: TGcm; i: Integer): Integer; inline;
begin
  if i < 64 then
    Result := (X.Hi shr (63 - i)) and 1
  else
    Result := (X.Lo shr (127 - i)) and 1;
end;

function GcmMul(const X, Y: TGcm): TGcm;
var
  Z, V: TGcm;
  i: Integer;
  lsb: QWord;
begin
  Z := GcmZero;
  V := Y;
  for i := 0 to 127 do
  begin
    if GcmBit(X, i) <> 0 then
      Z := GcmXor(Z, V);
    lsb := V.Lo and 1;
    V.Lo := (V.Lo shr 1) or (V.Hi shl 63);
    V.Hi := V.Hi shr 1;
    if lsb <> 0 then
      V.Hi := V.Hi xor QWord($E100000000000000);
  end;
  Result := Z;
end;

function GHashBlock(const H, Y: TGcm; const Block: TBytes; Offset: Integer): TGcm;
var
  X: TGcm;
begin
  X := GcmFromBytes(Block, Offset);
  Result := GcmMul(GcmXor(Y, X), H);
end;

{ GHASH of data with zero padding of the last partial block. }
function GHashPadded(const H, Y0: TGcm; const Data: TBytes): TGcm;
var
  Y: TGcm;
  i, n: Integer;
  Block: TBytes;
begin
  Y := Y0;
  n := Length(Data);
  i := 0;
  while n - i >= 16 do
  begin
    Y := GHashBlock(H, Y, Data, i);
    Inc(i, 16);
  end;
  if i < n then
  begin
    SetLength(Block, 16);
    FillChar(Block[0], 16, 0);
    Move(Data[i], Block[0], n - i);
    Y := GHashBlock(H, Y, Block, 0);
  end;
  Result := Y;
end;

procedure Inc32(var CB: TBytes);
var
  i: Integer;
begin
  for i := 15 downto 12 do
  begin
    CB[i] := Byte(CB[i] + 1);
    if CB[i] <> 0 then
      Break;
  end;
end;

{ GCTR: encryption of ICB, inc32, ... and XOR with Data. }
function GCtr(const AES: TAES; ICB: TBytes; const Data: TBytes): TBytes;
var
  i, off, n: Integer;
  KS: TBytes;
begin
  SetLength(Result, Length(Data));
  off := 0;
  while off < Length(Data) do
  begin
    AES.EncryptBlock(ICB, KS);
    n := 16;
    if n > Length(Data) - off then
      n := Length(Data) - off;
    for i := 0 to n - 1 do
      Result[off + i] := Data[off + i] xor KS[i];
    Inc(off, 16);
    Inc32(ICB);
  end;
end;

function ComputeJ0(const H, Y0: TGcm; const IV: TBytes): TGcm;
var
  Buf: TBytes;
  s, i: Integer;
begin
  if Length(IV) = 12 then
  begin
    SetLength(Buf, 16);
    Move(IV[0], Buf[0], 12);
    Buf[12] := 0;
    Buf[13] := 0;
    Buf[14] := 0;
    Buf[15] := 1;
    Result := GcmFromBytes(Buf, 0);
    Exit;
  end;
  { J0 = GHASH_H(IV || 0^s || 0^64 || [len(IV)]_64). }
  s := 16 - (Length(IV) mod 16);
  if s = 16 then
    s := 0;
  SetLength(Buf, Length(IV) + s + 16);
  FillChar(Buf[0], Length(Buf), 0);
  if Length(IV) > 0 then
    Move(IV[0], Buf[0], Length(IV));
  for i := 0 to 7 do
    Buf[Length(Buf) - 8 + i] := Byte(QWord(Length(IV) * 8) shr (56 - 8 * i));
  Result := GHashPadded(H, Y0, Buf);
end;

{Compute H and J0.}
procedure GcmSetup(AES: TAES; const Key, IV: TBytes; out H, J0: TGcm);
var
  Zero, HBlock: TBytes;
begin
  SetLength(Zero, 16);
  FillChar(Zero[0], 16, 0);
  AES.EncryptBlock(Zero, HBlock);
  H := GcmFromBytes(HBlock, 0);
  J0 := ComputeJ0(H, GcmZero, IV);
end;

{S = GHASH(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64);
  Tag = E(J0) xor S (16 bytes).}
function GcmTag(AES: TAES; const H, J0: TGcm;
  const AAD, Cipher: TBytes): TBytes;
var
  Y: TGcm;
  LenBlock, S, ICB: TBytes;
  i: Integer;
begin
  Y := GHashPadded(H, GcmZero, AAD);
  Y := GHashPadded(H, Y, Cipher);
  SetLength(LenBlock, 16);
  FillChar(LenBlock[0], 16, 0);
  for i := 0 to 7 do
  begin
    LenBlock[i] := Byte(QWord(Length(AAD) * 8) shr (56 - 8 * i));
    LenBlock[8 + i] := Byte(QWord(Length(Cipher) * 8) shr (56 - 8 * i));
  end;
  Y := GHashBlock(H, Y, LenBlock, 0);
  SetLength(S, 16);
  GcmToBytes(Y, S, 0);
  SetLength(ICB, 16);
  GcmToBytes(J0, ICB, 0);
  Result := GCtr(AES, ICB, S);
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

procedure AESGCMEncrypt(const Key, IV, AAD, Plain: TBytes;
  out Cipher, Tag: TBytes);
var
  AES: TAES;
  H, J0: TGcm;
  ICB: TBytes;
begin
  AES := TAES.Create(Key);
  try
    GcmSetup(AES, Key, IV, H, J0);
    SetLength(ICB, 16);
    GcmToBytes(J0, ICB, 0);
    Inc32(ICB);
    Cipher := GCtr(AES, ICB, Plain);
    Tag := GcmTag(AES, H, J0, AAD, Cipher);
  finally
    AES.Free;
  end;
end;

function AESGCMDecrypt(const Key, IV, AAD, Cipher, Tag: TBytes;
  out Plain: TBytes): Boolean;
var
  AES: TAES;
  H, J0: TGcm;
  ICB, Tag2: TBytes;
begin
  AES := TAES.Create(Key);
  try
    GcmSetup(AES, Key, IV, H, J0);
    Tag2 := GcmTag(AES, H, J0, AAD, Cipher);
    Result := ConstantTimeEq(Tag, Tag2);
    if Result then
    begin
      SetLength(ICB, 16);
      GcmToBytes(J0, ICB, 0);
      Inc32(ICB);
      Plain := GCtr(AES, ICB, Cipher);
    end
    else
      Plain := nil;
  finally
    AES.Free;
  end;
end;

end.
