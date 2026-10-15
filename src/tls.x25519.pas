{ SPDX-License-Identifier: Apache-2.0 }
unit tls.x25519;

{ X25519 — Curve25519 Diffie–Hellman (RFC 7748).

  Field arithmetic over GF(2^255 - 19) in radix 2^51 (five 64-bit
  limbs), a Montgomery ladder with a constant-time conditional swap
  and inversion through an addition chain for z^(p-2). The ladder
  never branches on scalar bits; the field operations are written
  without data-dependent branches.

  Used by the TLS 1.3 client (task 13) for the X25519 key-share group;
  the TLS 1.2 named-group table already reserves the code point. }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, tls.rand;

type
  EX25519Error = class(Exception);

  { X25519 key pair: a 32-byte clamped private scalar and the
    32-byte public u-coordinate X25519(private, 9). }
  TX25519KeyPair = record
    PrivateKey: TBytes;
    PublicKey: TBytes;
  end;

const
  X25519KeySize = 32;

{ Raw X25519 scalar multiplication: 32-byte scalar and 32-byte
  u-coordinate in, 32-byte u-coordinate out. The scalar is clamped
  as required by RFC 7748. }
function X25519(const Scalar, U: TBytes): TBytes;

{ Public key for a private scalar: X25519(PrivateKey, u = 9). }
function X25519PublicKey(const PrivateKey: TBytes): TBytes;

{ Shared secret: X25519(PrivateKey, PeerPublicKey). Raises
  EX25519Error when the exchange yields the all-zero value, which
  signals a low-order peer public key and is forbidden in TLS. }
function X25519SharedSecret(const PrivateKey, PeerPublicKey: TBytes): TBytes;

{ Ephemeral key pair from the CSPRNG (tls.rand). }
function X25519GenerateKeyPair: TX25519KeyPair;

{ Apply the RFC 7748 scalar clamping to a copy of Scalar. }
function X25519Clamp(const Scalar: TBytes): TBytes;

implementation

const
  MASK51: QWord = $7FFFFFFFFFFFF;      { 2^51 - 1 }
  A24: QWord = 121665;                 { (486662 - 2) / 4 }

  { 2*p = 2^256 - 38 split into 51-bit limbs; adding it before a
    subtraction keeps every limb non-negative (constant time). }
  TWO_P: array[0..4] of QWord = (
    $FFFFFFFFFFFDA,                    { 2^52 - 38 }
    $FFFFFFFFFFFFE,                    { 2^52 - 2 }
    $FFFFFFFFFFFFE,
    $FFFFFFFFFFFFE,
    $FFFFFFFFFFFFE
  );

  { p = 2^255 - 19 in 51-bit limbs, for the final conditional
    subtraction in FeToBytes. }
  P_LIMBS: array[0..4] of QWord = (
    $7FFFFFFFFFFED,                    { 2^51 - 19 }
    $7FFFFFFFFFFFF,
    $7FFFFFFFFFFFF,
    $7FFFFFFFFFFFF,
    $7FFFFFFFFFFFF
  );

type
  { A field element in radix 2^51; limb i carries 2^(51*i). }
  TFe = array[0..4] of QWord;

{ 64x64 -> 128 multiplication through 32-bit halves. }
procedure Mul64x64(a, b: QWord; out lo, hi: QWord);
var
  a0, a1, b0, b1, p0, p1, p2, p3, s, mid, c: QWord;
begin
  a0 := a and $FFFFFFFF;
  a1 := a shr 32;
  b0 := b and $FFFFFFFF;
  b1 := b shr 32;
  p0 := a0 * b0;
  p1 := a0 * b1;
  p2 := a1 * b0;
  p3 := a1 * b1;
  s := p1 + p2;
  c := QWord(s < p1);
  mid := (s and $FFFFFFFF) shl 32;
  lo := mid + p0;
  hi := p3 + (s shr 32) + (c shl 32) + QWord(lo < mid);
end;

{ Multiply x by y and add the 128-bit product to (lo, hi). }
procedure AccMul(var lo, hi: QWord; const x, y: QWord);
var
  pl, ph, s: QWord;
begin
  Mul64x64(x, y, pl, ph);
  s := lo + pl;
  if s < pl then
    Inc(hi);
  lo := s;
  hi := hi + ph;
end;

procedure FeZero(out r: TFe);
var
  i: Integer;
begin
  for i := 0 to 4 do
    r[i] := 0;
end;

procedure FeCopy(out r: TFe; const a: TFe);
var
  i: Integer;
begin
  for i := 0 to 4 do
    r[i] := a[i];
end;

{ r = a + b (mod p). }
procedure FeAdd(out r: TFe; const a, b: TFe);
var
  c: QWord;
begin
  r[0] := a[0] + b[0];
  r[1] := a[1] + b[1];
  r[2] := a[2] + b[2];
  r[3] := a[3] + b[3];
  r[4] := a[4] + b[4];
  c := r[0] shr 51; r[0] := r[0] and MASK51; r[1] := r[1] + c;
  c := r[1] shr 51; r[1] := r[1] and MASK51; r[2] := r[2] + c;
  c := r[2] shr 51; r[2] := r[2] and MASK51; r[3] := r[3] + c;
  c := r[3] shr 51; r[3] := r[3] and MASK51; r[4] := r[4] + c;
  c := r[4] shr 51; r[4] := r[4] and MASK51; r[0] := r[0] + c * 19;
  c := r[0] shr 51; r[0] := r[0] and MASK51; r[1] := r[1] + c;
end;

{ r = a - b (mod p) in constant time. }
procedure FeSub(out r: TFe; const a, b: TFe);
var
  c: QWord;
begin
  r[0] := a[0] + TWO_P[0] - b[0];
  r[1] := a[1] + TWO_P[1] - b[1];
  r[2] := a[2] + TWO_P[2] - b[2];
  r[3] := a[3] + TWO_P[3] - b[3];
  r[4] := a[4] + TWO_P[4] - b[4];
  c := r[0] shr 51; r[0] := r[0] and MASK51; r[1] := r[1] + c;
  c := r[1] shr 51; r[1] := r[1] and MASK51; r[2] := r[2] + c;
  c := r[2] shr 51; r[2] := r[2] and MASK51; r[3] := r[3] + c;
  c := r[3] shr 51; r[3] := r[3] and MASK51; r[4] := r[4] + c;
  c := r[4] shr 51; r[4] := r[4] and MASK51; r[0] := r[0] + c * 19;
  c := r[0] shr 51; r[0] := r[0] and MASK51; r[1] := r[1] + c;
end;

{ r = a * b (mod p). }
procedure FeMul(out r: TFe; const a, b: TFe);
var
  la, lb: TFe;
  tlo, thi: array[0..9] of QWord;
  dg: array[0..9] of QWord;
  i, j: Integer;
  s, c: QWord;
begin
  { Capture the operands so that r may alias a or b. }
  for i := 0 to 4 do
  begin
    la[i] := a[i];
    lb[i] := b[i];
  end;
  for i := 0 to 9 do
  begin
    tlo[i] := 0;
    thi[i] := 0;
  end;
  for i := 0 to 4 do
    for j := 0 to 4 do
      AccMul(tlo[i + j], thi[i + j], la[i], lb[j]);

  { Carry the convolution down to 51-bit limbs.  Index 8 holds a
    102-bit product, so it can carry into index 9 (2^459); the carry
    out of index 9 sits at 2^510 = 19^2 (mod p) and must be folded. }
  c := 0;
  for i := 0 to 9 do
  begin
    s := tlo[i] + c;
    if s < c then
      Inc(thi[i]);
    dg[i] := s and MASK51;
    c := (s shr 51) or (thi[i] shl 13);
  end;

  { Fold limbs 5..9: 2^(51*k) = 19 * 2^(51*(k-5)) for k >= 5,
    and the carry beyond limb 9: 2^510 = 361 (mod p). }
  dg[0] := dg[0] + 19 * dg[5] + 361 * c;
  dg[1] := dg[1] + 19 * dg[6];
  dg[2] := dg[2] + 19 * dg[7];
  dg[3] := dg[3] + 19 * dg[8];
  dg[4] := dg[4] + 19 * dg[9];

  { Normalise limbs 0..4. }
  c := 0;
  for i := 0 to 4 do
  begin
    dg[i] := dg[i] + c;
    r[i] := dg[i] and MASK51;
    c := dg[i] shr 51;
  end;
  r[0] := r[0] + c * 19;
  c := r[0] shr 51;
  r[0] := r[0] and MASK51;
  r[1] := r[1] + c;
end;

procedure FeSqr(out r: TFe; const a: TFe);
begin
  FeMul(r, a, a);
end;

{ r = a * 121665 (mod p), used for the a24 term of the ladder. }
procedure FeMul121665(out r: TFe; const a: TFe);
var
  i: Integer;
  pl, ph, s, c: QWord;
begin
  c := 0;
  for i := 0 to 4 do
  begin
    Mul64x64(a[i], A24, pl, ph);
    s := pl + c;
    if s < c then
      Inc(ph);
    r[i] := s and MASK51;
    c := (s shr 51) or (ph shl 13);
  end;
  r[0] := r[0] + c * 19;
  c := r[0] shr 51;
  r[0] := r[0] and MASK51;
  r[1] := r[1] + c;
end;

{ Constant-time conditional swap of a and b when swap = 1. }
procedure FeCswap(swap: QWord; var a, b: TFe);
var
  i: Integer;
  mask, t: QWord;
begin
  mask := QWord(0) - swap;
  for i := 0 to 4 do
  begin
    t := mask and (a[i] xor b[i]);
    a[i] := a[i] xor t;
    b[i] := b[i] xor t;
  end;
end;

{ Decode 32 little-endian bytes into a field element; bit 255 is
  masked off as prescribed by RFC 7748. }
function FeFromBytes(const B: TBytes): TFe;
var
  i: Integer;
  v: QWord;
begin
  for i := 0 to 4 do
    Result[i] := 0;
  for i := 0 to 254 do
  begin
    v := (QWord(B[i shr 3]) shr (i and 7)) and 1;
    Result[i div 51] := Result[i div 51] or (v shl (i mod 51));
  end;
end;

{ Canonicalise a field element to limbs < 2^51 (limb 1 may reach
  2^51); the caller may follow with the conditional subtraction of p. }
procedure FeNormalize(var a: TFe);
var
  c: QWord;
begin
  c := a[0] shr 51; a[0] := a[0] and MASK51; a[1] := a[1] + c;
  c := a[1] shr 51; a[1] := a[1] and MASK51; a[2] := a[2] + c;
  c := a[2] shr 51; a[2] := a[2] and MASK51; a[3] := a[3] + c;
  c := a[3] shr 51; a[3] := a[3] and MASK51; a[4] := a[4] + c;
  c := a[4] shr 51; a[4] := a[4] and MASK51; a[0] := a[0] + c * 19;
  c := a[0] shr 51; a[0] := a[0] and MASK51; a[1] := a[1] + c;
end;

{ Encode a field element as 32 little-endian bytes, subtracting p
  exactly once in constant time when the value is not canonical. }
function FeToBytes(const a: TFe): TBytes;
var
  n, t: TFe;
  i, pos: Integer;
  d, borrow, b1, b2, mask, v: QWord;
begin
  FeCopy(n, a);
  FeNormalize(n);

  borrow := 0;
  for i := 0 to 4 do
  begin
    d := n[i] - P_LIMBS[i];
    b1 := QWord(n[i] < P_LIMBS[i]);
    b2 := QWord(d < borrow);
    t[i] := d - borrow;
    borrow := b1 or b2;
  end;
  mask := borrow - 1; { all ones when no borrow (n >= p) }
  for i := 0 to 4 do
    n[i] := (t[i] and mask) or (n[i] and (not mask));

  SetLength(Result, X25519KeySize);
  for i := 0 to X25519KeySize - 1 do
    Result[i] := 0;
  for i := 0 to 4 do
    for pos := 0 to 50 do
    begin
      v := (n[i] shr pos) and 1;
      Result[(51 * i + pos) shr 3] :=
        Result[(51 * i + pos) shr 3] or Byte(v shl ((51 * i + pos) and 7));
    end;
end;

procedure FeSqrN(out r: TFe; const a: TFe; n: Integer);
var
  i: Integer;
  t: TFe;
begin
  FeSqr(t, a);
  for i := 2 to n do
    FeSqr(t, t);
  FeCopy(r, t);
end;

{ r = z^(p-2) = z^(2^255 - 21) via the standard addition chain. }
procedure FeInvert(out r: TFe; const z: TFe);
var
  t0, t1, t2, t3: TFe;
begin
  FeSqr(t0, z);          { z^2 }
  FeSqr(t1, t0);         { z^4 }
  FeSqr(t1, t1);         { z^8 }
  FeMul(t1, z, t1);      { z^9 }
  FeMul(t0, t0, t1);     { z^11 }
  FeSqr(t2, t0);         { z^22 }
  FeMul(t1, t1, t2);     { z^31 = z^(2^5-1) }
  FeSqrN(t2, t1, 5);
  FeMul(t1, t2, t1);     { z^(2^10-1) }
  FeSqrN(t2, t1, 10);
  FeMul(t2, t2, t1);     { z^(2^20-1) }
  FeSqrN(t3, t2, 20);
  FeMul(t2, t3, t2);     { z^(2^40-1) }
  FeSqrN(t2, t2, 10);
  FeMul(t1, t2, t1);     { z^(2^50-1) }
  FeSqrN(t2, t1, 50);
  FeMul(t2, t2, t1);     { z^(2^100-1) }
  FeSqrN(t3, t2, 100);
  FeMul(t2, t3, t2);     { z^(2^200-1) }
  FeSqrN(t2, t2, 50);
  FeMul(t1, t2, t1);     { z^(2^250-1) }
  FeSqrN(t1, t1, 5);
  FeMul(r, t1, t0);      { z^(2^255-21) }
end;

function X25519Clamp(const Scalar: TBytes): TBytes;
begin
  if Length(Scalar) <> X25519KeySize then
    raise EX25519Error.Create('X25519: scalar must be 32 bytes');
  Result := Copy(Scalar, 0, X25519KeySize);
  Result[0] := Result[0] and 248;
  Result[31] := Result[31] and 127;
  Result[31] := Result[31] or 64;
end;

function X25519(const Scalar, U: TBytes): TBytes;
var
  k: TBytes;
  x1, x2, z2, x3, z3: TFe;
  a, aa, b, bb, e, c, d, da, cb, t0, t1: TFe;
  swap, kt: QWord;
  t: Integer;
begin
  if Length(U) <> X25519KeySize then
    raise EX25519Error.Create('X25519: u-coordinate must be 32 bytes');
  k := X25519Clamp(Scalar);

  x1 := FeFromBytes(U);
  FeZero(x2); x2[0] := 1;
  FeZero(z2);
  FeCopy(x3, x1);
  FeZero(z3); z3[0] := 1;

  swap := 0;
  for t := 254 downto 0 do
  begin
    kt := (QWord(k[t shr 3]) shr (t and 7)) and 1;
    swap := swap xor kt;
    FeCswap(swap, x2, x3);
    FeCswap(swap, z2, z3);
    swap := kt;

    FeAdd(a, x2, z2);
    FeSqr(aa, a);
    FeSub(b, x2, z2);
    FeSqr(bb, b);
    FeSub(e, aa, bb);
    FeAdd(c, x3, z3);
    FeSub(d, x3, z3);
    FeMul(da, d, a);
    FeMul(cb, c, b);
    FeAdd(t0, da, cb);
    FeSqr(x3, t0);
    FeSub(t0, da, cb);
    FeSqr(t0, t0);
    FeMul(z3, x1, t0);
    FeMul(x2, aa, bb);
    FeMul121665(t0, e);
    FeAdd(t0, aa, t0);
    FeMul(z2, e, t0);
  end;
  FeCswap(swap, x2, x3);
  FeCswap(swap, z2, z3);

  FeInvert(t0, z2);
  FeMul(t1, x2, t0);
  Result := FeToBytes(t1);
end;

function X25519PublicKey(const PrivateKey: TBytes): TBytes;
var
  Base: TBytes;
begin
  SetLength(Base, X25519KeySize);
  FillChar(Base[0], X25519KeySize, 0);
  Base[0] := 9;
  Result := X25519(PrivateKey, Base);
end;

function X25519SharedSecret(const PrivateKey, PeerPublicKey: TBytes): TBytes;
var
  i: Integer;
  AllZero: Boolean;
begin
  Result := X25519(PrivateKey, PeerPublicKey);
  AllZero := True;
  for i := 0 to X25519KeySize - 1 do
    if Result[i] <> 0 then
    begin
      AllZero := False;
      Break;
    end;
  if AllZero then
    raise EX25519Error.Create('X25519: all-zero shared secret (low-order peer key)');
end;

function X25519GenerateKeyPair: TX25519KeyPair;
var
  Raw: TBytes;
begin
  SetLength(Raw, X25519KeySize);
  RandomBytes(Raw, X25519KeySize);
  Result.PrivateKey := X25519Clamp(Raw);
  Result.PublicKey := X25519PublicKey(Result.PrivateKey);
end;

end.
