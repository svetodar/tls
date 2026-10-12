{ SPDX-License-Identifier: Apache-2.0 }
unit tls.ec;

{ Elliptic curve cryptography (EC): NIST P-256, P-384.
  Affine coordinates, double-and-add scalar multiplication.
  TBN (tls.bn) — modular arithmetic,
  SHA-256/384 (tls.sha2) — for ECDSA (task 07),
  CSPRNG (tls.rand) — key generation.

  Implementation for task 07 (docs/tasks/07-ec.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, tls.bn, tls.rand, tls.sha2;

type
  { Elliptic curve point in affine coordinates.
    Infinity — point at infinity (neutral element of the group). }
  TECPoint = class
  public
    X, Y: TBN;
    Infinity: Boolean;
    constructor Create;
    constructor CreateFromXY(const PX, PY: TBN);
    class function InfinityPoint: TECPoint;
    function Clone: TECPoint;
    destructor Destroy; override;
  end;

  { Parameters of the elliptic curve y^2 = x^3 + a*x + b (mod p). }
  TECCurve = class
  public
    P: TBN;          { Prime field }
    A: TBN;          { Coefficient a }
    B: TBN;          { Coefficient b }
    G: TECPoint;     { Base point (generator) }
    N: TBN;          { Order of the base point }
    constructor Create;
    destructor Destroy; override;
  end;

  { ECDHE key pair: private scalar d and public point Q = d*G. }
  TECKeypair = class
  public
    PrivateKey: TBN;
    PublicKey: TECPoint;
    constructor Create;
    destructor Destroy; override;
  end;

  { ECDSA signature: pair (r, s). }
  TECDsaSig = class
  public
    R, S: TBN;
    constructor Create;
    destructor Destroy; override;
  end;

{ NIST curve parameters. }
function CurveP256: TECCurve;
function CurveP384: TECCurve;

{ Point operations. }
function PointAdd(const Curve: TECCurve; const P, Q: TECPoint): TECPoint;
function PointDouble(const Curve: TECCurve; const P: TECPoint): TECPoint;
function PointNeg(const Curve: TECCurve; const P: TECPoint): TECPoint;
function IsOnCurve(const Curve: TECCurve; const P: TECPoint): Boolean;

{ Point multiplication by scalar (double-and-add). }
function ScalarMul(const Curve: TECCurve; const K: TBN; const P: TECPoint): TECPoint;
{ Point encoding/decoding in SEC 1 format (uncompressed):
  0x04 || X || Y, where X and Y are big-endian bytes of fixed field length.
  The point at infinity is encoded as a single byte 0x00. }
function EncodePoint(const Curve: TECCurve; const P: TECPoint): TBytes;
function DecodePoint(const Curve: TECCurve; const Data: TBytes): TECPoint;

{ ECDHE: key pair generation and shared secret computation. }
function GenerateKeyPair(const Curve: TECCurve): TECKeypair;
function ComputeSharedSecret(const Curve: TECCurve; const PrivateKey: TBN;
  const PeerPublicKey: TECPoint): TECPoint;

{ ECDSA: signing and verification (FIPS 186-4).
  The hash is selected by curve: P-256 → SHA-256, P-384 → SHA-384. }
function ECDSASign(const Curve: TECCurve; const PrivateKey: TBN;
  const Message: TBytes): TECDsaSig;
function ECDSAVerify(const Curve: TECCurve; const PublicKey: TECPoint;
  const Message: TBytes; const Sig: TECDsaSig): Boolean;

implementation

{--- TECPoint ---}

constructor TECPoint.Create;
begin
  Infinity := True;
  X := nil;
  Y := nil;
end;

constructor TECPoint.CreateFromXY(const PX, PY: TBN);
begin
  Infinity := False;
  Self.X := PX.Clone;
  Self.Y := PY.Clone;
end;

class function TECPoint.InfinityPoint: TECPoint;
begin
  Result := TECPoint.Create;
end;

function TECPoint.Clone: TECPoint;
begin
  Result := TECPoint.Create;
  if not Infinity then
  begin
    Result.Infinity := False;
    Result.X := X.Clone;
    Result.Y := Y.Clone;
  end;
end;

destructor TECPoint.Destroy;
begin
  if X <> nil then X.Free;
  if Y <> nil then Y.Free;
  inherited;
end;

{--- TECCurve ---}

constructor TECCurve.Create;
begin
  P := nil; A := nil; B := nil; G := nil; N := nil;
end;

destructor TECCurve.Destroy;
begin
  if P <> nil then P.Free;
  if A <> nil then A.Free;
  if B <> nil then B.Free;
  if G <> nil then G.Free;
  if N <> nil then N.Free;
  inherited;
end;

{--- NIST curve parameters ---}

function CurveP256: TECCurve;
begin
  Result := TECCurve.Create;
  Result.P := TBN.CreateFromHex(
    'FFFFFFFF00000001000000000000000000000000' +
    'FFFFFFFFFFFFFFFFFFFFFFFF');
  Result.A := TBN.CreateFromHex(
    'FFFFFFFF00000001000000000000000000000000' +
    'FFFFFFFFFFFFFFFFFFFFFFFC');
  Result.B := TBN.CreateFromHex(
    '5AC635D8AA3A93E7B3EBBD55769886BC' +
    '651D06B0CC53B0F63BCE3C3E27D2604B');
  Result.G := TECPoint.CreateFromXY(
    TBN.CreateFromHex(
      '6B17D1F2E12C4247F8BCE6E563A440F2' +
      '77037D812DEB33A0F4A13945D898C296'),
    TBN.CreateFromHex(
      '4FE342E2FE1A7F9B8EE7EB4A7C0F9E16' +
      '2BCE33576B315ECECBB6406837BF51F5'));
  Result.N := TBN.CreateFromHex(
    'FFFFFFFF00000000FFFFFFFFFFFFFFFF' +
    'BCE6FAADA7179E84F3B9CAC2FC632551');
end;

function CurveP384: TECCurve;
begin
  Result := TECCurve.Create;
  Result.P := TBN.CreateFromHex(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE' +
    'FFFFFFFF0000000000000000FFFFFFFF');
  Result.A := TBN.CreateFromHex(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE' +
    'FFFFFFFF0000000000000000FFFFFFFC');
  Result.B := TBN.CreateFromHex(
    'B3312FA7E23EE7E4988E056BE3F82D19' +
    '181D9C6EFE8141120314088F5013875A' +
    'C656398D8A2ED19D2A85C8EDD3EC2AEF');
  Result.G := TECPoint.CreateFromXY(
    TBN.CreateFromHex(
      'AA87CA22BE8B05378EB1C71EF320AD74' +
      '6E1D3B628BA79B9859F741E082542A38' +
      '5502F25DBF55296C3A545E3872760AB7'),
    TBN.CreateFromHex(
      '3617DE4A96262C6F5D9E98BF9292DC29' +
      'F8F41DBD289A147CE9DA3113B5F0B8C0' +
      '0A60B1CE1D7E819D7A431D7C90EA0E5F'));
  Result.N := TBN.CreateFromHex(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
    'FFFFFFFFFFFFFFFFC7634D81F4372DDF' +
    '581A0DB248B0A77AECEC196ACCC52973');
end;

{--- Point operations ---}

function PointAdd(const Curve: TECCurve; const P, Q: TECPoint): TECPoint;
var
  Lambda, Rx, Ry, t1, t2: TBN;
begin
  if P.Infinity then
  begin
    Result := Q.Clone;
    Exit;
  end;
  if Q.Infinity then
  begin
    Result := P.Clone;
    Exit;
  end;
  if P.X.Equal(Q.X) then
  begin
    if P.Y.Equal(Q.Y) then
    begin
      Result := PointDouble(Curve, P);
      Exit;
    end;
    Result := TECPoint.InfinityPoint;
    Exit;
  end;
  { lambda = (Q.y - P.y) * (Q.x - P.x)^-1 mod p }
  t1 := Q.Y.ModSub(P.Y, Curve.P);
  t2 := Q.X.ModSub(P.X, Curve.P);
  Lambda := t2.ModInverse(Curve.P);
  t2.Free;
  t2 := Lambda.ModMul(t1, Curve.P);
  Lambda.Free;
  Lambda := t2;
  t1.Free;
  { R.x = lambda^2 - P.x - Q.x mod p }
  Rx := Lambda.ModMul(Lambda, Curve.P);
  t1 := Rx.ModSub(P.X, Curve.P);
  Rx.Free;
  Rx := t1.ModSub(Q.X, Curve.P);
  t1.Free;
  { R.y = lambda * (P.x - R.x) - P.y mod p }
  t1 := P.X.ModSub(Rx, Curve.P);
  t2 := Lambda.ModMul(t1, Curve.P);
  t1.Free;
  Ry := t2.ModSub(P.Y, Curve.P);
  t2.Free;
  Result := TECPoint.CreateFromXY(Rx, Ry);
  Rx.Free;
  Ry.Free;
  Lambda.Free;
end;

function PointDouble(const Curve: TECCurve; const P: TECPoint): TECPoint;
var
  Lambda, Rx, Ry, Two, Three, t1, t2: TBN;
begin
  if P.Infinity then
  begin
    Result := TECPoint.InfinityPoint;
    Exit;
  end;
  if P.Y.IsZero then
  begin
    Result := TECPoint.InfinityPoint;
    Exit;
  end;
  Two := TBN.CreateFromQWord(2);
  Three := TBN.CreateFromQWord(3);
  { lambda = (3*x^2 + a) * (2*y)^-1 mod p }
  t1 := P.X.ModMul(P.X, Curve.P);
  t2 := t1.ModMul(Three, Curve.P);
  t1.Free;
  t1 := t2.ModAdd(Curve.A, Curve.P);
  t2.Free;
  t2 := Two.ModMul(P.Y, Curve.P);
  Lambda := t2.ModInverse(Curve.P);
  t2.Free;
  t2 := t1.ModMul(Lambda, Curve.P);
  t1.Free;
  Lambda.Free;
  Lambda := t2;
  { R.x = lambda^2 - 2*x mod p }
  Rx := Lambda.ModMul(Lambda, Curve.P);
  t1 := Two.ModMul(P.X, Curve.P);
  t2 := Rx.ModSub(t1, Curve.P);
  t1.Free;
  Rx.Free;
  Rx := t2;
  { R.y = lambda * (x - R.x) - y mod p }
  t1 := P.X.ModSub(Rx, Curve.P);
  t2 := Lambda.ModMul(t1, Curve.P);
  t1.Free;
  Ry := t2.ModSub(P.Y, Curve.P);
  t2.Free;
  Result := TECPoint.CreateFromXY(Rx, Ry);
  Rx.Free;
  Ry.Free;
  Lambda.Free;
  Two.Free;
  Three.Free;
end;

function PointNeg(const Curve: TECCurve; const P: TECPoint): TECPoint;
var
  NegY: TBN;
begin
  if P.Infinity then
  begin
    Result := TECPoint.InfinityPoint;
    Exit;
  end;
  NegY := TBN.CreateFromQWord(0).ModSub(P.Y, Curve.P);
  Result := TECPoint.CreateFromXY(P.X, NegY);
  NegY.Free;
end;

function IsOnCurve(const Curve: TECCurve; const P: TECPoint): Boolean;
var
  LHS, RHS, Temp, Tmp: TBN;
begin
  if P.Infinity then
  begin
    Result := True;
    Exit;
  end;
  { LHS = y^2 mod p }
  LHS := P.Y.ModMul(P.Y, Curve.P);
  { RHS = x^3 + a*x + b mod p }
  RHS := P.X.ModMul(P.X, Curve.P);
  Tmp := RHS.ModMul(P.X, Curve.P);
  RHS.Free;
  RHS := Tmp;
  Temp := Curve.A.ModMul(P.X, Curve.P);
  Tmp := RHS.ModAdd(Temp, Curve.P);
  Temp.Free;
  RHS.Free;
  RHS := Tmp;
  Tmp := RHS.ModAdd(Curve.B, Curve.P);
  RHS.Free;
  RHS := Tmp;
  Result := LHS.Equal(RHS);
  LHS.Free;
  RHS.Free;
end;

{--- Scalar multiplication (double-and-add) ---}

function ScalarMul(const Curve: TECCurve; const K: TBN; const P: TECPoint): TECPoint;
var
  R, NewR: TECPoint;
  i: LongInt;
begin
  R := TECPoint.InfinityPoint;
  for i := K.BitLength - 1 downto 0 do
  begin
    NewR := PointDouble(Curve, R);
    R.Free;
    R := NewR;
    if K.BitAt(i) then
    begin
      NewR := PointAdd(Curve, R, P);
      R.Free;
      R := NewR;
    end;
  end;
  Result := R;
end;

{--- Point encoding/decoding (SEC 1, uncompressed) ---}

{Field size in bytes: ceil(P.BitLength / 8).}
function FieldSizeBytes(const Curve: TECCurve): LongInt;
begin
  Result := (Curve.P.BitLength + 7) div 8;
end;

{Pad big-endian bytes with leading zeros to length Len.}
function PadToLen(const B: TBytes; Len: LongInt): TBytes;
var
  i: LongInt;
begin
  SetLength(Result, Len);
  FillChar(Result[0], Len, 0);
  for i := 0 to Length(B) - 1 do
    Result[Len - Length(B) + i] := B[i];
end;

function EncodePoint(const Curve: TECCurve; const P: TECPoint): TBytes;
var
  FS: LongInt;
  Xb, Yb: TBytes;
  i: LongInt;
begin
  if P.Infinity then
  begin
    SetLength(Result, 1);
    Result[0] := 0;
    Exit;
  end;
  FS := FieldSizeBytes(Curve);
  Xb := PadToLen(P.X.ToBytes(True), FS);
  Yb := PadToLen(P.Y.ToBytes(True), FS);
  SetLength(Result, 1 + 2 * FS);
  Result[0] := $04;
  for i := 0 to FS - 1 do
  begin
    Result[1 + i] := Xb[i];
    Result[1 + FS + i] := Yb[i];
  end;
end;

function DecodePoint(const Curve: TECCurve; const Data: TBytes): TECPoint;
var
  FS: LongInt;
  Xb, Yb: TBytes;
  X, Y: TBN;
  i: LongInt;
begin
  Result := nil;
  if Length(Data) = 1 then
  begin
    if Data[0] <> 0 then
      raise EBNError.Create('DecodePoint: invalid point code');
    Result := TECPoint.InfinityPoint;
    Exit;
  end;
  if Data[0] <> $04 then
    raise EBNError.Create('DecodePoint: only uncompressed (0x04) supported');
  FS := FieldSizeBytes(Curve);
  if Length(Data) <> 1 + 2 * FS then
    raise EBNError.Create('DecodePoint: invalid data length');
  SetLength(Xb, FS);
  SetLength(Yb, FS);
  for i := 0 to FS - 1 do
  begin
    Xb[i] := Data[1 + i];
    Yb[i] := Data[1 + FS + i];
  end;
  X := TBN.CreateFromBytes(Xb, True);
  Y := TBN.CreateFromBytes(Yb, True);
  if (X.Compare(Curve.P) >= 0) or (Y.Compare(Curve.P) >= 0) then
  begin
    X.Free;
    Y.Free;
    raise EBNError.Create('DecodePoint: coordinate out of field');
  end;
  Result := TECPoint.CreateFromXY(X, Y);
  X.Free;
  Y.Free;
end;
{--- TECKeypair ---}

constructor TECKeypair.Create;
begin
  PrivateKey := nil;
  PublicKey := nil;
end;

destructor TECKeypair.Destroy;
begin
  if PrivateKey <> nil then PrivateKey.Free;
  if PublicKey <> nil then PublicKey.Free;
  inherited;
end;

{--- ECDHE ---}

function GenerateKeyPair(const Curve: TECCurve): TECKeypair;
var
  D, T: TBN;
begin
  Result := TECKeypair.Create;
  { Generate random scalar d in [1, N-1].
    Repeat while d = 0 (probability ~ 2^-256). }
  repeat
    D := TBN.RandomBits(Curve.N.BitLength, @RandomByteGen);
    T := D.Modulo(Curve.N);
    D.Free;
    D := T;
  until not D.IsZero;
  Result.PrivateKey := D;
  Result.PublicKey := ScalarMul(Curve, D, Curve.G);
end;

function ComputeSharedSecret(const Curve: TECCurve; const PrivateKey: TBN;
  const PeerPublicKey: TECPoint): TECPoint;
begin
  { S = d * Q_peer, where d is our private key, Q_peer is the peer's
    public point. If PeerPublicKey is Infinity, the result is also Infinity. }
  if PeerPublicKey.Infinity then
  begin
    Result := TECPoint.InfinityPoint;
    Exit;
  end;
  Result := ScalarMul(Curve, PrivateKey, PeerPublicKey);
end;

{--- ECDSA ---}

constructor TECDsaSig.Create;
begin
  R := nil;
  S := nil;
end;

destructor TECDsaSig.Destroy;
begin
  if R <> nil then R.Free;
  if S <> nil then S.Free;
  inherited;
end;

{ Choose hash by curve: P-256 → SHA-256, P-384 → SHA-384. }
function HashForCurve(const Curve: TECCurve; const Message: TBytes): TBytes;
begin
  if Curve.N.BitLength <= 256 then
    Result := SHA256(Message)
  else
    Result := SHA384(Message);
end;

{ Convert digest to TBN, truncating/padding to length N. }
function DigestToBN(const Curve: TECCurve; const Digest: TBytes): TBN;
var
  E, T: TBN;
  DigestLen, NLen: LongInt;
begin
  E := TBN.CreateFromBytes(Digest, True);
  DigestLen := Length(Digest) * 8;
  NLen := Curve.N.BitLength;
  if DigestLen > NLen then
  begin
    T := E.ShiftRight(DigestLen - NLen);
    E.Free;
    E := T;
  end
  else if DigestLen < NLen then
  begin
    T := E.ShiftLeft(NLen - DigestLen);
    E.Free;
    E := T;
  end;
  Result := E;
end;

function ECDSASign(const Curve: TECCurve; const PrivateKey: TBN;
  const Message: TBytes): TECDsaSig;
var
  Digest: TBytes;
  E, K, R, S, W, Temp, Tmp: TBN;
  P1: TECPoint;
begin
  Result := TECDsaSig.Create;
  Digest := HashForCurve(Curve, Message);
  E := DigestToBN(Curve, Digest);
  try
    while True do
    begin
      { k = random in [1, N-1] }
      repeat
        K := TBN.RandomBits(Curve.N.BitLength, @RandomByteGen);
        Tmp := K.Modulo(Curve.N);
        K.Free;
        K := Tmp;
      until not K.IsZero;
      { (x1, y1) = k * G }
      P1 := ScalarMul(Curve, K, Curve.G);
      { r = x1 mod N }
      R := P1.X.Modulo(Curve.N);
      P1.Free;
      if R.IsZero then
      begin
        R.Free;
        K.Free;
        Continue;
      end;
      { s = k^-1 * (e + r * d) mod N }
      W := K.ModInverse(Curve.N);
      Temp := R.ModMul(PrivateKey, Curve.N);
      Tmp := Temp.ModAdd(E, Curve.N);
      Temp.Free;
      Temp := Tmp;
      S := W.ModMul(Temp, Curve.N);
      W.Free;
      Temp.Free;
      if S.IsZero then
      begin
        S.Free;
        R.Free;
        K.Free;
        Continue;
      end;
      Result.R := R;
      Result.S := S;
      K.Free;
      Break;
    end;
    E.Free;
  except
    E.Free;
    raise;
  end;
end;

function ECDSAVerify(const Curve: TECCurve; const PublicKey: TECPoint;
  const Message: TBytes; const Sig: TECDsaSig): Boolean;
var
  Digest: TBytes;
  E, W, U1, U2, V: TBN;
  P1, P2, TmpP: TECPoint;
begin
  Result := False;
  { 1. Range check: 1 <= r < N, 1 <= s < N }
  if Sig.R.IsZero or (Sig.R.Compare(Curve.N) >= 0) then Exit;
  if Sig.S.IsZero or (Sig.S.Compare(Curve.N) >= 0) then Exit;

  { 2. e = H(M) }
  Digest := HashForCurve(Curve, Message);
  E := DigestToBN(Curve, Digest);
  try
    { 3. w = s^-1 mod N }
    W := Sig.S.ModInverse(Curve.N);
    if W = nil then
    begin
      E.Free;
      Exit;
    end;

    { 4. u1 = e * w mod N, u2 = r * w mod N }
    U1 := E.ModMul(W, Curve.N);
    U2 := Sig.R.ModMul(W, Curve.N);
    W.Free;

    { 5. (x1, y1) = u1 * G + u2 * Q }
    P1 := ScalarMul(Curve, U1, Curve.G);
    P2 := ScalarMul(Curve, U2, PublicKey);
    TmpP := PointAdd(Curve, P1, P2);
    P2.Free;
    P2 := TmpP;
    P1.Free;

    { 6. If the point is at infinity, the signature is invalid }
    if P2.Infinity then
    begin
      P2.Free;
      U1.Free;
      U2.Free;
      E.Free;
      Exit;
    end;

    { 7. v = x1 mod N }
    V := P2.X.Modulo(Curve.N);
    P2.Free;

    { 8. The signature is valid if v = r }
    Result := V.Equal(Sig.R);
    V.Free;
    U1.Free;
    U2.Free;
    E.Free;
  except
    E.Free;
    raise;
  end;
end;

end.
