{ SPDX-License-Identifier: Apache-2.0 }
unit test_x25519;

{X25519 tests (tls.x25519): RFC 7748 vectors (raw scalar
  multiplication, base point, iterated, Diffie-Hellman), scalar
  clamping, high-bit masking, key generation and low-order rejection.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TX25519Tests = class(TTestCase)
  published
    procedure TestRFC7748Vector1;
    procedure TestRFC7748Vector2;
    procedure TestRFC7748BasePoint;
    procedure TestRFC7748Iterated1000;
    procedure TestRFC7748DiffieHellman;
    procedure TestInputHighBitMasked;
    procedure TestLowOrderPointsProduceZero;
    procedure TestClamp;
    procedure TestPublicKeyFromPrivate;
    procedure TestKeyPairConsistency;
    procedure TestRejectBadLengths;
    procedure TestRejectLowOrderSharedSecret;
  end;

implementation

uses
  SysUtils, tls.x25519;

function HexNibble(ch: Char): Byte;
begin
  case ch of
    '0'..'9': Result := Ord(ch) - Ord('0');
    'a'..'f': Result := Ord(ch) - Ord('a') + 10;
    'A'..'F': Result := Ord(ch) - Ord('A') + 10;
  else
    raise Exception.Create('bad hex digit: ' + ch);
  end;
end;

function HexToBytes(const S: string): TBytes;
var
  i: Integer;
begin
  if (Length(S) mod 2) <> 0 then
    raise Exception.Create('hex string must have even length');
  SetLength(Result, Length(S) div 2);
  for i := 0 to High(Result) do
    Result[i] := (HexNibble(S[2 * i + 1]) shl 4) or HexNibble(S[2 * i + 2]);
end;

function BytesToHex(const B: TBytes): string;
const
  HexDigits = '0123456789abcdef';
var
  i: Integer;
begin
  Result := '';
  for i := 0 to High(B) do
    Result := Result + HexDigits[(B[i] shr 4) + 1] + HexDigits[(B[i] and 15) + 1];
end;

const
  { RFC 7748, section 5.2. }
  TV1Scalar = 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4';
  TV1U      = 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c';
  TV1Out    = 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552';
  TV2Scalar = '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d';
  TV2U      = 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493';
  TV2Out    = '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957';
  BaseScalar = '0900000000000000000000000000000000000000000000000000000000000000';
  Iter1Out   = '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079';
  Iter1000Out = '684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51';

  { RFC 7748, section 6.1 (Diffie-Hellman). }
  AlicePriv = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
  AlicePub  = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
  BobPriv   = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
  BobPub    = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
  SharedOut = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

procedure TX25519Tests.TestRFC7748Vector1;
begin
  AssertEquals('RFC 7748 vector 1', TV1Out,
    BytesToHex(X25519(HexToBytes(TV1Scalar), HexToBytes(TV1U))));
end;

procedure TX25519Tests.TestRFC7748Vector2;
begin
  AssertEquals('RFC 7748 vector 2', TV2Out,
    BytesToHex(X25519(HexToBytes(TV2Scalar), HexToBytes(TV2U))));
end;

procedure TX25519Tests.TestRFC7748BasePoint;
begin
  AssertEquals('RFC 7748 base point scalar multiplication', Iter1Out,
    BytesToHex(X25519(HexToBytes(BaseScalar), HexToBytes(BaseScalar))));
end;

procedure TX25519Tests.TestRFC7748Iterated1000;
var
  k, u, r: TBytes;
  i: Integer;
begin
  k := HexToBytes(BaseScalar);
  u := HexToBytes(BaseScalar);
  for i := 1 to 1000 do
  begin
    r := X25519(k, u);
    u := k;
    k := r;
  end;
  AssertEquals('RFC 7748 after 1000 iterations', Iter1000Out,
    BytesToHex(k));
end;

procedure TX25519Tests.TestRFC7748DiffieHellman;
var
  SharedA, SharedB: TBytes;
begin
  AssertEquals('Alice public key', AlicePub,
    BytesToHex(X25519PublicKey(HexToBytes(AlicePriv))));
  AssertEquals('Bob public key', BobPub,
    BytesToHex(X25519PublicKey(HexToBytes(BobPriv))));

  SharedA := X25519SharedSecret(HexToBytes(AlicePriv), HexToBytes(BobPub));
  SharedB := X25519SharedSecret(HexToBytes(BobPriv), HexToBytes(AlicePub));
  AssertEquals('Alice shared secret', SharedOut, BytesToHex(SharedA));
  AssertEquals('Bob shared secret', SharedOut, BytesToHex(SharedB));
end;

procedure TX25519Tests.TestLowOrderPointsProduceZero;
const
  ZeroU   = '0000000000000000000000000000000000000000000000000000000000000000';
  OneU    = '0100000000000000000000000000000000000000000000000000000000000000';
  MinusOneU = 'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f';
  ZeroOut = '0000000000000000000000000000000000000000000000000000000000000000';
var
  k: TBytes;
begin
  k := HexToBytes(AlicePriv);
  AssertEquals('u = 0', ZeroOut, BytesToHex(X25519(k, HexToBytes(ZeroU))));
  AssertEquals('u = 1', ZeroOut, BytesToHex(X25519(k, HexToBytes(OneU))));
  AssertEquals('u = p-1', ZeroOut, BytesToHex(X25519(k, HexToBytes(MinusOneU))));
end;

procedure TX25519Tests.TestInputHighBitMasked;
var
  u1, u2, r1, r2: TBytes;
begin
  u1 := HexToBytes(TV1U);
  u2 := Copy(u1, 0, X25519KeySize);
  u2[31] := u2[31] or $80;
  r1 := X25519(HexToBytes(TV1Scalar), u1);
  r2 := X25519(HexToBytes(TV1Scalar), u2);
  AssertEquals('bit 255 of u is ignored', BytesToHex(r1), BytesToHex(r2));
end;

procedure TX25519Tests.TestClamp;
var
  k: TBytes;
begin
  k := X25519Clamp(HexToBytes(
    'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'));
  AssertEquals('clamped low byte', 248, k[0]);
  AssertEquals('clamped high byte', 127, k[31]);
  k := X25519Clamp(HexToBytes('0000000000000000000000000000000000000000000000000000000000000000'));
  AssertEquals('clamped high byte sets bit 254', 64, k[31]);
end;

procedure TX25519Tests.TestPublicKeyFromPrivate;
begin
  AssertEquals('public key from private scalar', AlicePub,
    BytesToHex(X25519PublicKey(HexToBytes(AlicePriv))));
end;

procedure TX25519Tests.TestKeyPairConsistency;
var
  A, B: TX25519KeyPair;
  SA, SB: TBytes;
begin
  A := X25519GenerateKeyPair;
  B := X25519GenerateKeyPair;
  AssertEquals('private key length', X25519KeySize, Length(A.PrivateKey));
  AssertEquals('public key length', X25519KeySize, Length(A.PublicKey));
  AssertEquals('public key matches scalar', BytesToHex(A.PublicKey),
    BytesToHex(X25519PublicKey(A.PrivateKey)));

  SA := X25519SharedSecret(A.PrivateKey, B.PublicKey);
  SB := X25519SharedSecret(B.PrivateKey, A.PublicKey);
  AssertEquals('generated key pairs agree', BytesToHex(SA), BytesToHex(SB));
end;

procedure TX25519Tests.TestRejectBadLengths;
var
  Failed: Boolean;
begin
  Failed := False;
  try
    X25519(HexToBytes('00'), HexToBytes(TV1U));
  except
    on E: EX25519Error do
      Failed := True;
  end;
  AssertTrue('short scalar is rejected', Failed);

  Failed := False;
  try
    X25519(HexToBytes(TV1Scalar), HexToBytes('00'));
  except
    on E: EX25519Error do
      Failed := True;
  end;
  AssertTrue('short u-coordinate is rejected', Failed);
end;

procedure TX25519Tests.TestRejectLowOrderSharedSecret;
var
  Zero: TBytes;
  Failed: Boolean;
begin
  SetLength(Zero, X25519KeySize);
  FillChar(Zero[0], X25519KeySize, 0);
  Failed := False;
  try
    X25519SharedSecret(HexToBytes(AlicePriv), Zero);
  except
    on E: EX25519Error do
      Failed := True;
  end;
  AssertTrue('all-zero shared secret is rejected', Failed);
end;

initialization
  RegisterTest(TX25519Tests);

end.
