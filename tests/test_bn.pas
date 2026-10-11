unit test_bn;
{Tests for arbitrary-precision integer arithmetic (tls.bn).
  Known vectors + properties (a = q*b + r, a*inv ≡ 1 mod m, etc.).}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TBNTests = class(TTestCase)
  published
    procedure TestSmallArithmetic;
    procedure TestKnownMulDivMod;
    procedure TestKnownModPow;
    procedure TestModInverseKnown;
    procedure TestFromDecRoundTrip;
    procedure TestHexRoundTrip;
    procedure TestBytesRoundTrip;
    procedure TestShifts;
    procedure TestBitwise;
    procedure TestNotBits;
    procedure TestBitProperties;
    procedure TestRandomBitsRange;
    procedure TestDivideProperty;
    procedure TestMulCommutative;
    procedure TestModInverseProperty;
    procedure TestModPowLaws;
    procedure TestFermat61;
    procedure TestPerformance2048;
  end;

implementation

uses
  SysUtils, DateUtils, tls.bn;

{Deterministic byte generator (xorshift64*), so that properties
  are checked reproducibly and do not depend on Random of other tests.}
var
  GRandState: QWord = QWord($9E3779B97F4A7C15);

function TestRng(Count: LongInt): TBytes;
var
  i: LongInt;
  x: QWord;
begin
  Result := nil;
  SetLength(Result, Count);
  for i := 0 to Count - 1 do
  begin
    x := GRandState;
    x := x xor (x shr 12);
    x := x xor (x shl 25);
    x := x xor (x shr 27);
    GRandState := x;
    Result[i] := Byte((x * QWord(2685821657736338717)) shr 40);
  end;
end;

function RandBN(Bits: LongInt): TBN;
begin
  Result := TBN.RandomBits(Bits, @TestRng);
end;

{--- Known vectors ---}

procedure TBNTests.TestSmallArithmetic;
var
  a, b: TBN;
begin
  a := TBN.FromQWord(High(QWord));
  AssertEquals('2^64-1 hex', 'ffffffffffffffff', a.ToHex);
  AssertEquals('2^64-1 bits', 64, a.BitLength);
  b := a.Add(TBN.FromQWord(1));
  AssertEquals('2^64 hex', '10000000000000000', b.ToHex);
  AssertEquals('2^64 bits', 65, b.BitLength);
  AssertEquals('2^64 dec', '18446744073709551616', b.ToString);
  AssertEquals('sub round-trip', 'ffffffffffffffff', b.Sub(TBN.FromQWord(1)).ToHex);

  { 2^128. }
  AssertEquals('2^128 dec',
    '340282366920938463463374607431768211456',
    TBN.FromQWord(1).ShiftLeft(128).ToString);
end;

procedure TBNTests.TestKnownMulDivMod;
var
  a, b, m, q, r: TBN;
begin
  { a = 2^255 + 12345, b = 3^100. }
  a := TBN.FromHex('8000000000000000000000000000000000000000000000000000000000003039');
  b := TBN.FromHex('5a4653ca673768565b41f775d6947d55cf3813d1');
  m := TBN.FromHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43');

  AssertEquals('a*b',
    '2d2329e5339bb42b2da0fbbaeb4a3eaae79c09e8800000000000000000001101495e9b6b5ee66c56b01631789e8ffef5a7339989',
    a.Mul(b).ToHex);
  r := a.Divide(b, q);
  AssertEquals('a div b', '16afb1df2eff892c23d28e616', q.ToHex);
  AssertEquals('a mod b', '38bfac690eee902f1cb1876ac9952e95e9b8b643', r.ToHex);
  AssertEquals('q*b+r', a.ToHex, q.Mul(b).Add(r).ToHex);
  { a < m, so the remainder equals a itself; check on a smaller modulus. }
  AssertEquals('a mod m', a.ToHex, a.Modulo(m).ToHex);
  m := TBN.FromHex('ffffffffffffffffffffffffffffff61');
  AssertEquals('a mod m2', '8000000000000000000000000000614a', a.Modulo(m).ToHex);
  AssertEquals('a dec',
    '57896044618658097711785492504343953926634992332820282019728792003956564832313',
    a.ToString);
end;

procedure TBNTests.TestKnownModPow;
var
  a, m, e: TBN;
begin
  { 3^413 mod 97 = 48. }
  AssertEquals('3^413 mod 97', '48',
    TBN.FromDec('3').ModPow(TBN.FromDec('413'), TBN.FromDec('97')).ToString);

  { a^65537 mod m for 256-bit a and m. }
  a := TBN.FromHex('8000000000000000000000000000000000000000000000000000000000003039');
  m := TBN.FromHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff43');
  e := TBN.FromQWord(65537);
  AssertEquals('a^65537 mod m',
    '5ab87965567223e59c0e4993c77a6d933b917213895fe9a02d3a924667387329',
    a.ModPow(e, m).ToHex);
end;

procedure TBNTests.TestModInverseKnown;
var
  inv: TBN;
begin
  inv := TBN.FromQWord(3).ModInverse(TBN.FromQWord(11));
  AssertTrue('3^-1 mod 11 exists', inv <> nil);
  AssertEquals('3^-1 mod 11', '4', inv.ToHex);
  AssertEquals('3*4 mod 11', '1',
    TBN.FromQWord(3).ModMul(TBN.FromQWord(4), TBN.FromQWord(11)).ToString);

  { No inverse: gcd(6, 9) = 3. }
  AssertTrue('6^-1 mod 9 does not exist', TBN.FromQWord(6).ModInverse(TBN.FromQWord(9)) = nil);
end;

procedure TBNTests.TestFromDecRoundTrip;
const
  Dec300 =
    '100000000000000000000000000000000000000000000000000000000000000000' +
    '000000000000000000000000000000000000000000000000000000000000000000' +
    '000000000000000000000000000000000000000000000000000000000000000000' +
    '000000000000000000000000000000000000000000000000000000000000000000' +
    '0000000000000000000000000000123456789';
begin
  AssertEquals('10^300+123456789 hex',
    '17e43c8800759ba59c08e14c7cd7aad86a4a458109f91c21c571dbe84d52d936f44abe8a3d5b48c1' +
    '00959d9d0b6cc856b3adc93b67aea8f8e067d2c8d04bc177f7b4287a6e3fcda36fa3b3342eaeb442' +
    'e15d450952f4dd100000000000000000000000000000000000000000000000000000000000000000000' +
    '75bcd15',
    TBN.FromDec(Dec300).ToHex);
  AssertEquals('dec round-trip', Dec300, TBN.FromDec(Dec300).ToString);

  { Signed + and leading zeros. }
  AssertEquals('leading zeros', '123', TBN.FromDec('000123').ToString);
  AssertEquals('plus', '123', TBN.FromDec('+123').ToString);
end;

procedure TBNTests.TestHexRoundTrip;
var
  a: TBN;
begin
  a := TBN.FromHex('deadbeefcafebabe1122334455667788');
  AssertEquals('hex round-trip', 'deadbeefcafebabe1122334455667788', a.ToHex);
  AssertEquals('hex>>4', 'deadbeefcafebabe112233445566778', a.ShiftRight(4).ToHex);
  AssertEquals('hex<<4', 'deadbeefcafebabe11223344556677880', a.ShiftLeft(4).ToHex);
end;

procedure TBNTests.TestBytesRoundTrip;
var
  a, rt: TBN;
  be, le: TBytes;
begin
  a := TBN.FromHex('0123456789abcdef00ffeeddccbbaa998877665544332211');
  be := a.ToBytes(True);
  le := a.ToBytes(False);
  AssertEquals('big-endian length', 24, Length(be));
  AssertEquals('big-endian [0]', $01, Integer(be[0]));
  AssertEquals('big-endian [23]', $11, Integer(be[23]));
  AssertEquals('little-endian [0]', $11, Integer(le[0]));
  AssertEquals('little-endian [23]', $01, Integer(le[23]));
  rt := TBN.FromBytes(be, True);
  AssertEquals('BE round-trip', a.ToHex, rt.ToHex);
  rt := TBN.FromBytes(le, False);
  AssertEquals('LE round-trip', a.ToHex, rt.ToHex);
end;

procedure TBNTests.TestShifts;
var
  a: TBN;
begin
  a := TBN.FromQWord(1);
  AssertEquals('1<<0', '1', a.ShiftLeft(0).ToHex);
  AssertEquals('1<<63', '8000000000000000', a.ShiftLeft(63).ToHex);
  AssertEquals('1<<64', '10000000000000000', a.ShiftLeft(64).ToHex);
  AssertEquals('1<<65', '20000000000000000', a.ShiftLeft(65).ToHex);
  AssertEquals('1<<128 >>128', '1', a.ShiftLeft(128).ShiftRight(128).ToHex);
  AssertEquals('shift > bits', '0', a.ShiftRight(5).ToHex);
  AssertEquals('zero shl', '0', TBN.FromQWord(0).ShiftLeft(100).ToHex);
  AssertEquals('zero shr', '0', TBN.FromQWord(0).ShiftRight(100).ToHex);
end;

procedure TBNTests.TestBitwise;
var
  a, b: TBN;
begin
  a := TBN.FromHex('ff00ff00ff00ff00');
  b := TBN.FromHex('0f0f0f0f0f0f0f0f');
  AssertEquals('and', 'f000f000f000f00', a.AndBits(b).ToHex);
  AssertEquals('or', 'ff0fff0fff0fff0f', a.OrBits(b).ToHex);
  AssertEquals('xor', 'f00ff00ff00ff00f', a.XorBits(b).ToHex);
  { Different length: the shorter one is padded with zeros. }
  AssertEquals('and short', 'f000f000',
    a.AndBits(TBN.FromHex('f0f0f0f0')).ToHex);
end;

procedure TBNTests.TestNotBits;
var
  a: TBN;
begin
  AssertEquals('not 0', '0', TBN.FromQWord(0).NotBits.ToHex);
  AssertEquals('not 1', '0', TBN.FromQWord(1).NotBits.ToHex);
  AssertEquals('not 5 (101)', '2', TBN.FromQWord(5).NotBits.ToHex);
  { Padding only by significant bits, not by machine words. }
  a := TBN.FromHex('ff');
  AssertEquals('not ff', '0', a.NotBits.ToHex);
  a := TBN.FromHex('100');
  AssertEquals('not 100', 'ff', a.NotBits.ToHex);
end;

procedure TBNTests.TestBitProperties;
var
  a: TBN;
  i, bl: LongInt;
  ones: Integer;
begin
  a := TBN.FromHex('deadbeefcafebabe');
  AssertEquals('bitlength', 64, a.BitLength);
  AssertTrue('bit0', not a.BitAt(0));
  AssertTrue('bit1', a.BitAt(1));
  AssertTrue('bit63', a.BitAt(63));
  AssertTrue('bit64 missing', not a.BitAt(64));

  { Sum of set bits, reconstruction from bits. }
  a := TBN.FromHex('123456789abcdef0123456789abcdef');
  bl := a.BitLength;
  ones := 0;
  for i := 0 to bl - 1 do
    if a.BitAt(i) then
      Inc(ones);
  AssertEquals('number of set bits', 64, ones);
  AssertEquals('bitlength 121', 121, bl);
end;

procedure TBNTests.TestRandomBitsRange;
var
  i, bits: LongInt;
  v, limit: TBN;
begin
  for bits := 0 to 130 do
  begin
    v := RandBN(bits);
    limit := TBN.FromQWord(1).ShiftLeft(bits);
    AssertTrue(Format('RandomBits(%d) < 2^%d', [bits, bits]), v.Compare(limit) < 0);
    if bits > 0 then
      AssertTrue(Format('RandomBits(%d) bitlen <= %d', [bits, bits]), v.BitLength <= bits);
  end;
  { Nonzero result for sufficiently wide requests. }
  v := RandBN(256);
  AssertTrue('RandomBits(256) != 0', not v.IsZero);
end;

{--- Properties on random data ---}

procedure TBNTests.TestDivideProperty;
var
  i: LongInt;
  a, b, q, r: TBN;
begin
  for i := 1 to 40 do
  begin
    a := RandBN(64 + (i * 13) mod 448);
    b := RandBN(8 + (i * 7) mod 200).OrBits(TBN.FromQWord(1));
    r := a.Divide(b, q);
    AssertEquals(Format('division %d: q*b+r', [i]), a.ToHex, q.Mul(b).Add(r).ToHex);
    AssertTrue(Format('division %d: r < b', [i]), r.Compare(b) < 0);
    AssertEquals(Format('division %d: mod', [i]), r.ToHex, a.Modulo(b).ToHex);
  end;
end;

procedure TBNTests.TestMulCommutative;
var
  i: LongInt;
  a, b: TBN;
begin
  for i := 1 to 30 do
  begin
    a := RandBN(1 + (i * 29) mod 600);
    b := RandBN(1 + (i * 17) mod 600);
    AssertEquals(Format('mul comm %d', [i]), a.Mul(b).ToHex, b.Mul(a).ToHex);
    AssertEquals(Format('add comm %d', [i]), a.Add(b).ToHex, b.Add(a).ToHex);
  end;
end;

procedure TBNTests.TestModInverseProperty;
var
  i: LongInt;
  a, m, inv: TBN;
begin
  for i := 1 to 30 do
  begin
    m := RandBN(8 + (i * 11) mod 250).OrBits(TBN.FromQWord(1));
    a := RandBN(8 + (i * 23) mod 250).Modulo(m);
    inv := a.ModInverse(m);
    if inv <> nil then
    begin
      AssertTrue(Format('inv %d in range', [i]), inv.Compare(m) < 0);
      AssertEquals(Format('a*inv ≡ 1 mod m (%d)', [i]), '1',
        a.ModMul(inv, m).ToHex);
    end;
  end;
end;

procedure TBNTests.TestModPowLaws;
var
  i: LongInt;
  a, m, e1, e2, left, right: TBN;
begin
  for i := 1 to 20 do
  begin
    m := RandBN(16 + (i * 9) mod 240).OrBits(TBN.FromQWord(1));
    a := RandBN(16 + (i * 5) mod 240).Modulo(m);
    e1 := RandBN(8 + (i * 3) mod 80);
    e2 := RandBN(8 + (i * 7) mod 80);

    { a^(e1+e2) == a^e1 * a^e2 (mod m). }
    left := a.ModPow(e1.Add(e2), m);
    right := a.ModPow(e1, m).ModMul(a.ModPow(e2, m), m);
    AssertEquals(Format('modpow add %d', [i]), left.ToHex, right.ToHex);

    { (a^e1)^e2 == a^(e1*e2) (mod m). }
    left := a.ModPow(e1, m).ModPow(e2, m);
    right := a.ModPow(e1.Mul(e2), m);
    AssertEquals(Format('modpow mul %d', [i]), left.ToHex, right.ToHex);
  end;
end;

procedure TBNTests.TestFermat61;
var
  p, a, r: TBN;
  i: LongInt;
begin
  { p = 2^61-1 — prime (Mersenne). By Fermat's little theorem a^(p-1) ≡ 1. }
  p := TBN.FromQWord(1).ShiftLeft(61).Sub(TBN.FromQWord(1));
  for i := 1 to 5 do
  begin
    a := RandBN(60).OrBits(TBN.FromQWord(1));
    if a.Compare(p) >= 0 then
      a := a.Modulo(p);
    if a.IsZero then
      a := TBN.FromQWord(2);
    r := a.ModPow(p.Sub(TBN.FromQWord(1)), p);
    AssertEquals(Format('Fermat %d', [i]), '1', r.ToHex);
  end;
end;

procedure TBNTests.TestPerformance2048;
var
  a, e, m, r: TBN;
  t0: TDateTime;
  ms: Int64;
begin
  a := RandBN(2048).OrBits(TBN.FromQWord(1));
  e := RandBN(2048).OrBits(TBN.FromQWord(1));
  m := RandBN(2048).OrBits(TBN.FromQWord(1));
  t0 := Now;
  r := a.ModPow(e, m);
  ms := MilliSecondsBetween(Now, t0);
  AssertTrue(Format('2048-bit ModPow completed in 5 s (%d ms)', [ms]), ms < 5000);
  AssertTrue('result < m', r.Compare(m) < 0);
end;

initialization
  RegisterTest(TBNTests);

end.
