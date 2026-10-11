{ SPDX-License-Identifier: Apache-2.0 }
unit test_rand;
{CSPRNG tests (tls.rand): HMAC-DRBG, entropy and statistics.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TRandTests = class(TTestCase)
  published
    procedure TestDRBGDeterministic;
    procedure TestDRBGDifferentSeeds;
    procedure TestDRBGLengths;
    procedure TestDRBGReseedChanges;
    procedure TestDRBGReseedCounter;
    procedure TestSystemEntropy;
    procedure TestGlobalRandomBytes;
    procedure TestRandomQWord;
    procedure TestRandomBitsRange;
    procedure TestRandomByteGen;
    procedure TestUniformity;
    procedure TestNoTrivialRepeats;
    procedure TestRandomBitsWithTBN;
  end;

implementation

uses
  SysUtils, tls.rand, tls.bn;

function MakeSeed(Start: Byte; Count: LongInt): TBytes;
var
  i: LongInt;
begin
  SetLength(Result, Count);
  for i := 0 to Count - 1 do
    Result[i] := Byte(Start + i);
end;

function SameBytes(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and
            ((Length(A) = 0) or CompareMem(@A[0], @B[0], Length(A)));
end;

procedure TRandTests.TestDRBGDeterministic;
var
  d1, d2: THmacDRBG;
  a, b: TBytes;
begin
  d1 := THmacDRBG.Create(MakeSeed(0, 32));
  d2 := THmacDRBG.Create(MakeSeed(0, 32));
  try
    d1.Generate(a, 64);
    d2.Generate(b, 64);
    AssertTrue('same seed -> same sequence', SameBytes(a, b));
    AssertTrue('sequence is not all-zero', not SameBytes(a, MakeSeed(0, 64)));
  finally
    d1.Free;
    d2.Free;
  end;
end;

procedure TRandTests.TestDRBGDifferentSeeds;
var
  d1, d2: THmacDRBG;
  a, b: TBytes;
begin
  d1 := THmacDRBG.Create(MakeSeed(0, 32));
  d2 := THmacDRBG.Create(MakeSeed(1, 32));
  try
    d1.Generate(a, 64);
    d2.Generate(b, 64);
    AssertTrue('different seed -> different output', not SameBytes(a, b));
  finally
    d1.Free;
    d2.Free;
  end;
end;

procedure TRandTests.TestDRBGLengths;
var
  d: THmacDRBG;
  a, b: TBytes;
  n: LongInt;
const
  Lens: array[0..6] of LongInt = (0, 1, 16, 32, 33, 64, 1000);
begin
  d := THmacDRBG.Create(MakeSeed(7, 48));
  try
    for n := Low(Lens) to High(Lens) do
    begin
      d.Generate(a, Lens[n]);
      AssertEquals(Format('length %d', [Lens[n]]), Lens[n], Length(a));
      d.Generate(b, 16);
      if Lens[n] = 16 then
        AssertTrue('consecutive blocks differ', not SameBytes(a, b));
    end;
  finally
    d.Free;
  end;
end;

procedure TRandTests.TestDRBGReseedChanges;
var
  d: THmacDRBG;
  a, b: TBytes;
begin
  d := THmacDRBG.Create(MakeSeed(3, 32));
  try
    d.Generate(a, 64);
    d.Reseed(MakeSeed(200, 32));
    d.Generate(b, 64);
    AssertTrue('output changed after Reseed', not SameBytes(a, b));
  finally
    d.Free;
  end;
end;

procedure TRandTests.TestDRBGReseedCounter;
var
  d: THmacDRBG;
  B: TBytes;
begin
  d := THmacDRBG.Create(MakeSeed(5, 32));
  try
    AssertEquals('after Create', 1, d.ReseedCounter);
    d.Generate(B, 8);
    AssertEquals('after Generate', 2, d.ReseedCounter);
    d.Reseed(MakeSeed(9, 32));
    AssertEquals('after Reseed', 1, d.ReseedCounter);
    AssertTrue('no reseed needed', not d.NeedsReseed);
  finally
    d.Free;
  end;
end;

procedure TRandTests.TestSystemEntropy;
var
  a, b: TBytes;
begin
  a := SystemEntropy(64);
  b := SystemEntropy(64);
  AssertEquals('entropy length', 64, Length(a));
  AssertTrue('entropy changes between calls', not SameBytes(a, b));
  AssertEquals('entropy 0', 0, Length(SystemEntropy(0)));
end;

procedure TRandTests.TestGlobalRandomBytes;
var
  a, b, c: TBytes;
begin
  RandomBytes(a, 16);
  RandomBytes(b, 16);
  c := RandomBytes(200);
  AssertEquals('RandomBytes(16)', 16, Length(a));
  AssertEquals('RandomBytes(200)', 200, Length(c));
  AssertTrue('two calls differ', not SameBytes(a, b));
  AssertEquals('RandomBytes(0)', 0, Length(RandomBytes(0)));
end;

procedure TRandTests.TestRandomQWord;
var
  i, distinct: LongInt;
  vals: array[0..99] of QWord;
  j: LongInt;
  dup: Boolean;
begin
  distinct := 0;
  for i := 0 to 99 do
  begin
    vals[i] := RandomQWord;
    dup := False;
    for j := 0 to i - 1 do
      if vals[j] = vals[i] then
        dup := True;
    if not dup then
      Inc(distinct);
  end;
  AssertTrue('100 RandomQWord almost all unique', distinct >= 99);
end;

procedure TRandTests.TestRandomBitsRange;
var
  n: LongInt;
  B: TBytes;
  v: TBN;
begin
  for n := 0 to 130 do
  begin
    B := RandomBits(n);
    AssertEquals(Format('length of RandomBits(%d)', [n]), (n + 7) div 8, Length(B));
    if n > 0 then
    begin
      v := TBN.FromBytes(B, False);
      AssertTrue(Format('RandomBits(%d) < 2^%d', [n, n]), v.BitLength <= n);
      AssertTrue(Format('RandomBits(%d): bit %d cleared', [n, n]), not v.BitAt(n));
    end;
  end;
end;

procedure TRandTests.TestRandomByteGen;
var
  B: TBytes;
begin
  B := RandomByteGen(8);
  AssertEquals('RandomByteGen(8)', 8, Length(B));
  AssertEquals('RandomByteGen(0)', 0, Length(RandomByteGen(0)));
  AssertEquals('RandomByteGen(-1)', 0, Length(RandomByteGen(-1)));
end;

procedure TRandTests.TestUniformity;
const
  N = 1 shl 16; { 65536 bytes = 524288 bits }
var
  B: TBytes;
  counts: array[0..255] of LongInt;
  i, ones, chi2, expected: LongInt;
  k: Integer;
begin
  B := RandomBytes(N);
  FillChar(counts, SizeOf(counts), 0);
  ones := 0;
  for i := 0 to N - 1 do
  begin
    Inc(counts[B[i]]);
    for k := 0 to 7 do
      if (B[i] and (1 shl k)) <> 0 then
        Inc(ones);
  end;
  { Bit balance: expected N*4, allowed spread ±5000 (>> 5 sigma). }
  AssertTrue(Format('bit balance: %d', [ones]), Abs(ones - (N * 4)) < 5000);

  { Chi-square over 256 byte values. }
  expected := N div 256;
  chi2 := 0;
  for k := 0 to 255 do
  begin
    AssertTrue(Format('byte %d occurs', [k]), counts[k] > 0);
    Inc(chi2, (counts[k] - expected) * (counts[k] - expected) div expected);
  end;
  AssertTrue(Format('chi-square: %d (df=255)', [chi2]), chi2 < 420);
end;

procedure TRandTests.TestNoTrivialRepeats;
var
  B: TBytes;
  i, distinct, curRun, maxRun: LongInt;
  seen: array[0..255] of Boolean;
begin
  B := RandomBytes(1024);
  FillChar(seen, SizeOf(seen), 0);
  for i := 0 to High(B) do
    seen[B[i]] := True;
  distinct := 0;
  for i := 0 to 255 do
    if seen[i] then
      Inc(distinct);
  AssertTrue(Format('distinct bytes: %d', [distinct]), distinct > 200);

  maxRun := 1;
  curRun := 1;
  for i := 1 to High(B) do
  begin
    if B[i] = B[i - 1] then
      Inc(curRun)
    else
      curRun := 1;
    if curRun > maxRun then
      maxRun := curRun;
  end;
  AssertTrue(Format('maximum repeat: %d', [maxRun]), maxRun < 20);
end;

procedure TRandTests.TestRandomBitsWithTBN;
var
  a, b: TBN;
begin
  a := TBN.RandomBits(256, @RandomByteGen);
  b := TBN.RandomBits(256, @RandomByteGen);
  AssertTrue('RandomBits(256) nonzero', not a.IsZero);
  AssertTrue('RandomBits(256) <= 256 bits', a.BitLength <= 256);
  AssertTrue('two values differ', a.Compare(b) <> 0);
end;

initialization
  RegisterTest(TRandTests);

end.
