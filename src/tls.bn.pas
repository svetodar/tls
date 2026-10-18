{ SPDX-License-Identifier: Apache-2.0 }
unit tls.bn;

{Arbitrary-precision integer arithmetic (BN) in pure Pascal.
  TBN — integer >= 0: array of 64-bit words (QWord, little-endian by words),
  normalized (no leading zero words).
  Arithmetic: Add/Sub/Mul/Divide, comparison, bitwise operations,
  modular arithmetic (Modulo/ModAdd/ModSub/ModMul/ModPow/ModInverse).
  TSignedBN — signed integer (sign + magnitude) for extended GCD.
  Serves as the base block for RSA/EC/DH (docs/tasks/01-bn.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils;

type
  EBNError = class(Exception);

  {Byte generator for RandomBits: returns Count random bytes.
    In task 02 a CSPRNG (tls.rand) is plugged in here. }
  TByteGen = function(Count: LongInt): TBytes;

  TBN = class
  private
    FWords: array of QWord;
    procedure Normalize;
    function WordAt(i: LongInt): QWord;
    class function FromWords(const W: array of QWord): TBN;
  public
    constructor Create;
    constructor CreateFromQWord(v: QWord);
    constructor CreateFromBytes(const B: TBytes; bigEndian: Boolean);
    constructor CreateFromHex(const S: string);
    constructor CreateFromDec(const S: string);
    class function FromQWord(v: QWord): TBN;
    class function FromBytes(const B: TBytes; bigEndian: Boolean): TBN;
    class function FromHex(const S: string): TBN;
    class function FromDec(const S: string): TBN;
    {Random n-bit number (0 <= r < 2^n) via the byte generator. }
    class function RandomBits(n: LongInt; const Gen: TByteGen): TBN;

    function Clone: TBN;
    function Compare(const B: TBN): Integer;
    function Equal(const B: TBN): Boolean;
    function IsZero: Boolean;
    function BitLength: LongInt;
    function BitAt(i: LongInt): Boolean;

    function Add(const B: TBN): TBN;
    {Sub: self - B; error if B > self. }
    function Sub(const B: TBN): TBN;
    function Mul(const B: TBN): TBN;
    { Divide: Q = self div B, Result = self mod B. }
    function Divide(const B: TBN; var Q: TBN): TBN;
    function ShiftLeft(n: LongInt): TBN;
    function ShiftRight(n: LongInt): TBN;
    function AndBits(const B: TBN): TBN;
    function OrBits(const B: TBN): TBN;
    function XorBits(const B: TBN): TBN;
    {NotBits: complement over BitLength bits (2^BitLength - 1 - self). }
    function NotBits: TBN;
    {Neg: 0 -> 0; for nonzero — error (TBN >= 0). }
    function Neg: TBN;

    function Modulo(const B: TBN): TBN;
    function ModAdd(const B, M: TBN): TBN;
    function ModSub(const B, M: TBN): TBN;
    function ModMul(const B, M: TBN): TBN;
    {Binary exponentiation: self^E mod M. 0^0 = 1. }
    function ModPow(const E, M: TBN): TBN;
    {self^-1 mod M; nil if the inverse does not exist. }
    function ModInverse(const M: TBN): TBN;

    function ToBytes(bigEndian: Boolean): TBytes;
    function ToHex: string;
    function ToString: string; reintroduce;
  end;

  {Signed integer: sign + magnitude (for extended GCD in ModInverse). }
  TSignedBN = record
    Neg: Boolean;
    Mag: TBN;
  end;

  function SBFromBN(const A: TBN): TSignedBN;
  function SBFromInt(v: Int64): TSignedBN;
  function SBNeg(const A: TSignedBN): TSignedBN;
  function SBAdd(const A, B: TSignedBN): TSignedBN;
  function SBSub(const A, B: TSignedBN): TSignedBN;
  function SBMul(const A, B: TSignedBN): TSignedBN;
  function SBCompare(const A, B: TSignedBN): Integer;
  {SBToBN: error if A < 0. }
  function SBToBN(const A: TSignedBN): TBN;

implementation

{--- Helper functions ---}

function BN_WordBitLength(w: QWord): LongInt;
begin
  Result := 0;
  while w > 0 do
  begin
    Inc(Result);
    w := w shr 1;
  end;
end;

{64x64 -> 128 multiplication (lo:hi), carry-propagating via 32-bit halves. }
procedure BN_Mul64x64(a, b: QWord; var lo, hi: QWord);
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
  c := QWord(s < p1); {carry of bit 65 of the sum p1+p2 }
  mid := (s and $FFFFFFFF) shl 32;
  lo := mid + p0;
  hi := p3 + (s shr 32) + (c shl 32) + QWord(lo < mid);
end;

{Division of 128-bit (hi:lo) by 64-bit d > 0: q = div, r = mod.
  Bit-by-bit: r := 2r + bit, then r := r - d if r >= d.
  Invariant: before the step r < d, hence rhi = 0. }
procedure BN_Div128(hi, lo, d: QWord; var q, r: QWord);
var
  i: LongInt;
  rhi, rlo, bit: QWord;
begin
  {Requires hi < d, otherwise q >= 2^64 (QWord overflow). }
  if hi >= d then
    raise EBNError.Create('BN_Div128: quotient overflow');
  q := 0;
  rlo := 0;
  for i := 63 downto 0 do
  begin
    bit := (hi shr i) and 1;
    rhi := rlo shr 63;
    rlo := (rlo shl 1) or bit;
    q := q shl 1;
    if (rhi = 1) or (rlo >= d) then
    begin
      rlo := rlo - d; {at rhi = 1 the carry wraps correctly }
      q := q or 1;
    end;
  end;
  for i := 63 downto 0 do
  begin
    bit := (lo shr i) and 1;
    rhi := rlo shr 63;
    rlo := (rlo shl 1) or bit;
    q := q shl 1;
    if (rhi = 1) or (rlo >= d) then
    begin
      rlo := rlo - d;
      q := q or 1;
    end;
  end;
  r := rlo;
end;

{Array word shifts are done inline in Divide (FPC does not allow
  returning an open array from a function). }

function HexCharVal(c: Char): LongInt;
begin
  if (c >= '0') and (c <= '9') then
    Result := Ord(c) - Ord('0')
  else if (c >= 'a') and (c <= 'f') then
    Result := Ord(c) - Ord('a') + 10
  else if (c >= 'A') and (c <= 'F') then
    Result := Ord(c) - Ord('A') + 10
  else
    raise EBNError.CreateFmt('TBN: not a hex char: %c', [c]);
end;

function QWordToHex(v: QWord; minDigits: LongInt): string;
const
  D = '0123456789abcdef';
var
  s: string;
begin
  s := '';
  while v > 0 do
  begin
    s := D[1 + Integer(v and $F)] + s;
    v := v shr 4;
  end;
  while Length(s) < minDigits do
    s := '0' + s;
  Result := s;
end;

{--- TBN: constructors ---}

constructor TBN.Create;
begin
  inherited Create;
  FWords := nil;
end;

procedure TBN.Normalize;
begin
  while (Length(FWords) > 0) and (FWords[Length(FWords) - 1] = 0) do
    SetLength(FWords, Length(FWords) - 1);
end;

function TBN.WordAt(i: LongInt): QWord;
begin
  if (i >= 0) and (i < Length(FWords)) then
    Result := FWords[i]
  else
    Result := 0;
end;

class function TBN.FromWords(const W: array of QWord): TBN;
var
  i: LongInt;
begin
  Result := TBN.Create;
  SetLength(Result.FWords, Length(W));
  for i := 0 to Length(W) - 1 do
    Result.FWords[i] := W[i];
  Result.Normalize;
end;

constructor TBN.CreateFromQWord(v: QWord);
begin
  inherited Create;
  if v <> 0 then
  begin
    SetLength(FWords, 1);
    FWords[0] := v;
  end;
end;

constructor TBN.CreateFromBytes(const B: TBytes; bigEndian: Boolean);
var
  i, n: LongInt;
begin
  inherited Create;
  n := Length(B);
  if n = 0 then
    Exit;
  SetLength(FWords, (n + 7) div 8);
  if bigEndian then
    for i := 0 to n - 1 do
      FWords[(n - 1 - i) div 8] := FWords[(n - 1 - i) div 8] or
                                   (QWord(B[i]) shl (((n - 1 - i) mod 8) * 8))
  else
    for i := 0 to n - 1 do
      FWords[i div 8] := FWords[i div 8] or
                         (QWord(B[i]) shl ((i mod 8) * 8));
  Normalize;
end;

constructor TBN.CreateFromHex(const S: string);
var
  i, j: LongInt;
  v: QWord;
  hs: string;
begin
  inherited Create;
  hs := Trim(S);
  if (Length(hs) >= 2) and
     ((hs[1] = '$') or ((hs[1] = '0') and (hs[2] in ['x', 'X']))) then
    Delete(hs, 1, 2);
  if hs = '' then
    Exit;
  while Length(hs) mod 16 <> 0 do
    hs := '0' + hs;
  SetLength(FWords, Length(hs) div 16);
  for i := 0 to Length(FWords) - 1 do
  begin
    v := 0;
    for j := 1 to 16 do
      v := (v shl 4) + QWord(HexCharVal(hs[i * 16 + j]));
    {Hex string — from most significant digits to least significant; FWords — little-endian.}
    FWords[Length(FWords) - 1 - i] := v;
  end;
  Normalize;
end;

constructor TBN.CreateFromDec(const S: string);
var
  i, k: LongInt;
  carry, t, hi: QWord;
  ds: string;
begin
  inherited Create;
  ds := Trim(S);
  if ds = '' then
    raise EBNError.Create('TBN: empty string');
  if ds[1] = '+' then
    Delete(ds, 1, 1);
  if ds[1] = '-' then
    raise EBNError.Create('TBN: negative numbers not supported');
  for i := 1 to Length(ds) do
  begin
    if (ds[i] < '0') or (ds[i] > '9') then
      raise EBNError.CreateFmt('TBN: non-decimal character: %c', [ds[i]]);
    carry := QWord(Ord(ds[i]) - Ord('0')); { digit to add }
    for k := 0 to Length(FWords) - 1 do
    begin
      BN_Mul64x64(FWords[k], 10, t, hi);
      t := t + carry;
      if t < carry then
        Inc(hi);
      carry := hi;
      FWords[k] := t;
    end;
    if carry <> 0 then
    begin
      SetLength(FWords, Length(FWords) + 1);
      FWords[Length(FWords) - 1] := carry;
    end;
  end;
end;

class function TBN.FromQWord(v: QWord): TBN;
begin
  Result := TBN.CreateFromQWord(v);
end;

class function TBN.FromBytes(const B: TBytes; bigEndian: Boolean): TBN;
begin
  Result := TBN.CreateFromBytes(B, bigEndian);
end;

class function TBN.FromHex(const S: string): TBN;
begin
  Result := TBN.CreateFromHex(S);
end;

class function TBN.FromDec(const S: string): TBN;
begin
  Result := TBN.CreateFromDec(S);
end;

class function TBN.RandomBits(n: LongInt; const Gen: TByteGen): TBN;
var
  bytes: TBytes;
  nb, extra: LongInt;
begin
  if n < 0 then
    raise EBNError.Create('TBN.RandomBits: n < 0');
  if n = 0 then
    Exit(TBN.Create);
  nb := (n + 7) div 8;
  extra := nb * 8 - n; { how many high bits to clear }
  bytes := Gen(nb);
  if Length(bytes) < nb then
    raise EBNError.Create('TBN.RandomBits: generator returned too few bytes');
  if extra > 0 then
    bytes[nb - 1] := bytes[nb - 1] and Byte((1 shl (8 - extra)) - 1);
  Result := TBN.FromBytes(bytes, False);
end;

{--- TBN: comparison and bits ---}

function TBN.Clone: TBN;
begin
  Result := TBN.Create;
  Result.FWords := Copy(FWords);
end;

function TBN.Compare(const B: TBN): Integer;
var
  i: LongInt;
begin
  if Length(FWords) <> Length(B.FWords) then
  begin
    if Length(FWords) > Length(B.FWords) then
      Result := 1
    else
      Result := -1;
    Exit;
  end;
  for i := Length(FWords) - 1 downto 0 do
    if FWords[i] <> B.FWords[i] then
    begin
      if FWords[i] > B.FWords[i] then
        Result := 1
      else
        Result := -1;
      Exit;
    end;
  Result := 0;
end;

function TBN.Equal(const B: TBN): Boolean;
begin
  Result := Compare(B) = 0;
end;

function TBN.IsZero: Boolean;
begin
  Result := Length(FWords) = 0;
end;

function TBN.BitLength: LongInt;
var
  i: LongInt;
  w: QWord;
begin
  if IsZero then
    Exit(0);
  i := Length(FWords) - 1;
  w := FWords[i];
  Result := i * 64;
  while w > 0 do
  begin
    Inc(Result);
    w := w shr 1;
  end;
end;

function TBN.BitAt(i: LongInt): Boolean;
var
  w: QWord;
begin
  if (i < 0) or (i >= BitLength) then
    Exit(False);
  w := FWords[i div 64];
  Result := ((w shr (i mod 64)) and QWord(1)) <> 0;
end;

{--- TBN: arithmetic ---}

function TBN.Add(const B: TBN): TBN;
var
  n, i: LongInt;
  carry: QWord;
  wa, wb: QWord;
begin
  Result := TBN.Create;
  n := Length(FWords);
  if Length(B.FWords) > n then
    n := Length(B.FWords);
  SetLength(Result.FWords, n + 1);
  carry := 0;
  for i := 0 to n - 1 do
  begin
    wa := WordAt(i);
    wb := B.WordAt(i);
    Result.FWords[i] := wa + wb + carry;
    carry := QWord((Result.FWords[i] < wa) or
                   ((carry <> 0) and (Result.FWords[i] < wb)));
  end;
  Result.FWords[n] := carry;
  Result.Normalize;
end;

function TBN.Sub(const B: TBN): TBN;
var
  n, i: LongInt;
  borrow: QWord;
  wa, wb: QWord;
begin
  if Compare(B) < 0 then
    raise EBNError.Create('TBN.Sub: B > self (negative result)');
  Result := TBN.Create;
  n := Length(FWords);
  SetLength(Result.FWords, n);
  borrow := 0;
  for i := 0 to n - 1 do
  begin
    wa := FWords[i];
    wb := B.WordAt(i);
    if (wa < wb) or ((borrow = 1) and (wa = wb)) then
    begin
      Result.FWords[i] := wa - wb - borrow;
      borrow := 1;
    end
    else
    begin
      Result.FWords[i] := wa - wb - borrow;
      borrow := 0;
    end;
  end;
  Result.Normalize;
end;

function TBN.Mul(const B: TBN): TBN;
var
  i, j, n, m: LongInt;
  carry, lo, hi: QWord;
begin
  Result := TBN.Create;
  n := Length(FWords);
  m := Length(B.FWords);
  if (n = 0) or (m = 0) then
    Exit;
  SetLength(Result.FWords, n + m);
  for i := 0 to n - 1 do
  begin
    carry := 0;
    for j := 0 to m - 1 do
    begin
      BN_Mul64x64(FWords[i], B.FWords[j], lo, hi);
      { lo:hi += carry + Result[i+j] taking into account two carries. }
      hi := hi + QWord(lo + carry < lo);
      lo := lo + carry;
      hi := hi + QWord(lo + Result.FWords[i + j] < lo);
      lo := lo + Result.FWords[i + j];
      Result.FWords[i + j] := lo;
      carry := hi;
    end;
    Result.FWords[i + m] := carry;
  end;
  Result.Normalize;
end;

{ Division (Knuth's algorithm D): Q = self div B, Result = self mod B.
  The remainder is maintained in the dividend array da: at step j the window is
  da[j..j+m] (m+1 words, the most significant being da[j+m]). }
function TBN.Divide(const B: TBN; var Q: TBN): TBN;
const
  MaxW = High(QWord);
var
  n, m, s, j, i: LongInt;
  da, db: array of QWord;
  qa, tmp, rem: array of QWord;
  qhat, rhat, plo, phi, u, t, ai, borrow, wa: QWord;
  skipCorr: Boolean;
begin
  if B.IsZero then
    raise EBNError.Create('TBN.Divide: division by zero');
  if IsZero then
  begin
    Q := TBN.Create;
    Result := TBN.Create;
    Exit; { Q = 0, R = 0 }
  end;
  n := Length(FWords);
  m := Length(B.FWords);
  if n < m then
  begin
    Q := TBN.Create;
    Result := Clone;
    Exit;
  end;

  { Normalization: left shift so that the most significant bit of db[m-1] is set. }
  s := 64 - BN_WordBitLength(B.FWords[m - 1]);
  SetLength(da, n + 1);
  Move(FWords[0], da[0], n * SizeOf(QWord));
  da[n] := 0;
  SetLength(db, m);
  Move(B.FWords[0], db[0], m * SizeOf(QWord));
  if s > 0 then
  begin
    for i := n downto 1 do
      da[i] := (da[i] shl s) or (da[i - 1] shr (64 - s));
    da[0] := da[0] shl s;
    for i := m - 1 downto 1 do
      db[i] := (db[i] shl s) or (db[i - 1] shr (64 - s));
    db[0] := db[0] shl s;
  end;

  SetLength(qa, n - m + 1);
  SetLength(tmp, m + 1);

  for j := n - m downto 0 do
  begin
    { Estimate qhat: window < divisor, therefore da[j+m] <= db[m-1]. }
    skipCorr := False;
    if da[j + m] = db[m - 1] then
    begin
      qhat := MaxW;
      { rhat = (da[j+m]*2^64 + da[j+m-1]) mod db[m-1] = da[j+m-1] + db[m-1]. }
      if da[j + m - 1] > MaxW - db[m - 1] then
      begin
        rhat := MaxW; { overflow of b*rhat — no correction needed }
        skipCorr := True;
      end
      else
        rhat := da[j + m - 1] + db[m - 1];
    end
    else
      BN_Div128(da[j + m], da[j + m - 1], db[m - 1], qhat, rhat);

    { Correction: while qhat*db[m-2] > rhat*2^64 + da[j+m-2]. }
    if (not skipCorr) and (m >= 2) then
    begin
      ai := da[j + m - 2];
      BN_Mul64x64(qhat, db[m - 2], plo, phi);
      while (phi > rhat) or ((phi = rhat) and (plo > ai)) do
      begin
        Dec(qhat);
        if rhat > MaxW - db[m - 1] then
          Break; { rhat + db[m-1] >= b: correction complete }
        Inc(rhat, db[m - 1]);
        BN_Mul64x64(qhat, db[m - 2], plo, phi);
      end;
    end;

    { tmp = qhat * db (m+1 words). }
    t := 0;
    for i := 0 to m - 1 do
    begin
      BN_Mul64x64(qhat, db[i], plo, phi);
      u := plo + t;
      tmp[i] := u;
      t := phi + QWord(u < plo);
    end;
    tmp[m] := t;

    { Window da[j..j+m] -= tmp (m+1 words). }
    borrow := 0;
    for i := 0 to m do
    begin
      if (da[j + i] < tmp[i]) or
         ((borrow = 1) and (da[j + i] = tmp[i])) then
      begin
        da[j + i] := da[j + i] - tmp[i] - borrow;
        borrow := 1;
      end
      else
      begin
        da[j + i] := da[j + i] - tmp[i] - borrow;
        borrow := 0;
      end;
    end;

    {If borrow — qhat is overestimated: decrement and return db.}
    if borrow <> 0 then
    begin
      Dec(qhat);
      t := 0;
      for i := 0 to m - 1 do
      begin
        wa := da[j + i];
        u := wa + db[i] + t;
        da[j + i] := u;
        t := QWord((u < wa) or ((t <> 0) and (u < db[i])));
      end;
      da[j + m] := da[j + m] + t;
    end;
    qa[j] := qhat;
  end;

  {Remainder — da[0..m-1]; denormalization.}
  if s > 0 then
  begin
    for i := 0 to m - 2 do
      da[i] := (da[i] shr s) or (da[i + 1] shl (64 - s));
    da[m - 1] := da[m - 1] shr s;
  end;
  SetLength(rem, m);
  for i := 0 to m - 1 do
    rem[i] := da[i];

  Q := TBN.FromWords(qa);
  Result := TBN.FromWords(rem);
end;

{--- TBN: bitwise operations ---}

function TBN.ShiftLeft(n: LongInt): TBN;
var
  wordShift, bitShift, i, oldLen: LongInt;
  v: QWord;
begin
  Result := TBN.Create;
  if IsZero then
    Exit;
  if n = 0 then
    Exit(Clone);
  wordShift := n div 64;
  bitShift := n mod 64;
  oldLen := Length(FWords);
  SetLength(Result.FWords, oldLen + wordShift + 1);
  if bitShift = 0 then
  begin
    for i := 0 to oldLen - 1 do
      Result.FWords[i + wordShift] := FWords[i];
    Result.FWords[oldLen + wordShift] := 0;
  end
  else
  begin
    for i := 0 to oldLen - 1 do
    begin
      v := FWords[i] shl bitShift;
      if i > 0 then
        v := v or (FWords[i - 1] shr (64 - bitShift));
      Result.FWords[i + wordShift] := v;
    end;
    Result.FWords[oldLen + wordShift] := FWords[oldLen - 1] shr (64 - bitShift);
  end;
  Result.Normalize;
end;

function TBN.ShiftRight(n: LongInt): TBN;
var
  wordShift, bitShift, i, newLen: LongInt;
  v: QWord;
begin
  Result := TBN.Create;
  if IsZero then
    Exit;
  if n = 0 then
    Exit(Clone);
  wordShift := n div 64;
  bitShift := n mod 64;
  if wordShift >= Length(FWords) then
    Exit;
  newLen := Length(FWords) - wordShift;
  SetLength(Result.FWords, newLen);
  if bitShift = 0 then
    for i := 0 to newLen - 1 do
      Result.FWords[i] := FWords[i + wordShift]
  else
    for i := 0 to newLen - 1 do
    begin
      v := FWords[i + wordShift] shr bitShift;
      if i + wordShift + 1 < Length(FWords) then
        v := v or (FWords[i + wordShift + 1] shl (64 - bitShift));
      Result.FWords[i] := v;
    end;
  Result.Normalize;
end;

function TBN.AndBits(const B: TBN): TBN;
var
  n, i: LongInt;
begin
  Result := TBN.Create;
  n := Length(FWords);
  if Length(B.FWords) < n then
    n := Length(B.FWords);
  SetLength(Result.FWords, n);
  for i := 0 to n - 1 do
    Result.FWords[i] := FWords[i] and B.FWords[i];
  Result.Normalize;
end;

function TBN.OrBits(const B: TBN): TBN;
var
  n, i: LongInt;
begin
  Result := TBN.Create;
  n := Length(FWords);
  if Length(B.FWords) > n then
    n := Length(B.FWords);
  SetLength(Result.FWords, n);
  for i := 0 to n - 1 do
    Result.FWords[i] := WordAt(i) or B.WordAt(i);
  Result.Normalize;
end;

function TBN.XorBits(const B: TBN): TBN;
var
  n, i: LongInt;
begin
  Result := TBN.Create;
  n := Length(FWords);
  if Length(B.FWords) > n then
    n := Length(B.FWords);
  SetLength(Result.FWords, n);
  for i := 0 to n - 1 do
    Result.FWords[i] := WordAt(i) xor B.WordAt(i);
  Result.Normalize;
end;

function TBN.NotBits: TBN;
var
  one, pow, mask: TBN;
begin
  {Bitwise complement over BitLength bits: 2^BitLength - 1 - self.
    Every intermediate TBN is released; they are not owned by Result.}
  if IsZero then
    Exit(TBN.Create);
  one := TBN.FromQWord(1);
  try
    pow := one.ShiftLeft(BitLength);
    try
      mask := pow.Sub(one);
      try
        Result := mask.Sub(Self);
      finally
        mask.Free;
      end;
    finally
      pow.Free;
    end;
  finally
    one.Free;
  end;
end;

function TBN.Neg: TBN;
begin
  if IsZero then
    Result := TBN.Create
  else
    raise EBNError.Create('TBN.Neg: negative numbers not supported (TBN >= 0)');
end;

{--- TBN: modular arithmetic ---}

function TBN.Modulo(const B: TBN): TBN;
var
  q: TBN;
begin
  Result := Divide(B, q);
  q.Free;
end;

function TBN.ModAdd(const B, M: TBN): TBN;
var
  s: TBN;
begin
  if M.IsZero then
    raise EBNError.Create('TBN.ModAdd: M = 0');
  s := Add(B);
  Result := s.Modulo(M);
  s.Free;
end;

function TBN.ModSub(const B, M: TBN): TBN;
var
  a, bm, t: TBN;
begin
  if M.IsZero then
    raise EBNError.Create('TBN.ModSub: M = 0');
  a := Modulo(M);
  bm := B.Modulo(M);
  try
    if a.Compare(bm) >= 0 then
      Result := a.Sub(bm)
    else
    begin
      {M + a - bm in range (0, 2M).}
      t := a.Add(M);
      Result := t.Sub(bm);
      t.Free;
      if Result.Compare(M) >= 0 then
      begin
        t := Result;
        Result := t.Sub(M);
        t.Free;
      end;
    end;
  finally
    a.Free;
    bm.Free;
  end;
end;

function TBN.ModMul(const B, M: TBN): TBN;
var
  p: TBN;
begin
  if M.IsZero then
    raise EBNError.Create('TBN.ModMul: M = 0');
  p := Mul(B);
  Result := p.Modulo(M);
  p.Free;
end;

function TBN.ModPow(const E, M: TBN): TBN;
var
  acc, base, tmp: TBN;
  i: LongInt;
begin
  if M.IsZero then
    raise EBNError.Create('TBN.ModPow: M = 0');
  acc := TBN.FromQWord(1);
  base := Modulo(M);
  for i := E.BitLength - 1 downto 0 do
  begin
    tmp := acc.ModMul(acc, M);
    acc.Free;
    acc := tmp;
    if E.BitAt(i) then
    begin
      tmp := acc.ModMul(base, M);
      acc.Free;
      acc := tmp;
    end;
  end;
  base.Free;
  Result := acc;
end;

function TBN.ModInverse(const M: TBN): TBN;
var
  t, newt, tmpT, qs, prod, msb: TSignedBN;
  r, newr, q, rem, one: TBN;
begin
  if M.IsZero then
    raise EBNError.Create('TBN.ModInverse: M = 0');
  t := SBFromInt(0);
  newt := SBFromInt(1);
  r := M.Clone;
  newr := Modulo(M);
  while not newr.IsZero do
  begin
    rem := r.Divide(newr, q); { q = r div newr, rem = r mod newr }
    qs := SBFromBN(q);
    prod := SBMul(qs, newt);
    tmpT := SBSub(t, prod);
    prod.Mag.Free;
    {t <- newt; the previous t is no longer referenced.}
    t.Mag.Free;
    t := newt;
    newt := tmpT;
    {r <- newr; the previous r is no longer referenced.}
    r.Free;
    r := newr;
    newr := rem;
    q.Free;
  end;
  one := TBN.FromQWord(1);
  if r.Compare(one) <> 0 then
    Result := nil {GCD > 1: no inverse element}
  else
  begin
    msb := SBFromBN(M);
    while t.Neg do
    begin
      tmpT := SBAdd(t, msb);
      t.Mag.Free;
      t := tmpT;
    end;
    Result := t.Mag;
    t.Mag := nil; {ownership transferred to Result}
  end;
  t.Mag.Free;
  newt.Mag.Free;
  r.Free;
  newr.Free;
  one.Free;
end;

{--- TBN: conversion ---}

function TBN.ToBytes(bigEndian: Boolean): TBytes;
var
  n, i: LongInt;
begin
  Result := nil;
  n := (BitLength + 7) div 8;
  SetLength(Result, n);
  if bigEndian then
    for i := 0 to n - 1 do
      Result[i] := Byte(FWords[(n - 1 - i) div 8] shr
                        (((n - 1 - i) mod 8) * 8))
  else
    for i := 0 to n - 1 do
      Result[i] := Byte(FWords[i div 8] shr ((i mod 8) * 8));
end;

function TBN.ToHex: string;
var
  i: LongInt;
begin
  if IsZero then
    Exit('0');
  Result := QWordToHex(FWords[Length(FWords) - 1], 0);
  for i := Length(FWords) - 2 downto 0 do
    Result := Result + QWordToHex(FWords[i], 16);
end;

function TBN.ToString: string;
const
  Base: QWord = 10;
var
  n, q, rem, Divisor: TBN;
  s: string;
begin
  if IsZero then
    Exit('0');
  Divisor := TBN.CreateFromQWord(Base);
  n := Clone;
  s := '';
  while not n.IsZero do
  begin
    rem := n.Divide(Divisor, q);
    s := Chr(Ord('0') + Integer(rem.WordAt(0))) + s;
    rem.Free;
    n.Free;
    n := q;
  end;
  n.Free;
  Divisor.Free;
  Result := s;
end;

{--- TSignedBN ---}

function SBFromBN(const A: TBN): TSignedBN;
begin
  Result.Neg := False;
  Result.Mag := A;
end;

function SBFromInt(v: Int64): TSignedBN;
begin
  if v < 0 then
  begin
    Result.Neg := True;
    Result.Mag := TBN.CreateFromQWord(QWord(-v));
  end
  else
  begin
    Result.Neg := False;
    Result.Mag := TBN.CreateFromQWord(QWord(v));
  end;
end;

function SBNeg(const A: TSignedBN): TSignedBN;
begin
  Result.Neg := not A.Neg;
  Result.Mag := A.Mag;
end;

function SBAdd(const A, B: TSignedBN): TSignedBN;
var
  c: Integer;
begin
  if A.Neg = B.Neg then
  begin
    Result.Neg := A.Neg;
    Result.Mag := A.Mag.Add(B.Mag);
  end
  else
  begin
    c := A.Mag.Compare(B.Mag);
    if c = 0 then
    begin
      Result.Neg := False;
      Result.Mag := TBN.Create;
    end
    else if c > 0 then
    begin
      Result.Neg := A.Neg;
      Result.Mag := A.Mag.Sub(B.Mag);
    end
    else
    begin
      Result.Neg := B.Neg;
      Result.Mag := B.Mag.Sub(A.Mag);
    end;
  end;
end;

function SBSub(const A, B: TSignedBN): TSignedBN;
begin
  Result := SBAdd(A, SBNeg(B));
end;

function SBMul(const A, B: TSignedBN): TSignedBN;
begin
  Result.Neg := (A.Neg <> B.Neg);
  Result.Mag := A.Mag.Mul(B.Mag);
end;

function SBCompare(const A, B: TSignedBN): Integer;
begin
  if A.Neg <> B.Neg then
    Result := Ord(B.Neg) - Ord(A.Neg)
  else if A.Neg then
    Result := B.Mag.Compare(A.Mag)
  else
    Result := A.Mag.Compare(B.Mag);
end;

function SBToBN(const A: TSignedBN): TBN;
begin
  if A.Neg and not A.Mag.IsZero then
    raise EBNError.Create('SBToBN: negative number');
  Result := A.Mag;
end;

end.
