{ SPDX-License-Identifier: Apache-2.0 }
unit tls.rsa;

{RSA (RFC 8017) in pure Pascal.
  PKCS#1 v1.5 and PSS — sign/verify, encrypt/decrypt,
  key generation (Miller-Rabin).
  Implementation for task 06 (docs/tasks/06-rsa.md).
  Note: TBytes in FPC is 0-based ({$A-} by default). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, tls.bn, tls.rand, tls.sha2;

type
  TRSAKey = class
  private
    FN, FE, FD, FP, FQ: TBN;
  public
    constructor Create;
    destructor Destroy; override;
    {Public key (n, e) without the private part. }
    class function FromPublic(const AN, AE: TBN): TRSAKey;
    class function FromPublicBytes(const AModulus, AExponent: TBytes;
      ABigEndian: Boolean = True): TRSAKey;
    function PublicEncrypt(const M: TBN): TBN;
    function PrivateDecrypt(const C: TBN): TBN;
    function VerifyPKCS1v15(const Signature: TBN; const Hash: TBytes; const Oid: string): Boolean;
    function VerifyPSS(const Signature: TBN; const Hash: TBytes; SaltLen: Integer = -1): Boolean;
    {RSAES-PKCS1-v1_5 (RFC 8017 §7.1/§7.2, block type 02). }
    function EncryptPKCS1v15(const AMessage: TBytes): TBN;
    function DecryptPKCS1v15(const ACiphertext: TBN): TBytes;
    {Same, with ciphertext/message as big-endian bytes. }
    function EncryptPKCS1v15Bytes(const AMessage: TBytes): TBytes;
    function DecryptPKCS1v15Bytes(const ACiphertext: TBytes): TBytes;
    procedure Generate(Bits: LongInt);
    function SignPKCS1v15(const Hash: TBytes; const Oid: string): TBN;
    function SignPSS(const Hash: TBytes; SaltLen: Integer = -1): TBN;
    property N: TBN read FN;
    property E: TBN read FE;
    property D: TBN read FD;
    property P: TBN read FP;
    property Q: TBN read FQ;
  end;

function IsPrime(const N: TBN; Rounds: Integer = 20): Boolean;
function OidToDerBytes(const Oid: string): TBytes;
function PKCS1v15Encode(const Digest: TBytes; const Oid: string; ModLen: LongInt): TBN;
function PKCS1v15Decode(const AEM: TBN; const Oid: string; ModLen: LongInt; CheckOID: Boolean = True): TBytes;
function PKCS1v15EncryptEncode(const AMessage: TBytes; ModLen: LongInt): TBN;
function PKCS1v15DecryptDecode(const AEM: TBN; ModLen: LongInt): TBytes;
function PSSEncode(const Digest: TBytes; const Oid: string; SaltLen: LongInt; ModLen: LongInt): TBN;
function PSSVerify(const AEM: TBN; const Digest: TBytes; const Oid: string; SaltLen: LongInt; ModLen: LongInt): Boolean;

implementation

function OidToDerBytes(const Oid: string): TBytes;
var
  parts: array[0..15] of QWord;
  nParts: Integer;
  i, k: Integer;
  v: QWord;
  buf: array[0..4] of Byte;
  cnt: Integer;
  b: Byte;
  first: Boolean;
  s: string;
  dotPos: Integer;
  c: Char;
  out: TBytes;
  totalLen: Integer;
  pos: Integer;
begin
  nParts := 0;
  s := Oid;
  while Length(s) > 0 do
  begin
    dotPos := 0;
    for i := 1 to Length(s) do
    begin
      c := s[i];
      if c = '.' then
      begin
        dotPos := i;
        Break;
      end;
    end;
    if dotPos = 0 then
    begin
      parts[nParts] := StrToInt64(s);
      Inc(nParts);
      Break;
    end
    else
    begin
      parts[nParts] := StrToInt64(Copy(s, 1, dotPos - 1));
      Inc(nParts);
      s := Copy(s, dotPos + 1, Length(s) - dotPos);
    end;
  end;
  totalLen := 1;
  for i := 2 to nParts - 1 do
  begin
    v := parts[i];
    cnt := 0;
    while v > 0 do
    begin
      Inc(cnt);
      v := v shr 7;
    end;
    Inc(totalLen, cnt);
  end;
  SetLength(out, totalLen);
  out[0] := Byte(parts[0] * 40 + parts[1]);
  pos := 1;
  for i := 2 to nParts - 1 do
  begin
    v := parts[i];
    cnt := 0;
    first := True;
    while v > 0 do
    begin
      b := Byte(v and $7F);
      if not first then
        b := b or $80;
      buf[cnt] := b;
      Inc(cnt);
      v := v shr 7;
      first := False;
    end;
    for k := 0 to cnt - 1 do
      out[pos + k] := buf[cnt - 1 - k];
    pos := pos + cnt;
  end;
  Result := out;
end;

function MGF1(const Seed: TBytes; Len: LongInt): TBytes;
var
  i: LongInt;
  counter: LongWord;
  block: TBytes;
  h: TBytes;
  n: LongInt;
begin
  SetLength(Result, Len);
  i := 0;
  counter := 0;
  while i < Len do
  begin
    SetLength(block, Length(Seed) + 4);
    Move(Seed[0], block[0], Length(Seed));
    block[Length(Seed)] := Byte(counter shr 24);
    block[Length(Seed)+1] := Byte(counter shr 16);
    block[Length(Seed)+2] := Byte(counter shr 8);
    block[Length(Seed)+3] := Byte(counter);
    h := SHA256(block);
    n := Length(h);
    if n > Len - i then
      n := Len - i;
    Move(h[0], Result[i], n);
    i := i + n;
    Inc(counter);
  end;
end;

function PKCS1v15Encode(const Digest: TBytes; const Oid: string; ModLen: LongInt): TBN;
var
  oidBytes: TBytes;
  digestInfo: TBytes;
  em: TBytes;
  psLen: LongInt;
  i: LongInt;
begin
  oidBytes := OidToDerBytes(Oid);
  SetLength(digestInfo, 2 + (2 + 2 + Length(oidBytes) + 2) + (2 + Length(Digest)));
  digestInfo[0] := $30;
  digestInfo[1] := Byte(2 + 2 + Length(oidBytes) + 2 + 2 + Length(Digest));
  i := 2;
  digestInfo[i] := $30;
  digestInfo[i+1] := Byte(2 + 2 + Length(oidBytes) + 2);
  i := i + 2;
  digestInfo[i] := $06;
  digestInfo[i+1] := Byte(Length(oidBytes));
  Move(oidBytes[0], digestInfo[i+2], Length(oidBytes));
  i := i + 2 + Length(oidBytes);
  digestInfo[i] := $05;
  digestInfo[i+1] := $00;
  i := i + 2;
  digestInfo[i] := $04;
  digestInfo[i+1] := Byte(Length(Digest));
  Move(Digest[0], digestInfo[i+2], Length(Digest));

  psLen := ModLen - Length(digestInfo) - 3;
  if psLen < 8 then
    raise Exception.Create('PKCS1v15: modulus too small');
  SetLength(em, ModLen);
  em[0] := $00;
  em[1] := $01;
  for i := 2 to 1 + psLen do
    em[i] := $FF;
  em[2 + psLen] := $00;
  Move(digestInfo[0], em[3 + psLen], Length(digestInfo));
  Result := TBN.FromBytes(em, True);
end;

function PKCS1v15Decode(const AEM: TBN; const Oid: string; ModLen: LongInt;
  CheckOID: Boolean = True): TBytes;
var
  em, saved: TBytes;
  oidBytes: TBytes;
  i, k: LongInt;
  oidLen, octLen, origLen: LongInt;
begin
  Result := nil;
  em := AEM.ToBytes(True);
  if Length(em) < ModLen then
  begin
    origLen := Length(em);
    SetLength(saved, origLen);
    Move(em[0], saved[0], origLen);
    SetLength(em, ModLen);
    for i := 0 to ModLen - origLen - 1 do
      em[i] := $00;
    Move(saved[0], em[ModLen - origLen], origLen);
  end;
  if (em[0] <> $00) or (em[1] <> $01) then
    Exit;
  i := 2;
  while (i < ModLen) and (em[i] = $FF) do
    Inc(i);
  if (i >= ModLen) or (em[i] <> $00) then
    Exit;
  Inc(i);
  if (i >= ModLen) or (em[i] <> $30) then
    Exit;
  i := i + 2;
  if (i >= ModLen) or (em[i] <> $30) then
    Exit;
  i := i + 2;
  if (i >= ModLen) or (em[i] <> $06) then
    Exit;
  oidLen := em[i+1];
  i := i + 2;
  if CheckOID then
  begin
    oidBytes := OidToDerBytes(Oid);
    if (oidLen <> Length(oidBytes)) then
      Exit;
    for k := 0 to oidLen - 1 do
      if em[i + k] <> oidBytes[k] then
        Exit;
  end;
  i := i + oidLen;
  if (i >= ModLen) or (em[i] <> $05) or (em[i+1] <> $00) then
    Exit;
  i := i + 2;
  if (i >= ModLen) or (em[i] <> $04) then
    Exit;
  octLen := em[i+1];
  i := i + 2;
  if (i + octLen > ModLen) then
    Exit;
  SetLength(Result, octLen);
  Move(em[i], Result[0], octLen);
end;

{I2OSP: integer -> big-endian bytes of fixed length (RFC 8017 §4.1). }
function I2OSP(const X: TBN; Len: LongInt): TBytes;
var
  raw: TBytes;
  i, n: LongInt;
begin
  SetLength(Result, Len);
  if X.IsZero then
    Exit;
  raw := X.ToBytes(True);
  if Length(raw) > Len then
    raise Exception.Create('I2OSP: integer too large');
  n := Length(raw);
  for i := 0 to n - 1 do
    Result[Len - n + i] := raw[i];
end;

{RSAES-PKCS1-v1_5: EME-PKCS1-v1_5 (RFC 8017 §7.2.1).
  EM = 0x00 || 0x02 || PS || 0x00 || M, PS — random nonzero bytes (>= 8). }
function PKCS1v15EncryptEncode(const AMessage: TBytes; ModLen: LongInt): TBN;
var
  em, rnd: TBytes;
  psLen, mLen, i, j: LongInt;
begin
  mLen := Length(AMessage);
  if ModLen < 11 then
    raise Exception.Create('PKCS1v15 encrypt: modulus too small');
  if mLen > ModLen - 11 then
    raise Exception.Create('PKCS1v15 encrypt: message too long');
  psLen := ModLen - mLen - 3;
  SetLength(em, ModLen);
  em[0] := $00;
  em[1] := $02;
  i := 2;
  while i < 2 + psLen do
  begin
    rnd := RandomBytes(psLen - (i - 2) + 8);
    for j := 0 to Length(rnd) - 1 do
      if rnd[j] <> 0 then
      begin
        em[i] := rnd[j];
        Inc(i);
        if i >= 2 + psLen then
          Break;
      end;
  end;
  em[2 + psLen] := $00;
  for j := 0 to mLen - 1 do
    em[3 + psLen + j] := AMessage[j];
  Result := TBN.FromBytes(em, True);
end;

{RSAES-PKCS1-v1_5: EME-PKCS1-v1_5 decode (RFC 8017 §7.2.2).
  Returns nil on any format error (constant-time not guaranteed). }
function PKCS1v15DecryptDecode(const AEM: TBN; ModLen: LongInt): TBytes;
var
  em: TBytes;
  i, sep, mLen: LongInt;
begin
  Result := nil;
  if (ModLen < 11) or (AEM = nil) then
    Exit;
  em := I2OSP(AEM, ModLen);
  if (em[0] <> $00) or (em[1] <> $02) then
    Exit;
  sep := -1;
  for i := 2 to ModLen - 1 do
    if em[i] = $00 then
    begin
      sep := i;
      Break;
    end;
  if (sep < 0) or (sep - 2 < 8) then
    Exit;
  mLen := ModLen - sep - 1;
  SetLength(Result, mLen);
  for i := 0 to mLen - 1 do
    Result[i] := em[sep + 1 + i];
end;

{EMSA-PSS-ENCODE (RFC 8017, §9.1.1). Digest — already computed mHash.
  emBits = ModLen*8 - 1 (modulus — product of two primes). }
function PSSEncode(const Digest: TBytes; const Oid: string; SaltLen: LongInt; ModLen: LongInt): TBN;
var
  hLen, emLen, emBits, emPs, dbLen, extra: LongInt;
  salt, mprime, h, db, mask, maskedDb, em: TBytes;
  i: LongInt;
begin
  hLen := Length(Digest);
  if SaltLen < 0 then
    SaltLen := hLen;
  emLen := ModLen;
  emBits := ModLen * 8 - 1;
  if emLen < hLen + SaltLen + 2 then
    raise Exception.Create('PSS: modulus too small');
  dbLen := emLen - hLen - 1;
  emPs := emLen - SaltLen - hLen - 2;

  { M' = 0x00*8 || mHash || salt, H = Hash(M'). }
  SetLength(mprime, 8 + hLen + SaltLen);
  for i := 0 to 7 do
    mprime[i] := $00;
  if hLen > 0 then
    Move(Digest[0], mprime[8], hLen);
  salt := RandomBytes(SaltLen);
  if SaltLen > 0 then
    Move(salt[0], mprime[8 + hLen], SaltLen);
  h := SHA256(mprime);

  { DB = PS || 0x01 || salt. }
  SetLength(db, dbLen);
  for i := 0 to emPs - 1 do
    db[i] := $00;
  db[emPs] := $01;
  if SaltLen > 0 then
    Move(salt[0], db[emPs + 1], SaltLen);

  { maskedDB = DB xor MGF1(H, dbLen). }
  mask := MGF1(h, dbLen);
  SetLength(maskedDb, dbLen);
  for i := 0 to dbLen - 1 do
    maskedDb[i] := Byte(db[i] xor mask[i]);

  {Clear the high bits that do not fit in emBits (leftmost emLen*8-emBits). }
  extra := ModLen * 8 - emBits;
  if extra > 0 then
    maskedDb[0] := maskedDb[0] and Byte($FF shr extra);

  { EM = maskedDB || H || 0xbc. }
  SetLength(em, emLen);
  if dbLen > 0 then
    Move(maskedDb[0], em[0], dbLen);
  Move(h[0], em[dbLen], hLen);
  em[emLen - 1] := $bc;
  Result := TBN.FromBytes(em, True);
end;

{EMSA-PSS-VERIFY (RFC 8017, §9.1.2). Digest — already computed mHash. }
function PSSVerify(const AEM: TBN; const Digest: TBytes; const Oid: string; SaltLen: LongInt; ModLen: LongInt): Boolean;
var
  em, saved, h, h2, db, maskedDb, mask, mprime, salt: TBytes;
  hLen, emLen, emBits, emPs, dbLen, extra, origLen, i: LongInt;
  diff: Byte;
begin
  Result := False;
  hLen := Length(Digest);
  if SaltLen < 0 then
    SaltLen := hLen;
  emLen := ModLen;
  emBits := ModLen * 8 - 1;
  if emLen < hLen + SaltLen + 2 then
    Exit;
  dbLen := emLen - hLen - 1;
  emPs := emLen - SaltLen - hLen - 2;

  {EM must be exactly emLen bytes (with leading zeros). }
  em := AEM.ToBytes(True);
  if Length(em) < emLen then
  begin
    origLen := Length(em);
    SetLength(saved, origLen);
    if origLen > 0 then
      Move(em[0], saved[0], origLen);
    SetLength(em, emLen);
    for i := 0 to emLen - origLen - 1 do
      em[i] := $00;
    if origLen > 0 then
      Move(saved[0], em[emLen - origLen], origLen);
  end;

  {3. The rightmost byte of EM must be 0xbc. }
  if em[emLen - 1] <> $bc then
    Exit;

  {4. The leftmost bits of maskedDB must be zero. }
  extra := ModLen * 8 - emBits;
  if extra > 0 then
    if (em[0] and Byte($FF shl (8 - extra))) <> 0 then
      Exit;

  { 5. DB = maskedDB xor MGF1(H, dbLen). }
  SetLength(maskedDb, dbLen);
  if dbLen > 0 then
    Move(em[0], maskedDb[0], dbLen);
  SetLength(h, hLen);
  Move(em[dbLen], h[0], hLen);
  mask := MGF1(h, dbLen);
  SetLength(db, dbLen);
  for i := 0 to dbLen - 1 do
    db[i] := Byte(maskedDb[i] xor mask[i]);
  if extra > 0 then
    db[0] := db[0] and Byte($FF shr extra);

  {6. Check DB = PS || 0x01 || salt. }
  for i := 0 to emPs - 1 do
    if db[i] <> $00 then
      Exit;
  if db[emPs] <> $01 then
    Exit;
  if SaltLen > 0 then
    salt := Copy(db, emPs + 1, SaltLen)
  else
    salt := nil;

  { 7. H' = Hash(0x00*8 || mHash || salt); compare with H. }
  SetLength(mprime, 8 + hLen + SaltLen);
  for i := 0 to 7 do
    mprime[i] := $00;
  if hLen > 0 then
    Move(Digest[0], mprime[8], hLen);
  if SaltLen > 0 then
    Move(salt[0], mprime[8 + hLen], SaltLen);
  h2 := SHA256(mprime);
  diff := 0;
  for i := 0 to hLen - 1 do
    diff := diff or (h[i] xor h2[i]);
  Result := diff = 0;
end;

function IsPrime(const N: TBN; Rounds: Integer = 20): Boolean;
var
  nMinus1, d: TBN;
  r: LongInt;
  a, x: TBN;
  i, j: Integer;
  tmp: TBN;
begin
  if N.Compare(TBN.FromQWord(2)) = 0 then
  begin
    Result := True;
    Exit;
  end;
  if N.Compare(TBN.FromQWord(2)) < 0 then
  begin
    Result := False;
    Exit;
  end;
  if not N.BitAt(0) then
  begin
    Result := False;
    Exit;
  end;
  nMinus1 := N.Sub(TBN.FromQWord(1));
  d := nMinus1.Clone;
  r := 0;
  while not d.BitAt(0) do
  begin
    d := d.ShiftRight(1);
    Inc(r);
  end;
  for i := 1 to Rounds do
  begin
    a := TBN.RandomBits(N.BitLength, @RandomByteGen);
    a := a.Modulo(nMinus1);
    if a.Compare(TBN.FromQWord(2)) < 0 then
      a := a.Add(TBN.FromQWord(2));
    x := a.ModPow(d, N);
    if (x.IsZero) or x.Equal(TBN.FromQWord(1)) then
      Continue;
    tmp := x.Clone;
    for j := 1 to r - 1 do
    begin
      if tmp.Equal(nMinus1) then
        Break;
      tmp := tmp.ModMul(tmp, N);
    end;
    if not tmp.Equal(nMinus1) then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

constructor TRSAKey.Create;
begin
  inherited Create;
  FN := nil;
  FE := nil;
  FD := nil;
  FP := nil;
  FQ := nil;
end;

destructor TRSAKey.Destroy;
begin
  FN.Free;
  FE.Free;
  FD.Free;
  FP.Free;
  FQ.Free;
  inherited Destroy;
end;

class function TRSAKey.FromPublic(const AN, AE: TBN): TRSAKey;
begin
  if (AN = nil) or (AE = nil) then
    raise Exception.Create('RSA FromPublic: nil modulus or exponent');
  if AN.IsZero or AE.IsZero then
    raise Exception.Create('RSA FromPublic: zero modulus or exponent');
  Result := TRSAKey.Create;
  Result.FN := AN.Clone;
  Result.FE := AE.Clone;
end;

class function TRSAKey.FromPublicBytes(const AModulus, AExponent: TBytes;
  ABigEndian: Boolean = True): TRSAKey;
begin
  if (AModulus = nil) or (AExponent = nil) then
    raise Exception.Create('RSA FromPublicBytes: nil modulus or exponent');
  Result := FromPublic(TBN.FromBytes(AModulus, ABigEndian),
    TBN.FromBytes(AExponent, ABigEndian));
end;


function TRSAKey.PublicEncrypt(const M: TBN): TBN;
begin
  Result := M.ModPow(FE, FN);
end;

function TRSAKey.PrivateDecrypt(const C: TBN): TBN;
begin
  if FD = nil then
    raise Exception.Create('RSA: private key not available');
  Result := C.ModPow(FD, FN);
end;

function TRSAKey.VerifyPKCS1v15(const Signature: TBN; const Hash: TBytes; const Oid: string): Boolean;
var
  m: TBN;
  modLen: LongInt;
  i: LongInt;
  digest: TBytes;
begin
  modLen := (FN.BitLength + 7) div 8;
  m := Signature.ModPow(FE, FN);
  digest := PKCS1v15Decode(m, Oid, modLen);
  if digest = nil then
  begin
    Result := False;
    Exit;
  end;
  Result := (Length(digest) = Length(Hash));
  if Result then
    for i := 0 to Length(Hash) - 1 do
      if digest[i] <> Hash[i] then
        Result := False;
end;

function TRSAKey.VerifyPSS(const Signature: TBN; const Hash: TBytes; SaltLen: Integer = -1): Boolean;
var
  m: TBN;
  modLen: LongInt;
begin
  modLen := (FN.BitLength + 7) div 8;
  m := Signature.ModPow(FE, FN);
  Result := PSSVerify(m, Hash, '1.2.840.113549.1.1.11', SaltLen, modLen);
end;

function TRSAKey.EncryptPKCS1v15(const AMessage: TBytes): TBN;
var
  modLen: LongInt;
  em: TBN;
begin
  modLen := (FN.BitLength + 7) div 8;
  em := PKCS1v15EncryptEncode(AMessage, modLen);
  try
    Result := PublicEncrypt(em);
  finally
    em.Free;
  end;
end;

function TRSAKey.DecryptPKCS1v15(const ACiphertext: TBN): TBytes;
var
  modLen: LongInt;
  m: TBN;
begin
  modLen := (FN.BitLength + 7) div 8;
  m := PrivateDecrypt(ACiphertext);
  try
    Result := PKCS1v15DecryptDecode(m, modLen);
  finally
    m.Free;
  end;
end;

function TRSAKey.EncryptPKCS1v15Bytes(const AMessage: TBytes): TBytes;
var
  modLen: LongInt;
  c: TBN;
begin
  modLen := (FN.BitLength + 7) div 8;
  c := EncryptPKCS1v15(AMessage);
  try
    Result := I2OSP(c, modLen);
  finally
    c.Free;
  end;
end;

function TRSAKey.DecryptPKCS1v15Bytes(const ACiphertext: TBytes): TBytes;
var
  modLen: LongInt;
  c, m: TBN;
begin
  modLen := (FN.BitLength + 7) div 8;
  if Length(ACiphertext) <> modLen then
    raise Exception.Create('PKCS1v15 decrypt: ciphertext length mismatch');
  c := TBN.FromBytes(ACiphertext, True);
  try
    m := PrivateDecrypt(c);
    try
      Result := PKCS1v15DecryptDecode(m, modLen);
    finally
      m.Free;
    end;
  finally
    c.Free;
  end;
end;

procedure TRSAKey.Generate(Bits: LongInt);
var
  primeP, primeQ, modN, phiVal, expE, expD: TBN;
  halfBits: LongInt;
  candidate: TBN;
  loop: LongInt;
begin
  halfBits := Bits div 2;
  expE := TBN.FromQWord(65537);

  loop := 0;
  repeat
    candidate := TBN.RandomBits(halfBits, @RandomByteGen);
    candidate := candidate.OrBits(TBN.FromQWord(1).ShiftLeft(halfBits - 1));
    candidate := candidate.OrBits(TBN.FromQWord(1));
    Inc(loop);
    if loop > 10000 then
      raise Exception.Create('RSA Generate: cannot find p');
  until IsPrime(candidate, 20);
  primeP := candidate;

  loop := 0;
  repeat
    candidate := TBN.RandomBits(halfBits, @RandomByteGen);
    candidate := candidate.OrBits(TBN.FromQWord(1).ShiftLeft(halfBits - 1));
    candidate := candidate.OrBits(TBN.FromQWord(1));
    Inc(loop);
    if loop > 10000 then
      raise Exception.Create('RSA Generate: cannot find q');
  until IsPrime(candidate, 20);
  primeQ := candidate;

  if primeP.Equal(primeQ) then
    raise Exception.Create('RSA Generate: p == q');

  modN := primeP.Mul(primeQ);
  phiVal := primeP.Sub(TBN.FromQWord(1)).Mul(primeQ.Sub(TBN.FromQWord(1)));
  expD := expE.ModInverse(phiVal);
  if expD = nil then
    raise Exception.Create('RSA Generate: e not invertible');

  FN := modN;
  FE := expE;
  FD := expD;
  FP := primeP;
  FQ := primeQ;
end;

function TRSAKey.SignPKCS1v15(const Hash: TBytes; const Oid: string): TBN;
var
  modLen: LongInt;
  em: TBN;
begin
  modLen := (FN.BitLength + 7) div 8;
  em := PKCS1v15Encode(Hash, Oid, modLen);
  Result := PrivateDecrypt(em);
end;

function TRSAKey.SignPSS(const Hash: TBytes; SaltLen: Integer = -1): TBN;
var
  modLen: LongInt;
  em: TBN;
begin
  modLen := (FN.BitLength + 7) div 8;
  em := PSSEncode(Hash, '1.2.840.113549.1.1.11', SaltLen, modLen);
  Result := PrivateDecrypt(em);
end;

end.
