unit tls.rand;

{ CSPRNG: HMAC-DRBG (NIST SP 800-90A) on SHA-256.
  Entropy: /dev/urandom (Unix) or BCryptGenRandom (Windows);
  fallback — clock/counter/address, mixed with SHA-256.
  Thread-safe global generator; class THmacDRBG can be
  used separately (including with a fixed seed in tests).

  Implementation for task 02 (docs/tasks/02-rand.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, SyncObjs;

type
  { HMAC-DRBG on SHA-256: deterministic generator with reseed. }
  THmacDRBG = class
  private
    FK, FV: TBytes;
    FReseedCounter: Integer;
    procedure Update(const Provided: TBytes);
    procedure ResetState;
  public
    constructor Create(const Seed: TBytes);
    destructor Destroy; override;
    { Mix state with fresh entropy. }
    procedure Reseed(const Seed: TBytes);
    { Generate Count random bytes. }
    procedure Generate(out Buf: TBytes; Count: LongInt); overload;
    function Generate(Count: LongInt): TBytes; overload;
    { Generation counter since last reseed (for reseed policy). }
    property ReseedCounter: Integer read FReseedCounter;
    function NeedsReseed: Boolean;
  end;

{ Operating system entropy (Count bytes). }
function SystemEntropy(Count: LongInt): TBytes;

{ Global CSPRNG. }
procedure RandomBytes(out Buf: TBytes; Count: LongInt); overload;
function RandomBytes(Count: LongInt): TBytes; overload;
function RandomQWord: QWord;
{ Count "random bits": rounded up to a byte, high bits of
  the last byte cleared (result < 2^Count). }
function RandomBits(Count: LongInt): TBytes;
{ Compatible with TByteGen from tls.bn: TBN.RandomBits(n, @RandomByteGen). }
function RandomByteGen(Count: LongInt): TBytes;
{ Reinitialize the global generator with fresh entropy. }
procedure Reseed;

implementation

uses
  tls.hmac, tls.sha2;

const
  DRBG_OUTLEN = 32;               { SHA-256 }
  DRBG_RESEED_INTERVAL = 1 shl 20; { generations until mandatory reseed }

var
  GDRBG: THmacDRBG;
  GLock: TCriticalSection;
  GFallbackCounter: QWord = 0;

{--- Helpers ---}

function ZeroBytes(n: LongInt): TBytes;
begin
  SetLength(Result, n);
  if n > 0 then
    FillChar(Result[0], n, 0);
end;

function OneBytes(n: LongInt): TBytes;
begin
  SetLength(Result, n);
  if n > 0 then
    FillChar(Result[0], n, 1);
end;

function ConcatBytes(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

function BufWith(const Prefix: TBytes; B: Byte): TBytes;
begin
  SetLength(Result, Length(Prefix) + 1);
  if Length(Prefix) > 0 then
    Move(Prefix[0], Result[0], Length(Prefix));
  Result[Length(Prefix)] := B;
end;

{ Fallback entropy source: clock + counter + address + Random,
  all mixed with SHA-256. Used only if the OS source
  is unavailable (abnormal situation). }
procedure FallbackEntropy(var Buf: TBytes);
var
  seed: TBytes;
  block: TBytes;
  i, off, n: LongInt;
  w: QWord;
begin
  n := Length(Buf);
  if n = 0 then
    Exit;
  SetLength(seed, 32);
  w := QWord(Trunc(Now * 86400000.0));
  Move(w, seed[0], 8);
  w := QWord(PtrUInt(@Buf));
  Move(w, seed[8], 8);
  Inc(GFallbackCounter, QWord(6364136223846793005));
  w := GFallbackCounter;
  Move(w, seed[16], 8);
  w := QWord(Random(MaxInt)) or (QWord(Random(MaxInt)) shl 32);
  Move(w, seed[24], 8);

  off := 0;
  while off < n do
  begin
    block := SHA256(seed);
    for i := 0 to Length(block) - 1 do
    begin
      if off >= n then
        Break;
      Buf[off] := block[i];
      Inc(off);
    end;
    { Change seed for the next block. }
    seed[0] := seed[0] xor Byte(off);
    seed[31] := seed[31] + Byte(off * 7 + 1);
  end;
end;

{--- OS entropy ---}

{$IFDEF WINDOWS}
type
  TBCryptGenRandom = function(hAlgorithm: Pointer; pbBuffer: PByte;
    cbBuffer: LongWord; dwFlags: LongWord): LongInt; stdcall;

function SystemEntropy(Count: LongInt): TBytes;
var
  Lib: THandle;
  Fn: TBCryptGenRandom;
begin
  SetLength(Result, Count);
  if Count = 0 then
    Exit;
  Lib := LoadLibrary('bcrypt.dll');
  if Lib <> 0 then
  begin
    Fn := TBCryptGenRandom(GetProcAddress(Lib, 'BCryptGenRandom'));
    { BCRYPT_USE_SYSTEM_PREFERRED_RNG = 2, algorithm = nil. }
    if Assigned(Fn) and (Fn(nil, @Result[0], LongWord(Count), 2) = 0) then
    begin
      FreeLibrary(Lib);
      Exit;
    end;
    FreeLibrary(Lib);
  end;
  FallbackEntropy(Result);
end;
{$ELSE}
function SystemEntropy(Count: LongInt): TBytes;
var
  F: TFileStream;
begin
  SetLength(Result, Count);
  if Count = 0 then
    Exit;
  try
    F := TFileStream.Create('/dev/urandom', fmOpenRead or fmShareDenyNone);
    try
      F.ReadBuffer(Result[0], Count);
    finally
      F.Free;
    end;
  except
    FallbackEntropy(Result);
  end;
end;
{$ENDIF}

{--- THmacDRBG ---}

procedure THmacDRBG.ResetState;
begin
  FK := ZeroBytes(DRBG_OUTLEN);
  FV := OneBytes(DRBG_OUTLEN);
end;

procedure THmacDRBG.Update(const Provided: TBytes);
var
  Tmp: TBytes;
begin
  { K = HMAC(K, V || 0x00 || provided_data). }
  Tmp := BufWith(FV, 0);
  if Length(Provided) > 0 then
    Tmp := ConcatBytes(Tmp, Provided);
  FK := HMAC256(FK, Tmp);

  { V = HMAC(K, V). }
  FV := HMAC256(FK, FV);

  if Length(Provided) > 0 then
  begin
    { K = HMAC(K, V || 0x01 || provided_data). }
    Tmp := BufWith(FV, 1);
    Tmp := ConcatBytes(Tmp, Provided);
    FK := HMAC256(FK, Tmp);

    { V = HMAC(K, V). }
    FV := HMAC256(FK, FV);
  end;
end;

constructor THmacDRBG.Create(const Seed: TBytes);
begin
  inherited Create;
  ResetState;
  Update(Seed);
  FReseedCounter := 1;
end;

destructor THmacDRBG.Destroy;
begin
  if Length(FK) > 0 then
    FillChar(FK[0], Length(FK), 0);
  if Length(FV) > 0 then
    FillChar(FV[0], Length(FV), 0);
  inherited Destroy;
end;

procedure THmacDRBG.Reseed(const Seed: TBytes);
begin
  Update(Seed);
  FReseedCounter := 1;
end;

procedure THmacDRBG.Generate(out Buf: TBytes; Count: LongInt);
var
  off, n: LongInt;
begin
  SetLength(Buf, Count);
  off := 0;
  while off < Count do
  begin
    FV := HMAC256(FK, FV);
    n := DRBG_OUTLEN;
    if n > Count - off then
      n := Count - off;
    Move(FV[0], Buf[off], n);
    Inc(off, n);
  end;
  Update(nil);
  Inc(FReseedCounter);
end;

function THmacDRBG.Generate(Count: LongInt): TBytes;
begin
  Generate(Result, Count);
end;

function THmacDRBG.NeedsReseed: Boolean;
begin
  Result := FReseedCounter > DRBG_RESEED_INTERVAL;
end;

{--- Global CSPRNG ---}

procedure EnsureInit;
begin
  if GDRBG = nil then
    GDRBG := THmacDRBG.Create(SystemEntropy(48));
end;

procedure RandomBytes(out Buf: TBytes; Count: LongInt);
begin
  GLock.Acquire;
  try
    EnsureInit;
    if GDRBG.NeedsReseed then
      GDRBG.Reseed(SystemEntropy(48));
    GDRBG.Generate(Buf, Count);
  finally
    GLock.Release;
  end;
end;

function RandomBytes(Count: LongInt): TBytes;
begin
  RandomBytes(Result, Count);
end;

function RandomQWord: QWord;
var
  B: TBytes;
  i: Integer;
begin
  RandomBytes(B, 8);
  Result := 0;
  for i := 7 downto 0 do
    Result := (Result shl 8) or QWord(B[i]);
end;

function RandomBits(Count: LongInt): TBytes;
var
  extra, n: LongInt;
begin
  if Count < 0 then
    raise EArgumentOutOfRangeException.Create('RandomBits: Count < 0');
  if Count = 0 then
    Exit(nil);
  n := (Count + 7) div 8;
  SetLength(Result, n);
  RandomBytes(Result, n);
  extra := n * 8 - Count;
  if extra > 0 then
    Result[n - 1] := Result[n - 1] and Byte((1 shl (8 - extra)) - 1);
end;

function RandomByteGen(Count: LongInt): TBytes;
begin
  if Count <= 0 then
    Exit(nil);
  RandomBytes(Result, Count);
end;

procedure Reseed;
begin
  GLock.Acquire;
  try
    EnsureInit;
    GDRBG.Reseed(SystemEntropy(48));
  finally
    GLock.Release;
  end;
end;

initialization
  GLock := TCriticalSection.Create;

finalization
  if GDRBG <> nil then
    GDRBG.Free;
  GLock.Free;

end.
