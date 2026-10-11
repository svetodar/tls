unit tls.prf;

{ TLS 1.2 PRF (RFC 5246, section 5): P_hash based on HMAC-SHA256/384/512.
  PRF(secret, label, seed) = P_hash(secret, label + seed), where the choice
  of hash function is determined by the cipher suite (SHA-256 or SHA-384).

  Also here — derivation of TLS 1.2 key material (RFC 5246, 8.1):
    master_secret  = PRF(pre_master_secret, "master secret",
                         ClientHello.random + ServerHello.random)[0..47]
    extended_master_secret = PRF(pre_master_secret, "extended master secret",
                         session_hash)[0..47]        (RFC 7627)
    key_block      = PRF(master_secret, "key expansion",
                         server_random + client_random)  (order server+client!)

  Implementation for task 12 (docs/tasks/12-tls12.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, tls.sha2, tls.hmac;

const
  { The master secret length in TLS 1.2 is always 48 bytes (RFC 5246, 8.1). }
  TLS12MasterSecretLen = 48;

type
  { Splitting the TLS 1.2 key block into components (RFC 5246, 6.3).
    For AEAD suites (AES-GCM, ChaCha20-Poly1305) MacLen = 0 and
    Client/ServerWriteMAC are empty. }
  TTLS12KeyBlock = record
    ClientWriteMAC: TBytes;
    ServerWriteMAC: TBytes;
    ClientWriteKey: TBytes;
    ServerWriteKey: TBytes;
    ClientWriteIV: TBytes;
    ServerWriteIV: TBytes;
  end;

{ P_hash(secret, seed) from RFC 5246: expands the secret to Count bytes.
    A(0) = seed
    A(i) = HMAC_hash(secret, A(i-1))
    P_hash = HMAC_hash(secret, A(1)+seed)
             || HMAC_hash(secret, A(2)+seed) || ... (truncated to Count) }
function PHash(AKind: THashKind; const Secret, Seed: TBytes;
  Count: Integer): TBytes;

{ TLS 1.2 PRF: PRF(secret, label, seed) = P_hash(secret, label + seed).
  ALabel — ASCII label ('master secret', 'key expansion',
  'client finished', 'server finished', etc.). }
function TLS12PRF(AKind: THashKind; const Secret: TBytes;
  const ALabel: AnsiString; const Seed: TBytes; Count: Integer): TBytes; overload;
function TLS12PRF(AKind: THashKind; const Secret: TBytes;
  const ALabel: TBytes; const Seed: TBytes; Count: Integer): TBytes; overload;

{ Wrappers for the typical cipher suite PRF hashes. }
function TLS12PRFSHA256(const Secret: TBytes; const ALabel: AnsiString;
  const Seed: TBytes; Count: Integer): TBytes;
function TLS12PRFSHA384(const Secret: TBytes; const ALabel: AnsiString;
  const Seed: TBytes; Count: Integer): TBytes;

{ master_secret = PRF(pre_master_secret, "master secret",
                      ClientRandom + ServerRandom)  (always 48 bytes). }
function TLS12MasterSecret(AKind: THashKind;
  const PreMasterSecret, ClientRandom, ServerRandom: TBytes): TBytes;

{ extended master secret (RFC 7627, EMS):
    PRF(pre_master_secret, "extended master secret", session_hash)  (48 bytes). }
function TLS12ExtendedMasterSecret(AKind: THashKind;
  const PreMasterSecret, SessionHash: TBytes): TBytes;

{ Key block length = 2*(MacLen + KeyLen + IVLen). }
function TLS12KeyBlockLength(MacLen, KeyLen, IVLen: Integer): Integer;

{ Raw TLS 1.2 key block:
    PRF(master_secret, "key expansion", ServerRandom + ClientRandom). }
function TLS12KeyBlockRaw(AKind: THashKind;
  const MasterSecret, ServerRandom, ClientRandom: TBytes;
  Count: Integer): TBytes;

{ Parsing the raw key block into six components in RFC 5246 order:
    client_write_MAC, server_write_MAC, client_write_key,
    server_write_key, client_write_IV, server_write_IV. }
function TLS12SplitKeyBlock(const KeyBlock: TBytes;
  MacLen, KeyLen, IVLen: Integer): TTLS12KeyBlock;

{ Computes and parses the key block at once. }
function TLS12KeyBlock(AKind: THashKind;
  const MasterSecret, ServerRandom, ClientRandom: TBytes;
  MacLen, KeyLen, IVLen: Integer): TTLS12KeyBlock;

implementation

{ Character string -> bytes (TLS labels are always ASCII). }
function StrToBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

{ Concatenation of two byte buffers. }
function ConcatBuf(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

procedure CheckLen(const AName: AnsiString; AValue: Integer);
begin
  if AValue < 0 then
    raise Exception.CreateFmt('TLS 1.2 PRF: negative value %s', [AName]);
end;

function PHash(AKind: THashKind; const Secret, Seed: TBytes;
  Count: Integer): TBytes;
var
  A, Part, Block: TBytes;
  Pos, ToCopy: Integer;
begin
  if Count < 0 then
    raise Exception.Create('PHash: negative length');
  SetLength(Result, Count);
  if Count = 0 then
    Exit;

  A := THMAC.Compute(AKind, Secret, Seed); { A(1) }
  Pos := 0;
  while Pos < Count do
  begin
    { Block = HMAC(secret, A(i) + seed) }
    SetLength(Part, Length(A) + Length(Seed));
    if Length(A) > 0 then
      Move(A[0], Part[0], Length(A));
    if Length(Seed) > 0 then
      Move(Seed[0], Part[Length(A)], Length(Seed));
    Block := THMAC.Compute(AKind, Secret, Part);

    ToCopy := Count - Pos;
    if ToCopy > Length(Block) then
      ToCopy := Length(Block);
    Move(Block[0], Result[Pos], ToCopy);
    Inc(Pos, ToCopy);

    if Pos < Count then
      A := THMAC.Compute(AKind, Secret, A); { A(i+1) }
  end;
end;

function TLS12PRF(AKind: THashKind; const Secret: TBytes;
  const ALabel: TBytes; const Seed: TBytes; Count: Integer): TBytes;
var
  SeedWithLabel: TBytes;
begin
  SetLength(SeedWithLabel, Length(ALabel) + Length(Seed));
  if Length(ALabel) > 0 then
    Move(ALabel[0], SeedWithLabel[0], Length(ALabel));
  if Length(Seed) > 0 then
    Move(Seed[0], SeedWithLabel[Length(ALabel)], Length(Seed));
  Result := PHash(AKind, Secret, SeedWithLabel, Count);
end;

function TLS12PRF(AKind: THashKind; const Secret: TBytes;
  const ALabel: AnsiString; const Seed: TBytes; Count: Integer): TBytes;
begin
  Result := TLS12PRF(AKind, Secret, StrToBytes(ALabel), Seed, Count);
end;

function TLS12PRFSHA256(const Secret: TBytes; const ALabel: AnsiString;
  const Seed: TBytes; Count: Integer): TBytes;
begin
  Result := TLS12PRF(hkSHA256, Secret, ALabel, Seed, Count);
end;

function TLS12PRFSHA384(const Secret: TBytes; const ALabel: AnsiString;
  const Seed: TBytes; Count: Integer): TBytes;
begin
  Result := TLS12PRF(hkSHA384, Secret, ALabel, Seed, Count);
end;

function TLS12MasterSecret(AKind: THashKind;
  const PreMasterSecret, ClientRandom, ServerRandom: TBytes): TBytes;
begin
  Result := TLS12PRF(AKind, PreMasterSecret, 'master secret',
    ConcatBuf(ClientRandom, ServerRandom), TLS12MasterSecretLen);
end;

function TLS12ExtendedMasterSecret(AKind: THashKind;
  const PreMasterSecret, SessionHash: TBytes): TBytes;
begin
  Result := TLS12PRF(AKind, PreMasterSecret, 'extended master secret',
    SessionHash, TLS12MasterSecretLen);
end;

function TLS12KeyBlockLength(MacLen, KeyLen, IVLen: Integer): Integer;
begin
  CheckLen('MacLen', MacLen);
  CheckLen('KeyLen', KeyLen);
  CheckLen('IVLen', IVLen);
  Result := 2 * (MacLen + KeyLen + IVLen);
end;

function TLS12KeyBlockRaw(AKind: THashKind;
  const MasterSecret, ServerRandom, ClientRandom: TBytes;
  Count: Integer): TBytes;
begin
  { Note: in key expansion the order is server_random + client_random,
    the reverse of the order in master secret. }
  Result := TLS12PRF(AKind, MasterSecret, 'key expansion',
    ConcatBuf(ServerRandom, ClientRandom), Count);
end;

function TLS12SplitKeyBlock(const KeyBlock: TBytes;
  MacLen, KeyLen, IVLen: Integer): TTLS12KeyBlock;
var
  P: Integer;

  function Take(N: Integer): TBytes;
  begin
    SetLength(Result, N);
    if N > 0 then
    begin
      Move(KeyBlock[P], Result[0], N);
      Inc(P, N);
    end;
  end;

begin
  CheckLen('MacLen', MacLen);
  CheckLen('KeyLen', KeyLen);
  CheckLen('IVLen', IVLen);
  if Length(KeyBlock) < TLS12KeyBlockLength(MacLen, KeyLen, IVLen) then
    raise Exception.CreateFmt(
      'TLS 1.2 key block: not enough data (%d < %d)', 
      [Length(KeyBlock), TLS12KeyBlockLength(MacLen, KeyLen, IVLen)]);
  P := 0;
  Result.ClientWriteMAC := Take(MacLen);
  Result.ServerWriteMAC := Take(MacLen);
  Result.ClientWriteKey := Take(KeyLen);
  Result.ServerWriteKey := Take(KeyLen);
  Result.ClientWriteIV := Take(IVLen);
  Result.ServerWriteIV := Take(IVLen);
end;

function TLS12KeyBlock(AKind: THashKind;
  const MasterSecret, ServerRandom, ClientRandom: TBytes;
  MacLen, KeyLen, IVLen: Integer): TTLS12KeyBlock;
begin
  Result := TLS12SplitKeyBlock(
    TLS12KeyBlockRaw(AKind, MasterSecret, ServerRandom, ClientRandom,
      TLS12KeyBlockLength(MacLen, KeyLen, IVLen)),
    MacLen, KeyLen, IVLen);
end;

end.
