unit tls.hmac;

{ HMAC (RFC 2104) on SHA-256/384/512.
  Incremental (Update/Final) and one-shot (HMAC256/HMAC384/HMAC512). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, tls.sha2;

type
  THashKind = (hkSHA256, hkSHA384, hkSHA512);

  THMAC = class
  private
    FKind: THashKind;
    FInner: TSHA2Base;
    FOuter: TSHA2Base;
    FOutLen: Integer;
  public
    constructor Create(AKind: THashKind; const Key: TBytes);
    destructor Destroy; override;
    procedure Update(const Data: TBytes);
    procedure Update(const Data: TBytes; Offset, Count: Integer);
    procedure Final(var Mac: TBytes);
    class function Compute(AKind: THashKind; const Key, Data: TBytes): TBytes;
  end;

function HMAC256(const Key, Data: TBytes): TBytes;
function HMAC384(const Key, Data: TBytes): TBytes;
function HMAC512(const Key, Data: TBytes): TBytes;

implementation

constructor THMAC.Create(AKind: THashKind; const Key: TBytes);
var
  Block: Integer;
  K: TBytes;
  InnerPad, OuterPad: TBytes;
  i: Integer;
begin
  FKind := AKind;
  case AKind of
    hkSHA256:
      begin
        FInner := TSHA256.Create;
        FOuter := TSHA256.Create;
        Block := 64;
        FOutLen := 32;
      end;
    hkSHA384:
      begin
        FInner := TSHA384.Create;
        FOuter := TSHA384.Create;
        Block := 128;
        FOutLen := 48;
      end;
  else
      begin
        FInner := TSHA512.Create;
        FOuter := TSHA512.Create;
        Block := 128;
        FOutLen := 64;
      end;
  end;
  K := Key;
  if Length(K) > Block then
  begin
    case AKind of
      hkSHA256: K := SHA256(K);
      hkSHA384: K := SHA384(K);
    else
      K := SHA512(K);
    end;
  end;
  SetLength(InnerPad, Block);
  SetLength(OuterPad, Block);
  for i := 0 to Block - 1 do
  begin
    if i < Length(K) then
    begin
      InnerPad[i] := K[i] xor $36;
      OuterPad[i] := K[i] xor $5C;
    end
    else
    begin
      InnerPad[i] := $36;
      OuterPad[i] := $5C;
    end;
  end;
  FInner.Update(InnerPad);
  FOuter.Update(OuterPad);
end;

destructor THMAC.Destroy;
begin
  FInner.Free;
  FOuter.Free;
  inherited Destroy;
end;

procedure THMAC.Update(const Data: TBytes);
begin
  Update(Data, 0, Length(Data));
end;

procedure THMAC.Update(const Data: TBytes; Offset, Count: Integer);
begin
  FInner.Update(Data, Offset, Count);
end;

procedure THMAC.Final(var Mac: TBytes);
var
  InnerDigest: TBytes;
begin
  FInner.Final(InnerDigest);
  FOuter.Update(InnerDigest);
  FOuter.Final(Mac);
end;

class function THMAC.Compute(AKind: THashKind; const Key, Data: TBytes): TBytes;
var
  H: THMAC;
begin
  H := Create(AKind, Key);
  try
    H.Update(Data);
    H.Final(Result);
  finally
    H.Free;
  end;
end;

function HMAC256(const Key, Data: TBytes): TBytes;
begin
  Result := THMAC.Compute(hkSHA256, Key, Data);
end;

function HMAC384(const Key, Data: TBytes): TBytes;
begin
  Result := THMAC.Compute(hkSHA384, Key, Data);
end;

function HMAC512(const Key, Data: TBytes): TBytes;
begin
  Result := THMAC.Compute(hkSHA512, Key, Data);
end;

end.
