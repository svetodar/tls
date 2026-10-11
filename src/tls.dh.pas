{ SPDX-License-Identifier: Apache-2.0 }
unit tls.dh;

{ Diffie–Hellman in finite fields (DHE) in pure Pascal.
  TDHKey: P (prime modulus), G (generator), Priv, Pub.
  Generate: Priv = random(2..P-2), Pub = G^Priv mod P.
  ComputeSecret: PeerPub^Priv mod P (shared secret).
  Built-in RFC 3526 groups (2048, 3072 bits, G = 2).
  Implementation for task 08 (docs/tasks/08-dh.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, tls.bn, tls.rand;

type
  TDHKey = class
  public
    P: TBN;
    G: TBN;
    Priv: TBN;
    Pub: TBN;
    constructor Create;
    destructor Destroy; override;

    { Ephemeral key generation: Priv = random(2..P-2), Pub = G^Priv mod P. }
    procedure Generate;

    { Computing the shared secret: PeerPub^Priv mod P. }
    function ComputeSecret(const PeerPub: TBN): TBN;

    { Basic PeerPub check: 2 <= PeerPub <= P-2. }
    function ValidatePeerPub(const PeerPub: TBN): Boolean;

    { Full check: basic + PeerPub^q mod P = 1, where q = (P-1)/2. }
    function ValidatePeerPubFull(const PeerPub: TBN): Boolean;
  end;

{ Built-in RFC 3526 groups (G = 2). }
function Group2048: TDHKey;
function Group3072: TDHKey;

implementation

{--- TDHKey ---}

constructor TDHKey.Create;
begin
  P := nil;
  G := nil;
  Priv := nil;
  Pub := nil;
end;

destructor TDHKey.Destroy;
begin
  if P <> nil then P.Free;
  if G <> nil then G.Free;
  if Priv <> nil then Priv.Free;
  if Pub <> nil then Pub.Free;
  inherited;
end;

procedure TDHKey.Generate;
var
  Pm2: TBN;
begin
  if (P = nil) or (G = nil) then
    raise EBNError.Create('TDHKey.Generate: P and G not set');
  if Priv <> nil then Priv.Free;
  if Pub <> nil then Pub.Free;
  { Priv = random(2..P-2) }
  Pm2 := P.Sub(TBN.FromQWord(2));
  try
    Priv := TBN.RandomBits(P.BitLength, @RandomByteGen);
    Priv := Priv.Modulo(Pm2);
    Priv := Priv.Add(TBN.FromQWord(2));
  finally
    Pm2.Free;
  end;
  { Pub = G^Priv mod P }
  Pub := G.ModPow(Priv, P);
end;

function TDHKey.ComputeSecret(const PeerPub: TBN): TBN;
begin
  if (P = nil) or (Priv = nil) then
    raise EBNError.Create('TDHKey.ComputeSecret: key not generated');
  Result := PeerPub.ModPow(Priv, P);
end;

function TDHKey.ValidatePeerPub(const PeerPub: TBN): Boolean;
var
  Two, Pm2: TBN;
begin
  if P = nil then
    Exit(False);
  Two := TBN.FromQWord(2);
  Pm2 := P.Sub(Two);
  try
    Result := (PeerPub.Compare(Two) >= 0)
        and (PeerPub.Compare(Pm2) <= 0);
  finally
    Two.Free;
    Pm2.Free;
  end;
end;

function TDHKey.ValidatePeerPubFull(const PeerPub: TBN): Boolean;
var
  Q, Check: TBN;
begin
  if not ValidatePeerPub(PeerPub) then
    Exit(False);
  { q = (P-1)/2 }
  Q := P.Sub(TBN.FromQWord(1));
  Q := Q.ShiftRight(1);
  { PeerPub^q mod P must be 1 }
  Check := PeerPub.ModPow(Q, P);
  Result := Check.Equal(TBN.FromQWord(1));
  Q.Free;
  Check.Free;
end;

{--- RFC 3526 groups ---}

function Group2048: TDHKey;
begin
  Result := TDHKey.Create;
  Result.P := TBN.CreateFromHex(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
    '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF');
  Result.G := TBN.CreateFromQWord(2);
end;

function Group3072: TDHKey;
begin
  Result := TDHKey.Create;
  Result.P := TBN.CreateFromHex(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
    '3995497CEA956AE515D2261898FA051015728E5A8AACAA68AD33170D04507A33' +
    'A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' +
    'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864' +
    'D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E2' +
    '08E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF');
  Result.G := TBN.CreateFromQWord(2);
end;

end.
