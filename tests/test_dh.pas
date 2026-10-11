{ SPDX-License-Identifier: Apache-2.0 }
unit test_dh;

{Tests DH (tls.dh): symmetry of ComputeSecret, vectors, RFC 3526 groups.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TDHTests = class(TTestCase)
  published
    procedure TestSymmetrySmallPrime;
    procedure TestKnownVectorSmallPrime;
    procedure TestValidatePeerPub;
    procedure TestValidatePeerPubFull;
    procedure TestGroup2048;
    procedure TestGroup3072;
    procedure TestGenerateProducesValidPub;
  end;

implementation

uses
  SysUtils, tls.dh, tls.bn;

{Symmetry: Alice and Bob generate keys, both compute shared secret —
  results must match. Use small prime P=23, G=5.}
procedure TDHTests.TestSymmetrySmallPrime;
var
  A, B: TDHKey;
  S1, S2: TBN;
begin
  A := TDHKey.Create;
  B := TDHKey.Create;
  try
    A.P := TBN.CreateFromQWord(23);
    A.G := TBN.CreateFromQWord(5);
    B.P := TBN.CreateFromQWord(23);
    B.G := TBN.CreateFromQWord(5);
    A.Generate;
    B.Generate;

    S1 := A.ComputeSecret(B.Pub);
    S2 := B.ComputeSecret(A.Pub);
    Check(S1.Equal(S2), 'Shared secrets must be equal');
    Check(S1.Compare(TBN.FromQWord(0)) > 0, 'Secret must be > 0');
  finally
    S1.Free;
    S2.Free;
    A.Free;
    B.Free;
  end;
end;

{Known vector: P=23, G=5, privA=6 -> pubA=8, privB=15 -> pubB=19,
  shared = 8^15 mod 23 = 19^6 mod 23 = 2.}
procedure TDHTests.TestKnownVectorSmallPrime;
var
  A: TDHKey;
  PeerPub: TBN;
  Secret: TBN;
begin
  A := TDHKey.Create;
  try
    A.P := TBN.CreateFromQWord(23);
    A.G := TBN.CreateFromQWord(5);
    {Set priv manually: priv=6 -> pub = 5^6 mod 23 = 8}
    A.Priv := TBN.CreateFromQWord(6);
    A.Pub := A.G.ModPow(A.Priv, A.P);
    Check(A.Pub.Equal(TBN.CreateFromQWord(8)),
      'pub should be 8, got ' + A.Pub.ToString);

    { peer pub = 19 (privB=15) }
    PeerPub := TBN.CreateFromQWord(19);
    Secret := A.ComputeSecret(PeerPub);
    Check(Secret.Equal(TBN.CreateFromQWord(2)),
      'shared secret should be 2, got ' + Secret.ToString);
    Secret.Free;
  finally
    A.Free;
  end;
end;

{ValidatePeerPub: 1 and P-1 out of range, 2..P-2 in range.}
procedure TDHTests.TestValidatePeerPub;
var
  K: TDHKey;
  One, Pm1, Two, Pm2: TBN;
begin
  K := TDHKey.Create;
  try
    K.P := TBN.CreateFromQWord(23);
    K.G := TBN.CreateFromQWord(5);
    One := TBN.CreateFromQWord(1);
    Pm1 := TBN.CreateFromQWord(22);
    Two := TBN.CreateFromQWord(2);
    Pm2 := TBN.CreateFromQWord(21);
    Check(not K.ValidatePeerPub(One), '1 is out of range');
    Check(not K.ValidatePeerPub(Pm1), 'P-1 is out of range');
    Check(K.ValidatePeerPub(Two), '2 is in range');
    Check(K.ValidatePeerPub(Pm2), 'P-2 is in range');
  finally
    One.Free;
    Pm1.Free;
    Two.Free;
    Pm2.Free;
    K.Free;
  end;
end;

{ValidatePeerPubFull: for P=23, q=11.
  5^11 mod 23 = 22 (not 1) -> fails full check.
  But 8^11 mod 23: 8^11 = 8589934592 mod 23 = 1 -> passes.}
procedure TDHTests.TestValidatePeerPubFull;
var
  K: TDHKey;
  Eight, Five: TBN;
begin
  K := TDHKey.Create;
  try
    K.P := TBN.CreateFromQWord(23);
    K.G := TBN.CreateFromQWord(5);
    Eight := TBN.CreateFromQWord(8);
    Five := TBN.CreateFromQWord(5);
    { 8 = 5^6 mod 23, 8^11 mod 23 = 1 -> full check passes}
    Check(K.ValidatePeerPubFull(Eight), '8 should pass full validation');
    { 5 = 5^1, 5^11 mod 23 = 22 != 1 -> fails}
    Check(not K.ValidatePeerPubFull(Five), '5 should fail full validation');
  finally
    Eight.Free;
    Five.Free;
    K.Free;
  end;
end;

{ Group 2048: P has 2048 bits, G=2, Generate yields valid pub.}
procedure TDHTests.TestGroup2048;
var
  K: TDHKey;
begin
  K := Group2048;
  try
    Check(K.P.BitLength = 2048, 'P must be 2048 bits');
    Check(K.G.Equal(TBN.CreateFromQWord(2)), 'G must be 2');
    K.Generate;
    Check(K.Pub <> nil, 'Pub must be generated');
    Check(K.ValidatePeerPub(K.Pub), 'Pub must be in [2, P-2]');
  finally
    K.Free;
  end;
end;

{ Group 3072: P has 3072 bits, G=2.}
procedure TDHTests.TestGroup3072;
var
  K: TDHKey;
begin
  K := Group3072;
  try
    Check(K.P.BitLength = 3072, 'P must be 3072 bits');
    Check(K.G.Equal(TBN.CreateFromQWord(2)), 'G must be 2');
    K.Generate;
    Check(K.Pub <> nil, 'Pub must be generated');
    Check(K.ValidatePeerPub(K.Pub), 'Pub must be in [2, P-2]');
  finally
    K.Free;
  end;
end;

{ Generate with RFC 3526 group 2048: pub is valid, two keys yield
  the same secret. }
procedure TDHTests.TestGenerateProducesValidPub;
var
  A, B: TDHKey;
  S1, S2: TBN;
begin
  A := Group2048;
  B := Group2048;
  try
    A.Generate;
    B.Generate;
    Check(A.ValidatePeerPub(A.Pub), 'A.Pub valid');
    Check(B.ValidatePeerPub(B.Pub), 'B.Pub valid');
    S1 := A.ComputeSecret(B.Pub);
    S2 := B.ComputeSecret(A.Pub);
    Check(S1.Equal(S2), '2048-bit shared secrets must match');
  finally
    S1.Free;
    S2.Free;
    A.Free;
    B.Free;
  end;
end;

initialization
  RegisterTest(TDHTests);

end.
