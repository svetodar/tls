unit test_chacha;
{ Tests for ChaCha20, Poly1305 and AEAD ChaCha20-Poly1305 (RFC 8439). }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TChaChaTests = class(TTestCase)
  published
    procedure TestChaCha20BlockRFC8439;
    procedure TestChaCha20EncryptRFC8439;
    procedure TestPoly1305RFC8439;
    procedure TestAeadRFC8439;
    procedure TestAeadRoundTrip;
    procedure TestAeadTamperTag;
    procedure TestAeadTamperAAD;
    procedure TestAeadEmpty;
    procedure TestPoly1305PartialBlocks;
  end;

implementation

uses
  SysUtils, tls.chacha20, tls.sha2;

function S(const X: string): TBytes;
begin
  SetLength(Result, Length(X));
  if Length(X) > 0 then
    Move(X[1], Result[0], Length(X));
end;

procedure TChaChaTests.TestChaCha20BlockRFC8439;
var
  Key, Nonce, Block: TBytes;
begin
  Key := HexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  Nonce := HexToBytes('000000090000004a00000000');
  Block := ChaCha20Block(Key, Nonce, 1);
  AssertEquals('ChaCha20 block §2.3.2',
    '10f1e7e4d13b5915500fdd1fa32071c4' +
    'c7d1f4c733c068030422aa9ac3d46c4e' +
    'd2826446079faa0914c2d705d98b02a2' +
    'b5129cd1de164eb9cbd083e8a2503c4e',
    BytesToHex(Block));
end;

procedure TChaChaTests.TestChaCha20EncryptRFC8439;
var
  Key, Nonce, PT, CT: TBytes;
begin
  Key := HexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  Nonce := HexToBytes('000000000000004a00000000');
  PT := S('Ladies and Gentlemen of the class of ''99: If I could offer you only ' +
          'one tip for the future, sunscreen would be it.');
  CT := ChaCha20Xor(Key, Nonce, 1, PT);
  AssertEquals('ChaCha20 encrypt §2.4.2',
    '6e2e359a2568f98041ba0728dd0d6981' +
    'e97e7aec1d4360c20a27afccfd9fae0b' +
    'f91b65c5524733ab8f593dabcd62b357' +
    '1639d624e65152ab8f530c359f0861d8' +
    '07ca0dbf500d6a6156a38e088a22b65e' +
    '52bc514d16ccf806818ce91ab7793736' +
    '5af90bbf74a35be6b40b8eedf2785e42' +
    '874d',
    BytesToHex(CT));
  { Reversibility. }
  AssertEquals('ChaCha20 decrypt', BytesToHex(PT),
    BytesToHex(ChaCha20Xor(Key, Nonce, 1, CT)));
end;

procedure TChaChaTests.TestPoly1305RFC8439;
var
  Key, Msg, Tag: TBytes;
begin
  Key := HexToBytes('85d6be7857556d337f4452fe42d506a8' +
                    '0103808afb0db2fd4abff6af4149f51b');
  Msg := S('Cryptographic Forum Research Group');
  Tag := Poly1305(Key, Msg);
  AssertEquals('Poly1305 §2.5.2', 'a8061dc1305136c6c22b8baf0c0127a9',
    BytesToHex(Tag));
end;

procedure TChaChaTests.TestAeadRFC8439;
var
  Key, Nonce, AAD, PT, CT, Tag, RT: TBytes;
begin
  Key := HexToBytes('808182838485868788898a8b8c8d8e8f' +
                    '909192939495969798999a9b9c9d9e9f');
  Nonce := HexToBytes('070000004041424344454647');
  AAD := HexToBytes('50515253c0c1c2c3c4c5c6c7');
  PT := S('Ladies and Gentlemen of the class of ''99: If I could offer you only ' +
          'one tip for the future, sunscreen would be it.');
  ChaCha20Poly1305Encrypt(Key, Nonce, AAD, PT, CT, Tag);
  AssertEquals('AEAD §2.8.2 C',
    'd31a8d34648e60db7b86afbc53ef7ec2' +
    'a4aded51296e08fea9e2b5a736ee62d6' +
    '3dbea45e8ca9671282fafb69da92728b' +
    '1a71de0a9e060b2905d6a5b67ecd3b36' +
    '92ddbd7f2d778b8c9803aee328091b58' +
    'fab324e4fad675945585808b4831d7bc' +
    '3ff4def08e4b7a9de576d26586cec64b' +
    '6116',
    BytesToHex(CT));
  AssertEquals('AEAD §2.8.2 tag', '1ae10b594f09e26a7e902ecbd0600691',
    BytesToHex(Tag));
  AssertTrue('AEAD decrypt', ChaCha20Poly1305Decrypt(Key, Nonce, AAD, CT, Tag, RT));
  AssertEquals('AEAD PT', BytesToHex(PT), BytesToHex(RT));
end;

procedure TChaChaTests.TestAeadRoundTrip;
var
  Key, Nonce, AAD, PT, CT, Tag, RT: TBytes;
  n, i: Integer;
begin
  Key := HexToBytes('808182838485868788898a8b8c8d8e8f' +
                    '909192939495969798999a9b9c9d9e9f');
  Nonce := HexToBytes('070000004041424344454647');
  AAD := HexToBytes('aabbccddeeff');
  for n := 0 to 40 do
  begin
    SetLength(PT, n);
    for i := 0 to n - 1 do
      PT[i] := Byte(n * 5 + i);
    ChaCha20Poly1305Encrypt(Key, Nonce, AAD, PT, CT, Tag);
    AssertEquals(Format('AEAD C len %d', [n]), n, Length(CT));
    AssertEquals(Format('AEAD tag len %d', [n]), 16, Length(Tag));
    AssertTrue(Format('AEAD decrypt %d', [n]),
      ChaCha20Poly1305Decrypt(Key, Nonce, AAD, CT, Tag, RT));
    if n > 0 then
      AssertTrue(Format('AEAD bytes %d', [n]), CompareMem(@PT[0], @RT[0], n));
  end;
end;

procedure TChaChaTests.TestAeadTamperTag;
var
  Key, Nonce, AAD, PT, CT, Tag, RT: TBytes;
begin
  Key := HexToBytes('808182838485868788898a8b8c8d8e8f' +
                    '909192939495969798999a9b9c9d9e9f');
  Nonce := HexToBytes('070000004041424344454647');
  AAD := HexToBytes('aabbccddeeff');
  PT := S('secret message');
  ChaCha20Poly1305Encrypt(Key, Nonce, AAD, PT, CT, Tag);
  Tag[15] := Tag[15] xor $80;
  AssertTrue('forged tag rejected',
    not ChaCha20Poly1305Decrypt(Key, Nonce, AAD, CT, Tag, RT));
end;

procedure TChaChaTests.TestAeadTamperAAD;
var
  Key, Nonce, AAD, PT, CT, Tag, RT: TBytes;
begin
  Key := HexToBytes('808182838485868788898a8b8c8d8e8f' +
                    '909192939495969798999a9b9c9d9e9f');
  Nonce := HexToBytes('070000004041424344454647');
  AAD := HexToBytes('aabbccddeeff');
  PT := S('secret message');
  ChaCha20Poly1305Encrypt(Key, Nonce, AAD, PT, CT, Tag);
  AAD[0] := AAD[0] xor $01;
  AssertTrue('modified AAD rejected',
    not ChaCha20Poly1305Decrypt(Key, Nonce, AAD, CT, Tag, RT));
end;

procedure TChaChaTests.TestAeadEmpty;
var
  Key, Nonce, CT, Tag, RT: TBytes;
begin
  Key := HexToBytes('808182838485868788898a8b8c8d8e8f' +
                    '909192939495969798999a9b9c9d9e9f');
  Nonce := HexToBytes('070000004041424344454647');
  ChaCha20Poly1305Encrypt(Key, Nonce, nil, nil, CT, Tag);
  AssertEquals('empty C', 0, Length(CT));
  AssertEquals('empty tag', 16, Length(Tag));
  AssertTrue('empty decrypt', ChaCha20Poly1305Decrypt(Key, Nonce, nil, CT, Tag, RT));
  AssertEquals('empty PT', 0, Length(RT));
end;

procedure TChaChaTests.TestPoly1305PartialBlocks;
var
  Key, Msg, Tag: TBytes;
  i, n: Integer;
  P: TPoly1305;
begin
  { Same result when message is fed in chunks. }
  Key := HexToBytes('85d6be7857556d337f4452fe42d506a8' +
                    '0103808afb0db2fd4abff6af4149f51b');
  Msg := S('Cryptographic Forum Research Group');
  P := TPoly1305.Create(Key);
  try
    n := 0;
    while n < Length(Msg) do
    begin
      for i := 0 to 4 do
      begin
        if n >= Length(Msg) then
          Break;
        P.Update(Copy(Msg, n, 1));
        Inc(n);
      end;
    end;
    Tag := P.Final;
  finally
    P.Free;
  end;
  AssertEquals('Poly1305 in chunks', 'a8061dc1305136c6c22b8baf0c0127a9',
    BytesToHex(Tag));
end;

initialization
  RegisterTest(TChaChaTests);

end.
