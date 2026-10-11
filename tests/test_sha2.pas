unit test_sha2;
{ Tests for SHA-256/384/512 and HMAC (FIPS 180-4, RFC 4231). }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TSHA2Tests = class(TTestCase)
  published
    procedure TestSHA256Empty;
    procedure TestSHA256Abc;
    procedure TestSHA256TwoBlocks;
    procedure TestSHA256MillionA;
    procedure TestSHA384Empty;
    procedure TestSHA384Abc;
    procedure TestSHA384TwoBlocks;
    procedure TestSHA384MillionA;
    procedure TestSHA512Empty;
    procedure TestSHA512Abc;
    procedure TestSHA512TwoBlocks;
    procedure TestSHA512MillionA;
    procedure TestIncrementalEqualsOneShot;
    procedure TestHMAC256RFC4231;
    procedure TestHexRoundTrip;
  end;

implementation

uses
  SysUtils, tls.sha2, tls.hmac;

{--- SHA-256 ---}

procedure TSHA2Tests.TestSHA256Empty;
begin
  AssertEquals('SHA-256("")',
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    BytesToHex(SHA256Str('')));
end;

procedure TSHA2Tests.TestSHA256Abc;
begin
  AssertEquals('SHA-256("abc")',
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    BytesToHex(SHA256Str('abc')));
end;

procedure TSHA2Tests.TestSHA256TwoBlocks;
begin
  AssertEquals('SHA-256(56B)',
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1',
    BytesToHex(SHA256Str('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')));
end;

procedure TSHA2Tests.TestSHA256MillionA;
var
  Data: TBytes;
  i: Integer;
begin
  SetLength(Data, 1000000);
  for i := 0 to 999999 do
    Data[i] := Ord('a');
  AssertEquals('SHA-256(1M "a")',
    'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
    BytesToHex(SHA256(Data)));
end;

{--- SHA-384 ---}

procedure TSHA2Tests.TestSHA384Empty;
begin
  AssertEquals('SHA-384("")',
    '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b',
    BytesToHex(SHA384Str('')));
end;

procedure TSHA2Tests.TestSHA384Abc;
begin
  AssertEquals('SHA-384("abc")',
    'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7',
    BytesToHex(SHA384Str('abc')));
end;

procedure TSHA2Tests.TestSHA384TwoBlocks;
begin
  AssertEquals('SHA-384(56B)',
    '3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b',
    BytesToHex(SHA384Str('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')));
end;

procedure TSHA2Tests.TestSHA384MillionA;
var
  Data: TBytes;
  i: Integer;
begin
  SetLength(Data, 1000000);
  for i := 0 to 999999 do
    Data[i] := Ord('a');
  AssertEquals('SHA-384(1M "a")',
    '9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985',
    BytesToHex(SHA384(Data)));
end;

{--- SHA-512 ---}

procedure TSHA2Tests.TestSHA512Empty;
begin
  AssertEquals('SHA-512("")',
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
    BytesToHex(SHA512Str('')));
end;

procedure TSHA2Tests.TestSHA512Abc;
begin
  AssertEquals('SHA-512("abc")',
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    BytesToHex(SHA512Str('abc')));
end;

procedure TSHA2Tests.TestSHA512TwoBlocks;
begin
  AssertEquals('SHA-512(56B)',
    '204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445',
    BytesToHex(SHA512Str('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')));
end;

procedure TSHA2Tests.TestSHA512MillionA;
var
  Data: TBytes;
  i: Integer;
begin
  SetLength(Data, 1000000);
  for i := 0 to 999999 do
    Data[i] := Ord('a');
  AssertEquals('SHA-512(1M "a")',
    'e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b',
    BytesToHex(SHA512(Data)));
end;

{--- Incremental == one-shot ---}

procedure TSHA2Tests.TestIncrementalEqualsOneShot;
var
  Data: TBytes;
  DigestOne, DigestInc: TBytes;
  H: TSHA256;
  Chunk: TBytes;
  i, off: Integer;
  const
    ChunkSize = 7; { arbitrary chunk size }
begin
  { Generate 200 bytes of pseudorandom data. }
  SetLength(Data, 200);
  for i := 0 to 199 do
    Data[i] := (i * 37 + 13) and $FF;

  { One-shot. }
  DigestOne := SHA256(Data);

  { Incremental with 7-byte chunks. }
  H := TSHA256.Create;
  try
    off := 0;
    while off < Length(Data) do
    begin
      Chunk := Copy(Data, off, ChunkSize);
      H.Update(Chunk);
      Inc(off, ChunkSize);
    end;
    H.Final(DigestInc);
  finally
    H.Free;
  end;

  AssertEquals('SHA-256 incremental == one-shot',
    BytesToHex(DigestOne), BytesToHex(DigestInc));
end;

{--- HMAC-SHA256 (RFC 4231) ---}

procedure TSHA2Tests.TestHMAC256RFC4231;
var
  Key, Data, Mac: TBytes;
  i: Integer;
begin
  { Case 1: key = 0x0b * 20, data = "Hi There" }
  SetLength(Key, 20);
  for i := 0 to 19 do Key[i] := $0B;
  Data := TEncoding.UTF8.GetBytes('Hi There');
  Mac := HMAC256(Key, Data);
  AssertEquals('HMAC-SHA256 case 1',
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
    BytesToHex(Mac));

  { Case 2: key = "Jefe", data = "what do ya want for nothing?" }
  Key := TEncoding.UTF8.GetBytes('Jefe');
  Data := TEncoding.UTF8.GetBytes('what do ya want for nothing?');
  Mac := HMAC256(Key, Data);
  AssertEquals('HMAC-SHA256 case 2',
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
    BytesToHex(Mac));

  { Case 3: key = 0xaa * 20, data = 0xdd * 50 }
  SetLength(Key, 20);
  for i := 0 to 19 do Key[i] := $AA;
  SetLength(Data, 50);
  for i := 0 to 49 do Data[i] := $DD;
  Mac := HMAC256(Key, Data);
  AssertEquals('HMAC-SHA256 case 3',
    '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe',
    BytesToHex(Mac));

  { Case 4: key = 0x01..0x13 (19 bytes), data = 0xcd * 50 }
  SetLength(Key, 19);
  for i := 0 to 18 do Key[i] := i + 1;
  SetLength(Data, 50);
  for i := 0 to 49 do Data[i] := $CD;
  Mac := HMAC256(Key, Data);
  AssertEquals('HMAC-SHA256 case 4',
    '0066117c8516f20a5a92c5ab6e6a2e58f93097a37b606ba0a87f2ebc0c8c7674',
    BytesToHex(Mac));

  { Case 6: key = 0xaa * 131, data = "Test Using Larger Than Block-Size Key - Hash Key First" }
  SetLength(Key, 131);
  for i := 0 to 130 do Key[i] := $AA;
  Data := TEncoding.UTF8.GetBytes('Test Using Larger Than Block-Size Key - Hash Key First');
  Mac := HMAC256(Key, Data);
  AssertEquals('HMAC-SHA256 case 6',
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
    BytesToHex(Mac));

  { Case 7: key = 0x0c * 131, data = "Test Using Larger Than Block-Size Key and Data Longer Than Key" }
  SetLength(Key, 131);
  for i := 0 to 130 do Key[i] := $0C;
  Data := TEncoding.UTF8.GetBytes('Test Using Larger Than Block-Size Key and Data Longer Than Key');
  Mac := HMAC256(Key, Data);
  AssertEquals('HMAC-SHA256 case 7',
    '4c8ff76c615741ef9720fe86101f04d7e39fa9c95f5c7d24e64219f97d93b01e',
    BytesToHex(Mac));
end;

{--- HexToBytes / BytesToHex ---}

procedure TSHA2Tests.TestHexRoundTrip;
var
  B, RT: TBytes;
  S: string;
  i: Integer;
begin
  { Empty array. }
  SetLength(B, 0);
  S := BytesToHex(B);
  AssertEquals('empty hex', '', S);
  AssertEquals('empty hex->bytes', 0, Length(HexToBytes(S)));

  { All 256 byte values. }
  SetLength(B, 256);
  for i := 0 to 255 do
    B[i] := i;
  S := BytesToHex(B);
  AssertEquals('hex length', 512, Length(S));
  AssertEquals('hex[0..1]', '00', S[1] + S[2]);
  AssertEquals('hex[510..511]', 'ff', S[511] + S[512]);

  { Reversibility. }
  { Reversibility. FPC 3.2.2: = for dynamic arrays compares only
    length, so we compare byte-by-byte via CompareMem. }
  RT := HexToBytes(S);
  AssertEquals('round-trip len', Length(B), Length(RT));
  AssertTrue('round-trip', CompareMem(@B[0], @RT[0], Length(B)));

  { Uppercase. }
  S := 'AABBCC';
  B := HexToBytes(S);
  AssertEquals('hex upper len', 3, Length(B));
  AssertEquals('hex upper [0]', $AA, Integer(B[0]));
  AssertEquals('hex upper [1]', $BB, Integer(B[1]));
  AssertEquals('hex upper [2]', $CC, Integer(B[2]));
end;

initialization
  RegisterTest(TSHA2Tests);

end.
