{ SPDX-License-Identifier: Apache-2.0 }
unit test_aes;
{AES-128/192/256 tests: ECB/CBC (FIPS-197, SP 800-38A),
  GCM (SP 800-38D) and error handling.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TAESTests = class(TTestCase)
  published
    procedure TestECB128;
    procedure TestECB192;
    procedure TestECB256;
    procedure TestCBC128NIST;
    procedure TestCBC192NIST;
    procedure TestCBC256NIST;
    procedure TestCBCPaddingRoundTrip;
    procedure TestGCMVector1;
    procedure TestGCMVector2;
    procedure TestGCMVector3;
    procedure TestGCMVector4AAD;
    procedure TestGCMVector5IV64;
    procedure TestGCMRoundTrip;
    procedure TestGCMTagRejected;
    procedure TestGCMAADMismatch;
    procedure TestInvalidKey;
  end;

implementation

uses
  SysUtils, tls.aes, tls.sha2;

const
  PT4 =
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52ef' +
    'f69f2445df4f9b17ad2b417be66c3710';

procedure TAESTests.TestECB128;
var
  Key, InBlock, CT: TBytes;
begin
  Key := HexToBytes('000102030405060708090a0b0c0d0e0f');
  InBlock := HexToBytes('00112233445566778899aabbccddeeff');
  CT := AESBlockEncrypt(Key, InBlock);
  AssertEquals('AES-128 ECB', '69c4e0d86a7b0430d8cdb78070b4c55a',
    BytesToHex(CT));
  AssertEquals('AES-128 ECB decrypt', BytesToHex(InBlock),
    BytesToHex(AESBlockDecrypt(Key, CT)));
end;

procedure TAESTests.TestECB192;
var
  Key, InBlock, CT: TBytes;
begin
  Key := HexToBytes('000102030405060708090a0b0c0d0e0f1011121314151617');
  InBlock := HexToBytes('00112233445566778899aabbccddeeff');
  CT := AESBlockEncrypt(Key, InBlock);
  AssertEquals('AES-192 ECB', 'dda97ca4864cdfe06eaf70a0ec0d7191',
    BytesToHex(CT));
  AssertEquals('AES-192 ECB decrypt', BytesToHex(InBlock),
    BytesToHex(AESBlockDecrypt(Key, CT)));
end;

procedure TAESTests.TestECB256;
var
  Key, InBlock, CT: TBytes;
begin
  Key := HexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  InBlock := HexToBytes('00112233445566778899aabbccddeeff');
  CT := AESBlockEncrypt(Key, InBlock);
  AssertEquals('AES-256 ECB', '8ea2b7ca516745bfeafc49904b496089',
    BytesToHex(CT));
  AssertEquals('AES-256 ECB decrypt', BytesToHex(InBlock),
    BytesToHex(AESBlockDecrypt(Key, CT)));
end;

procedure TAESTests.TestCBC128NIST;
var
  Key, IV, PT, CT, RT: TBytes;
begin
  Key := HexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
  IV := HexToBytes('000102030405060708090a0b0c0d0e0f');
  PT := HexToBytes(PT4);
  CT := AESCBCEncryptNoPad(Key, IV, PT);
  AssertEquals('AES-128-CBC',
    '7649abac8119b246cee98e9b12e9197d' +
    '5086cb9b507219ee95db113a917678b2' +
    '73bed6b8e3c1743b7116e69e22229516' +
    '3ff1caa1681fac09120eca307586e1a7',
    BytesToHex(CT));
  RT := AESCBCDecryptNoPad(Key, IV, CT);
  AssertEquals('AES-128-CBC decrypt', PT4, BytesToHex(RT));
end;

procedure TAESTests.TestCBC192NIST;
var
  Key, IV, PT, CT: TBytes;
begin
  Key := HexToBytes('8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b');
  IV := HexToBytes('000102030405060708090a0b0c0d0e0f');
  PT := HexToBytes(PT4);
  CT := AESCBCEncryptNoPad(Key, IV, PT);
  AssertEquals('AES-192-CBC',
    '4f021db243bc633d7178183a9fa071e8' +
    'b4d9ada9ad7dedf4e5e738763f69145a' +
    '571b242012fb7ae07fa9baac3df102e0' +
    '08b0e27988598881d920a9e64f5615cd',
    BytesToHex(CT));
end;

procedure TAESTests.TestCBC256NIST;
var
  Key, IV, PT, CT: TBytes;
begin
  Key := HexToBytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
  IV := HexToBytes('000102030405060708090a0b0c0d0e0f');
  PT := HexToBytes(PT4);
  CT := AESCBCEncryptNoPad(Key, IV, PT);
  AssertEquals('AES-256-CBC',
    'f58c4c04d6e5f1ba779eabfb5f7bfbd6' +
    '9cfc4e967edb808d679f777bc6702c7d' +
    '39f23369a9d9bacfa530e26304231461' +
    'b2eb05e2c39be9fcda6c19078c6a9d1b',
    BytesToHex(CT));
end;

procedure TAESTests.TestCBCPaddingRoundTrip;
var
  Key, IV, PT, CT, RT: TBytes;
  n, i: Integer;
begin
  Key := HexToBytes('2b7e151628aed2a6abf7158809cf4f3c');
  IV := HexToBytes('000102030405060708090a0b0c0d0e0f');
  for n := 0 to 47 do
  begin
    SetLength(PT, n);
    for i := 0 to n - 1 do
      PT[i] := Byte(i * 7 + 1);
    CT := AESCBCEncrypt(Key, IV, PT);
    AssertEquals(Format('CBC padding len %d', [n]), ((n div 16) + 1) * 16,
      Length(CT));
    RT := AESCBCDecrypt(Key, IV, CT);
    AssertEquals(Format('CBC padding round-trip %d', [n]), n, Length(RT));
    if n > 0 then
      AssertTrue(Format('CBC padding bytes %d', [n]),
        CompareMem(@PT[0], @RT[0], n));
  end;
end;

procedure TAESTests.TestGCMVector1;
var
  Key, IV, AAD, P, C, T: TBytes;
begin
  Key := HexToBytes('00000000000000000000000000000000');
  IV := HexToBytes('000000000000000000000000');
  AAD := nil;
  P := nil;
  AESGCMEncrypt(Key, IV, AAD, P, C, T);
  AssertEquals('GCM TC1 C', '', BytesToHex(C));
  AssertEquals('GCM TC1 T', '58e2fccefa7e3061367f1d57a4e7455a',
    BytesToHex(T));
  AssertTrue('GCM TC1 decrypt', AESGCMDecrypt(Key, IV, AAD, C, T, P));
end;

procedure TAESTests.TestGCMVector2;
var
  Key, IV, AAD, P, C, T: TBytes;
begin
  Key := HexToBytes('00000000000000000000000000000000');
  IV := HexToBytes('000000000000000000000000');
  AAD := nil;
  P := HexToBytes('00000000000000000000000000000000');
  AESGCMEncrypt(Key, IV, AAD, P, C, T);
  AssertEquals('GCM TC2 C', '0388dace60b6a392f328c2b971b2fe78',
    BytesToHex(C));
  AssertEquals('GCM TC2 T', 'ab6e47d42cec13bdf53a67b21257bddf',
    BytesToHex(T));
end;

procedure TAESTests.TestGCMVector3;
var
  Key, IV, AAD, P, C, T, PT: TBytes;
begin
  Key := HexToBytes('feffe9928665731c6d6a8f9467308308');
  IV := HexToBytes('cafebabefacedbaddecaf888');
  AAD := nil;
  P := HexToBytes('d9313225f88406e5a55909c5aff5269a' +
                  '86a7a9531534f7da2e4c303d8a318a72' +
                  '1c3c0c95956809532fcf0e2449a6b525' +
                  'b16aedf5aa0de657ba637b391aafd255');
  AESGCMEncrypt(Key, IV, AAD, P, C, T);
  AssertEquals('GCM TC3 C',
    '42831ec2217774244b7221b784d0d49c' +
    'e3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa05' +
    '1ba30b396a0aac973d58e091473f5985',
    BytesToHex(C));
  AssertEquals('GCM TC3 T', '4d5c2af327cd64a62cf35abd2ba6fab4',
    BytesToHex(T));
  AssertTrue('GCM TC3 decrypt', AESGCMDecrypt(Key, IV, AAD, C, T, PT));
  AssertEquals('GCM TC3 PT', BytesToHex(P), BytesToHex(PT));
end;

procedure TAESTests.TestGCMVector4AAD;
var
  Key, IV, AAD, P, C, T: TBytes;
begin
  Key := HexToBytes('feffe9928665731c6d6a8f9467308308');
  IV := HexToBytes('cafebabefacedbaddecaf888');
  AAD := HexToBytes('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  P := HexToBytes('d9313225f88406e5a55909c5aff5269a' +
                  '86a7a9531534f7da2e4c303d8a318a72' +
                  '1c3c0c95956809532fcf0e2449a6b525' +
                  'b16aedf5aa0de657ba637b39');
  AESGCMEncrypt(Key, IV, AAD, P, C, T);
  AssertEquals('GCM TC4 C',
    '42831ec2217774244b7221b784d0d49c' +
    'e3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa05' +
    '1ba30b396a0aac973d58e091',
    BytesToHex(C));
  AssertEquals('GCM TC4 T', '5bc94fbc3221a5db94fae95ae7121a47',
    BytesToHex(T));
end;

procedure TAESTests.TestGCMVector5IV64;
var
  Key, IV, AAD, P, C, T: TBytes;
begin
  Key := HexToBytes('feffe9928665731c6d6a8f9467308308');
  IV := HexToBytes('cafebabefacedbad');
  AAD := HexToBytes('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  P := HexToBytes('d9313225f88406e5a55909c5aff5269a' +
                  '86a7a9531534f7da2e4c303d8a318a72' +
                  '1c3c0c95956809532fcf0e2449a6b525' +
                  'b16aedf5aa0de657ba637b39');
  AESGCMEncrypt(Key, IV, AAD, P, C, T);
  AssertEquals('GCM TC5 C',
    '61353b4c2806934a777ff51fa22a4755' +
    '699b2a714fcdc6f83766e5f97b6c7423' +
    '73806900e49f24b22b097544d4896b42' +
    '4989b5e1ebac0f07c23f4598',
    BytesToHex(C));
  AssertEquals('GCM TC5 T', '3612d2e79e3b0785561be14aaca2fccb',
    BytesToHex(T));
end;

procedure TAESTests.TestGCMRoundTrip;
var
  Key, IV, AAD, P, C, T, RT: TBytes;
  n, i: Integer;
begin
  Key := HexToBytes('feffe9928665731c6d6a8f9467308308');
  IV := HexToBytes('cafebabefacedbaddecaf888');
  AAD := HexToBytes('0102030405');
  for n := 0 to 40 do
  begin
    SetLength(P, n);
    for i := 0 to n - 1 do
      P[i] := Byte(n * 3 + i);
    AESGCMEncrypt(Key, IV, AAD, P, C, T);
    AssertEquals(Format('GCM C len %d', [n]), n, Length(C));
    AssertTrue(Format('GCM decrypt %d', [n]), AESGCMDecrypt(Key, IV, AAD, C, T, RT));
    AssertEquals(Format('GCM PT len %d', [n]), n, Length(RT));
    if n > 0 then
      AssertTrue(Format('GCM PT bytes %d', [n]),
        CompareMem(@P[0], @RT[0], n));
  end;
end;

procedure TAESTests.TestGCMTagRejected;
var
  Key, IV, AAD, P, C, T, RT: TBytes;
begin
  Key := HexToBytes('feffe9928665731c6d6a8f9467308308');
  IV := HexToBytes('cafebabefacedbaddecaf888');
  AAD := nil;
  P := HexToBytes('d9313225f88406e5a55909c5aff5269a');
  AESGCMEncrypt(Key, IV, AAD, P, C, T);
  T[0] := T[0] xor $01;
  AssertTrue('forged tag rejected',
    not AESGCMDecrypt(Key, IV, AAD, C, T, RT));
end;

procedure TAESTests.TestGCMAADMismatch;
var
  Key, IV, AAD, P, C, T, RT: TBytes;
begin
  Key := HexToBytes('feffe9928665731c6d6a8f9467308308');
  IV := HexToBytes('cafebabefacedbaddecaf888');
  AAD := HexToBytes('0102030405');
  P := HexToBytes('d9313225f88406e5a55909c5aff5269a');
  AESGCMEncrypt(Key, IV, AAD, P, C, T);
  AAD[0] := AAD[0] xor $01;
  AssertTrue('modified AAD rejected',
    not AESGCMDecrypt(Key, IV, AAD, C, T, RT));
end;

procedure TAESTests.TestInvalidKey;
var
  ok: Boolean;
begin
  ok := False;
  try
    AESBlockEncrypt(HexToBytes('00112233'), HexToBytes('00112233445566778899aabbccddeeff'));
  except
    on E: EAESError do
      ok := True;
  end;
  AssertTrue('invalid key size', ok);
end;

initialization
  RegisterTest(TAESTests);

end.
