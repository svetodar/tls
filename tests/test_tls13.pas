{ SPDX-License-Identifier: Apache-2.0 }
unit test_tls13;
{TLS 1.3 tests (RFC 8446, milestone F): HKDF (RFC 5869), HKDF-Expand-Label
  and the key schedule, key_share on P-256/P-384, ClientHello/ServerHello
  and the other handshake parsers, the 1.3 record layer, Finished and the
  TTLS13Client handshake over the mock/real transport.

  Tests are grouped by area and use only published vectors (RFC 5869,
  RFC 8446 examples) or an independent reference (openssl / python3); the
  end-to-end test talks to `openssl s_server -tls1_3` and is skipped when
  the openssl CLI is unavailable.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TTLS13Tests = class(TTestCase)
  published
    { --- constants and capability checks --- }
    procedure TestHashLengths;
    procedure TestDefaultCipherSuites;
    procedure TestCipherSuiteHashKind;
    procedure TestDefaultSupportedGroups;
    procedure TestSignatureSchemeSupport;

    { --- HKDF (RFC 5869) and HKDF-Expand-Label (RFC 8446, 7.1) --- }
    procedure TestHKDFExtractRFC5869;
    procedure TestHKDFExtractEmptySaltIsHashLenZeros;
    procedure TestHKDFExpandRFC5869;
    procedure TestHkdfLabelSerialization;
    procedure TestHKDFExpandLabelEqualsExpand;
    procedure TestHKDFExpandLabelVectors;
    procedure TestHKDFBoundsAndErrors;

    { --- key schedule (RFC 8446, 7.1) --- }
    procedure TestKeyScheduleRFC8448;
    procedure TestKeySchedulePSKEarlySecret;
    procedure TestKeyScheduleSHA384Reference;
    procedure TestKeyScheduleAggregateConsistency;
    procedure TestKeyScheduleUnsupportedSuite;

    { --- record layer (RFC 8446, 5) --- }
    procedure TestRecordNonceAndAAD;
    procedure TestRecordNonceAndAADBounds;
    procedure TestInnerPlaintextEncodeDecode;
    procedure TestInnerPlaintextPaddingAndLength;
    procedure TestInnerPlaintextNegative;
    procedure TestRecordProtectRFC8448ClientFinished;
    procedure TestRecordProtectRFC8448ApplicationData;
    procedure TestRecordPublishedSuiteVectors;
    procedure TestRecordRoundTripAllSuites;
    procedure TestRecordNegative;
    procedure TestLegacyChangeCipherSpec;

    { --- handshake messages: ClientHello structure, the ServerHello /
      EncryptedExtensions / Certificate parsers, CertificateVerify content
      and signature verification, and the explicit rejections
      (HelloRetryRequest, unknown suite, malformed bodies, bad signature) --- }
    procedure TestClientHelloStructure;
    procedure TestServerHelloParser;
    procedure TestServerHelloHelloRetryRequest;
    procedure TestServerHelloUnknownSuite;
    procedure TestServerHelloGrammarRejections;
    procedure TestEncryptedExtensionsParser;
    procedure TestCertificateParser;
    procedure TestTLS13CertificateChain;
    procedure TestCertificateVerifyContent;
    procedure TestCertificateVerifySignatures;
  end;

implementation

uses
  SysUtils, Classes, tls.tls12, tls.tls13, tls.hmac, tls.sha2, tls.x509,
  tls.certstore;

{ ==================================================================== }
{ Helper functions                                                      }
{ ==================================================================== }

function W16(AValue: Word): TBytes;
begin
  Result := nil;
  SetLength(Result, 2);
  Result[0] := Byte((AValue shr 8) and $FF);
  Result[1] := Byte(AValue and $FF);
end;

function W24(AValue: LongWord): TBytes;
begin
  Result := nil;
  SetLength(Result, 3);
  Result[0] := Byte((AValue shr 16) and $FF);
  Result[1] := Byte((AValue shr 8) and $FF);
  Result[2] := Byte(AValue and $FF);
end;

function B1(AValue: Byte): TBytes;
begin
  Result := nil;
  SetLength(Result, 1);
  Result[0] := AValue;
end;

function Cat(const A, B: TBytes): TBytes;
begin
  Result := nil;
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

function Cat3(const A, B, C: TBytes): TBytes;
begin
  Result := Cat(Cat(A, B), C);
end;

function StrBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  Result := nil;
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

function ReadU16(const AData: TBytes; AOffset: Integer): Word;
begin
  Result := (Word(AData[AOffset]) shl 8) or Word(AData[AOffset + 1]);
end;

{ One extension record, for assembling handshake messages by hand. }
function SimpleExt(AExtType: Word; const AData: TBytes): TTLSExtension;
begin
  Result.ExtType := AExtType;
  Result.Data := AData;
end;

{ ServerHello body (RFC 8446, 4.1.3) built field by field, so a test can
  flip a single field and check the parser's rejection. }
function BuildServerHelloBodyRaw(const ARandom, ASessionIDEcho: TBytes;
  ASuite: Word; ACompression: Byte; const AExtensions: TBytes): TBytes;
begin
  Result := Cat(W16(TLS13LegacyVersion), ARandom);
  Result := Cat(Result, B1(Length(ASessionIDEcho)));
  Result := Cat(Result, ASessionIDEcho);
  Result := Cat(Result, W16(ASuite));
  Result := Cat(Result, B1(ACompression));
  Result := Cat(Result, AExtensions);
end;

{ Well-formed ServerHello body with the two mandatory extensions: the
  supported_versions selection and the server key_share. }
function BuildServerHelloBody(const ARandom, ASessionIDEcho: TBytes;
  ASuite: Word; AGroup: Word; const AKeyExchange: TBytes): TBytes;
var
  Exts: TTLSExtensions;
begin
  SetLength(Exts, 2);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Exts[1] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(AGroup, AKeyExchange));
  Result := BuildServerHelloBodyRaw(ARandom, ASessionIDEcho, ASuite, 0,
    EncodeTLSExtensions(Exts));
end;

{ The HRR sentinel random of RFC 8446, 4.1.3. }
function HelloRetryRequestRandom: TBytes;
var
  i: Integer;
begin
  Result := nil;
  SetLength(Result, 32);
  for i := 0 to 31 do
    Result[i] := TLS13HelloRetryRequestRandom[i];
end;

{ Fixture loader: tries the working directory first, then the executable's
  directory (bin/../tests/fixtures), as the other test units do. Returns
  nil when the file is missing. }
function LoadFixtureBytes(const AName: string): TBytes;
var
  fs: TFileStream;
  path: string;
begin
  Result := nil;
  path := 'tests' + PathDelim + 'fixtures' + PathDelim + AName;
  if not FileExists(path) then
    path := ExtractFilePath(ParamStr(0)) + '..' + PathDelim + 'tests' +
      PathDelim + 'fixtures' + PathDelim + AName;
  if not FileExists(path) then
    Exit;
  fs := TFileStream.Create(path, fmOpenRead);
  try
    SetLength(Result, fs.Size);
    if fs.Size > 0 then
      fs.ReadBuffer(Result[0], fs.Size);
  finally
    fs.Free;
  end;
end;

{ ==================================================================== }
{ Constants and capability checks                                       }
{ ==================================================================== }

procedure TTLS13Tests.TestHashLengths;
begin
  AssertEquals('SHA-256 output length', 32, TLS13HashLen(hkSHA256));
  AssertEquals('SHA-384 output length', 48, TLS13HashLen(hkSHA384));
  AssertEquals('SHA-512 output length', 64, TLS13HashLen(hkSHA512));
end;

procedure TTLS13Tests.TestDefaultCipherSuites;
var
  Suites: TTLSCipherSuites;
begin
  Suites := TLS13DefaultCipherSuites;
  AssertEquals('three default cipher suites', 3, Length(Suites));
  AssertEquals('suite[0]', TLS13CipherAES128GCMSHA256, Suites[0]);
  AssertEquals('suite[1]', TLS13CipherAES256GCMSHA384, Suites[1]);
  AssertEquals('suite[2]', TLS13CipherChaCha20Poly1305SHA256, Suites[2]);
  AssertTrue('0x1301 supported', TLS13CipherSuiteSupported(Suites[0]));
  AssertTrue('0x1302 supported', TLS13CipherSuiteSupported(Suites[1]));
  AssertTrue('0x1303 supported', TLS13CipherSuiteSupported(Suites[2]));
  AssertFalse('TLS 1.2 suite rejected', TLS13CipherSuiteSupported($C02F));
end;

procedure TTLS13Tests.TestCipherSuiteHashKind;
begin
  AssertEquals('0x1301 -> SHA-256', Ord(hkSHA256),
    Ord(TLS13CipherSuiteHashKind(TLS13CipherAES128GCMSHA256)));
  AssertEquals('0x1302 -> SHA-384', Ord(hkSHA384),
    Ord(TLS13CipherSuiteHashKind(TLS13CipherAES256GCMSHA384)));
  AssertEquals('0x1303 -> SHA-256', Ord(hkSHA256),
    Ord(TLS13CipherSuiteHashKind(TLS13CipherChaCha20Poly1305SHA256)));
end;

procedure TTLS13Tests.TestDefaultSupportedGroups;
var
  Groups: TTLSNamedGroups;
begin
  Groups := TLS13DefaultSupportedGroups;
  AssertEquals('three default groups', 3, Length(Groups));
  AssertEquals('group[0]', TLS13GroupX25519, Groups[0]);
  AssertEquals('group[1]', TLS13GroupSecp256r1, Groups[1]);
  AssertEquals('group[2]', TLS13GroupSecp384r1, Groups[2]);
  AssertTrue('X25519 supported', TLS13GroupSupported(TLS13GroupX25519));
  AssertTrue('P-256 supported', TLS13GroupSupported(TLS13GroupSecp256r1));
  AssertTrue('P-384 supported', TLS13GroupSupported(TLS13GroupSecp384r1));
  AssertFalse('secp521r1 rejected', TLS13GroupSupported(25));
end;

procedure TTLS13Tests.TestSignatureSchemeSupport;
begin
  AssertTrue('ecdsa_secp256r1_sha256', 
    TLS13SignatureSchemeSupported(TLSSigECDSA_Secp256r1_SHA256));
  AssertTrue('ecdsa_secp384r1_sha384',
    TLS13SignatureSchemeSupported(TLSSigECDSA_Secp384r1_SHA384));
  AssertTrue('rsa_pss_rsae_sha256',
    TLS13SignatureSchemeSupported(TLSSigRSA_PSS_RSAE_SHA256));
  AssertFalse('rsa_pkcs1_sha256 rejected',
    TLS13SignatureSchemeSupported(TLSSigRSA_PKCS1_SHA256));
  AssertFalse('rsa_pss_rsae_sha384 rejected',
    TLS13SignatureSchemeSupported(TLSSigRSA_PSS_RSAE_SHA384));
  AssertFalse('unknown scheme rejected',
    TLS13SignatureSchemeSupported($FFFF));
end;

{ ==================================================================== }
{ HKDF (RFC 5869) and HKDF-Expand-Label (RFC 8446, 7.1)                }
{ ==================================================================== }

{ RFC 5869, Appendix A, test cases 1-3: extract and expand over
  HMAC-SHA256. The PRK/OKM values are quoted verbatim from the RFC. }
procedure TTLS13Tests.TestHKDFExtractRFC5869;
const
  IKM1  = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
  SALT1 = '000102030405060708090a0b0c';
  PRK1  = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
  IKM2  = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        + '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        + '404142434445464748494a4b4c4d4e4f';
  SALT2 = '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        + '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
  PRK2  = '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244';
begin
  { Appendix A.1: PRK = HMAC-SHA256(salt, IKM) }
  AssertEquals('RFC 5869 A.1 (TC1) PRK', PRK1,
    BytesToHex(HKDFExtract(hkSHA256, HexToBytes(SALT1), HexToBytes(IKM1))));
  { Appendix A.2 (TC2): long salt and IKM }
  AssertEquals('RFC 5869 A.2 (TC2) PRK', PRK2,
    BytesToHex(HKDFExtract(hkSHA256, HexToBytes(SALT2), HexToBytes(IKM2))));
end;

{ RFC 5869, 2.2: an empty salt is treated as HashLen zero bytes
  (Appendix A.3, TC3; the same PRK follows from an explicit 32-byte
  zero salt). }
procedure TTLS13Tests.TestHKDFExtractEmptySaltIsHashLenZeros;
const
  IKM1 = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
  PRK3 = '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04';
  ZERO = '0000000000000000000000000000000000000000000000000000000000000000';
var
  Empty, Zeros: TBytes;
begin
  Empty := HKDFExtract(hkSHA256, nil, HexToBytes(IKM1));
  AssertEquals('RFC 5869 A.3 (TC3) PRK', PRK3, BytesToHex(Empty));
  Zeros := HKDFExtract(hkSHA256, HexToBytes(ZERO), HexToBytes(IKM1));
  AssertEquals('empty salt == HashLen zero bytes', BytesToHex(Empty),
    BytesToHex(Zeros));
end;

{ RFC 5869, Appendix A, test cases 1-3: HKDF-Expand. }
procedure TTLS13Tests.TestHKDFExpandRFC5869;
const
  IKM1  = '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b';
  SALT1 = '000102030405060708090a0b0c';
  INFO1 = 'f0f1f2f3f4f5f6f7f8f9';
  PRK1  = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
  OKM1  = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
        + '34007208d5b887185865';
  PRK2  = '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244';
  IKM2  = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        + '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        + '404142434445464748494a4b4c4d4e4f';
  SALT2 = '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        + '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        + 'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf';
  INFO2 = 'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
        + 'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        + 'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff';
  OKM2  = 'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c'
        + '59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71'
        + 'cc30c58179ec3e87c14c01d5c1f3434f1d87';
  PRK3  = '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04';
  OKM3  = '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'
        + '9d201395faa4b61a96c8';
begin
  { A.1: L = 42 }
  AssertEquals('RFC 5869 A.1 (TC1) OKM', OKM1,
    BytesToHex(HKDFExpand(hkSHA256, HexToBytes(PRK1), HexToBytes(INFO1), 42)));
  { A.1 also fixes the extract from the same inputs }
  AssertEquals('RFC 5869 A.1 extract matches', PRK1,
    BytesToHex(HKDFExtract(hkSHA256, HexToBytes(SALT1), HexToBytes(IKM1))));
  { A.2: L = 82, long salt/IKM/info }
  AssertEquals('RFC 5869 A.2 (TC2) OKM', OKM2,
    BytesToHex(HKDFExpand(hkSHA256, HexToBytes(PRK2), HexToBytes(INFO2), 82)));
  { A.3: empty info, L = 42 }
  AssertEquals('RFC 5869 A.3 (TC3) OKM', OKM3,
    BytesToHex(HKDFExpand(hkSHA256, HexToBytes(PRK3), nil, 42)));
  { A.4/A.5 are SHA-1 cases and are out of scope. }
end;

{ Serialization of the HkdfLabel structure (RFC 8446, 7.1): a uint16
  length, a length-prefixed "tls13 " || label, and a length-prefixed
  context. }
procedure TTLS13Tests.TestHkdfLabelSerialization;
const
  EXPECTED = '0020'          { length = 32 }
           + '12'            { label length = 18 }
           + '746c73313320632068732074726166666963'  { "tls13 c hs traffic" }
           + '04'            { context length = 4 }
           + 'aabbccdd';
begin
  AssertEquals('HkdfLabel("c hs traffic", 0xaabbccdd, 32)', EXPECTED,
    BytesToHex(TLS13HkdfLabel(TLS13LabelClientHandshakeTraffic,
      HexToBytes('aabbccdd'), 32)));
end;

{ HKDF-Expand-Label(Secret, Label, Context, L) must be exactly
  HKDF-Expand(Secret, HkdfLabel(...), L). }
procedure TTLS13Tests.TestHKDFExpandLabelEqualsExpand;
var
  Secret, Ctx, HkdfLabel: TBytes;
begin
  Secret := HexToBytes(
    '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  Ctx := HexToBytes('aabbccdd');
  HkdfLabel := TLS13HkdfLabel(TLS13LabelWriteKey, Ctx, 16);
  AssertEquals('Expand-Label == Expand(HkdfLabel)',
    BytesToHex(HKDFExpand(hkSHA256, Secret, HkdfLabel, 16)),
    BytesToHex(HKDFExpandLabel(hkSHA256, Secret, TLS13LabelWriteKey, Ctx, 16)));
  AssertEquals('Expand-Label output length', 16,
    Length(HKDFExpandLabel(hkSHA256, Secret, TLS13LabelWriteKey, Ctx, 16)));
end;

{ Independent reference vectors for HKDF-Expand-Label, produced with a
  small python3 script that implements HKDF from RFC 5869 on top of the
  standard `hmac`/`hashlib` modules (documented, not the FPC code under
  test). Secret = PRK of RFC 5869 TC1 for SHA-256. }
procedure TTLS13Tests.TestHKDFExpandLabelVectors;
const
  PRK1 = '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5';
  SEC384 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
         + '202122232425262728292a2b2c2d2e2f';
var
  Secret, Ctx: TBytes;
begin
  Secret := HexToBytes(PRK1);
  Ctx := HexToBytes('aabbccdd');
  AssertEquals('c hs traffic', 
    'e8e307ed215703b0336014108dcc146c80b73cbb18418c8c2b737067dcef0aa8',
    BytesToHex(HKDFExpandLabel(hkSHA256, Secret,
      TLS13LabelClientHandshakeTraffic, Ctx, 32)));
  AssertEquals('s hs traffic',
    '6e43f3bde6bd25b572dd93b60df82f75fbdd63451803e00f9a61cfa1cbb66de5',
    BytesToHex(HKDFExpandLabel(hkSHA256, Secret,
      TLS13LabelServerHandshakeTraffic, Ctx, 32)));
  AssertEquals('key', '9ccc80a2ad506ada9ad073d8d21dcb6b',
    BytesToHex(HKDFExpandLabel(hkSHA256, Secret, TLS13LabelWriteKey, Ctx, 16)));
  AssertEquals('iv', '4664d0ecc0a3b9754e0c57aa',
    BytesToHex(HKDFExpandLabel(hkSHA256, Secret, TLS13LabelWriteIV, Ctx, 12)));
  AssertEquals('finished',
    '335f22243ad4ed1dd10dd5a7159d82a7aa81378da372fd47c650252bbbec748d',
    BytesToHex(HKDFExpandLabel(hkSHA256, Secret, 'finished', Ctx, 32)));
  AssertEquals('derived, empty context',
    '7dca4af7f26ac002ec60e308f135d1795196427528e69955f97aadcb44bef0d0',
    BytesToHex(HKDFExpandLabel(hkSHA256, Secret, TLS13LabelDerived, nil, 32)));
  { SHA-384 suite (0x1302) uses the same label encoding }
  AssertEquals('SHA-384 key, empty context',
    '6877d022f1c61d24ebb7487c16752d9a4798e40431c75b39320e537c90e23225',
    BytesToHex(HKDFExpandLabel(hkSHA384, HexToBytes(SEC384),
      TLS13LabelWriteKey, nil, 32)));
end;

{ Boundaries and explicit failures: negative/oversized output length,
  short PRK, empty label and a label longer than 255 bytes. }
procedure TTLS13Tests.TestHKDFBoundsAndErrors;
var
  Secret, Failed: TBytes;
  Raised: Boolean;
  LongLabel: AnsiString;
begin
  Secret := HexToBytes(
    '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');

  { L = 0 is legal and yields an empty result (RFC 5869, 2.3). }
  AssertEquals('L = 0', 0, Length(HKDFExpand(hkSHA256, Secret, nil, 0)));

  Raised := False;
  try
    HKDFExpand(hkSHA256, Secret, nil, -1);
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('negative L rejected', Raised);

  Raised := False;
  try
    HKDFExpand(hkSHA256, Secret, nil, 255 * 32 + 1);
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('L > 255*HashLen rejected', Raised);

  Raised := False;
  try
    HKDFExpand(hkSHA256, HexToBytes('0011'), nil, 32);
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('short PRK rejected', Raised);

  { Read through a local so that FPC does not warn about an unused
    value; the call must still raise. }
  Raised := False;
  try
    Failed := TLS13HkdfLabel('', nil, 16);
    AssertEquals('unreachable', 0, Length(Failed));
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('empty label rejected', Raised);

  LongLabel := StringOfChar('x', 256);
  Raised := False;
  try
    Failed := TLS13HkdfLabel(LongLabel, nil, 16);
    AssertEquals('unreachable', 0, Length(Failed));
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('label longer than 255 bytes rejected', Raised);
end;

{ ==================================================================== }
{ Key schedule (RFC 8446, 7.1)                                          }
{ ==================================================================== }

{ Published trace: RFC 8448, section 3 "Simple 1-RTT Handshake"
  (TLS_AES_128_GCM_SHA256, no PSK). Every intermediate secret, the
  Transcript-Hash("") context of the two "derived" stages and the two
  transcript hashes are quoted verbatim from the RFC, which states that
  intermediate values are shown "so that implementations might be checked
  incrementally against these values". The handshake-secret step was
  additionally reproduced with `openssl kdf ... -kdfopt mode:EXTRACT_ONLY`. }
procedure TTLS13Tests.TestKeyScheduleRFC8448;
const
  DHE = '8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d';
  TH_HELLO = '860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8';
  TH_SFIN = '9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13';
  EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
  EARLY_SECRET = '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a';
  DERIVED_HANDSHAKE = '6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba';
  HANDSHAKE_SECRET = '1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac';
  C_HS = 'b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21';
  S_HS = 'b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38';
  DERIVED_MASTER = '43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4';
  MASTER_SECRET = '18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919';
  C_AP = '9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5';
  S_AP = 'a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643';
var
  Early, Handshake, Master: TBytes;
begin
  { The context of every "derived" stage is Transcript-Hash("") — the
    RFC prints it as e3b0c4.. (SHA-256 of the empty string). }
  AssertEquals('Transcript-Hash("")', EMPTY_HASH,
    BytesToHex(TLS13TranscriptHash(hkSHA256, nil)));

  Early := TLS13EarlySecret(hkSHA256, nil);
  AssertEquals('early secret', EARLY_SECRET, BytesToHex(Early));
  AssertEquals('derived (early -> handshake)', DERIVED_HANDSHAKE,
    BytesToHex(TLS13DerivedSecret(hkSHA256, Early)));

  Handshake := TLS13HandshakeSecret(hkSHA256, Early, HexToBytes(DHE));
  AssertEquals('handshake secret', HANDSHAKE_SECRET, BytesToHex(Handshake));
  AssertEquals('c hs traffic', C_HS,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA256, Handshake,
      TLS13LabelClientHandshakeTraffic, HexToBytes(TH_HELLO))));
  AssertEquals('s hs traffic', S_HS,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA256, Handshake,
      TLS13LabelServerHandshakeTraffic, HexToBytes(TH_HELLO))));

  AssertEquals('derived (handshake -> master)', DERIVED_MASTER,
    BytesToHex(TLS13DerivedSecret(hkSHA256, Handshake)));
  Master := TLS13MasterSecret(hkSHA256, Handshake);
  AssertEquals('master secret', MASTER_SECRET, BytesToHex(Master));
  AssertEquals('c ap traffic', C_AP,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA256, Master,
      TLS13LabelClientApplicationTraffic, HexToBytes(TH_SFIN))));
  AssertEquals('s ap traffic', S_AP,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA256, Master,
      TLS13LabelServerApplicationTraffic, HexToBytes(TH_SFIN))));
end;

{ RFC 8448, section 4 "Resumed 0-RTT Handshake": the resumption secret of
  section 3 becomes the PSK, so the early secret is HKDF-Extract over a
  non-empty IKM, and the early traffic secret is derived from the
  ClientHello transcript hash quoted in the same trace. }
procedure TTLS13Tests.TestKeySchedulePSKEarlySecret;
const
  PSK = '4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3';
  EARLY_SECRET = '9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c';
  TH_CLIENTHELLO =
    '08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d960913';
  C_E_TRAFFIC =
    '3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6caab62';
var
  Early: TBytes;
begin
  Early := TLS13EarlySecret(hkSHA256, HexToBytes(PSK));
  AssertEquals('early secret from the resumption PSK', EARLY_SECRET,
    BytesToHex(Early));
  AssertEquals('c e traffic', C_E_TRAFFIC,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA256, Early, 'c e traffic',
      HexToBytes(TH_CLIENTHELLO))));
end;

{ SHA-384 key schedule (TLS_AES_256_GCM_SHA384, 0x1302). RFC 8448 only
  traces SHA-256 suites, so these inputs come from an independent
  python3 reference implementation of RFC 8446, 7.1 built directly on
  hmac/hashlib — not on the FPC code under test:

    DHE = 00 01 .. 2f (48 bytes),
    Transcript-Hash(ClientHello..ServerHello)
        = SHA-384("ClientHello..ServerHello (python3 reference)"),
    Transcript-Hash(ServerHello..server Finished)
        = SHA-384("ServerHello..server Finished (python3 reference)").

  The transcript hashes and every derived secret are quoted verbatim
  from the reference run. }
procedure TTLS13Tests.TestKeyScheduleSHA384Reference;
const
  DHE = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
      + '202122232425262728292a2b2c2d2e2f';
  TH_HELLO = 'ee4e4fbaf44767c993751a9d4cdcc7f2c8eb5252eeebce001686f670dcf3553b'
           + '3e790790946a9d7aa21afa7cd7a5d081';
  TH_SFIN = 'e137155d09a2fcc642af6e06d1ece047007970b64f1f3e0a40c22950713c140a'
          + '96379ba02c602e9f54eaf526ed6b165d';
  EARLY_SECRET = '7ee8206f5570023e6dc7519eb1073bc4e791ad37b5c382aa10ba18e2357e7169'
        + '71f9362f2c2fe2a76bfd78dfec4ea9b5';
  HANDSHAKE_SECRET = 'deb1becd84738bdcbf73bdd28bd2209d2fe51b84986a4fbb63d7e3902c00a7d8'
            + '67db2d8e1af869b952dcab5d7f482cab';
  C_HS = '92062ada8e4fed59323e73633626a0f1a2dd56fda7540b56fb54a9e67d0935af'
       + '9d77edae66803b33ff3f34284a4cdf94';
  S_HS = 'a5db36f9a560bc5cfd460a1c9d726f713d67432f649388fe0cb76a19f5332765'
       + '5f319341b77ed5541e3a71d93965100f';
  MASTER_SECRET = '78f71f66fe0d83f65f92e4665b4e2acccb43632e32ebf128e19b5d95c60d4990'
         + '721065aea51bb55a9eb9f81cd7cbf3e1';
  C_AP = '64ec89820a274446fb07578faaf4677c69b1484aac0a05bdb9fd926351782c32'
       + '28a5afb6fdae78cba152e1389c2e68ee';
  S_AP = '5ec521ac015b8541d948bffb81a4ffa41b0bdec93f48d7099651e55fe37548f7'
       + '9cf779595429cd5b49e30e883308f775';
var
  Early, Handshake, Master: TBytes;
begin
  AssertEquals('0x1302 maps to SHA-384', Ord(hkSHA384),
    Ord(TLS13CipherSuiteHashKind(TLS13CipherAES256GCMSHA384)));

  Early := TLS13EarlySecret(hkSHA384, nil);
  AssertEquals('early secret', EARLY_SECRET, BytesToHex(Early));
  Handshake := TLS13HandshakeSecret(hkSHA384, Early, HexToBytes(DHE));
  AssertEquals('handshake secret', HANDSHAKE_SECRET, BytesToHex(Handshake));
  AssertEquals('c hs traffic', C_HS,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA384, Handshake,
      TLS13LabelClientHandshakeTraffic, HexToBytes(TH_HELLO))));
  AssertEquals('s hs traffic', S_HS,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA384, Handshake,
      TLS13LabelServerHandshakeTraffic, HexToBytes(TH_HELLO))));

  Master := TLS13MasterSecret(hkSHA384, Handshake);
  AssertEquals('master secret', MASTER_SECRET, BytesToHex(Master));
  AssertEquals('SHA-384 secrets are 48 bytes', 48, Length(Master));
  AssertEquals('c ap traffic', C_AP,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA384, Master,
      TLS13LabelClientApplicationTraffic, HexToBytes(TH_SFIN))));
  AssertEquals('s ap traffic', S_AP,
    BytesToHex(TLS13DeriveSecretFromHash(hkSHA384, Master,
      TLS13LabelServerApplicationTraffic, HexToBytes(TH_SFIN))));
end;

{ TLS13DeriveKeySchedule must be exactly the sequence of the individual
  steps, with HashKind/HashLen filled in. Its inputs are raw handshake
  transcripts, so this test uses arbitrary bytes and checks the wiring of
  the aggregate record against the primitives; the independent vectors
  are TestKeyScheduleRFC8448 and TestKeyScheduleSHA384Reference. }
procedure TTLS13Tests.TestKeyScheduleAggregateConsistency;
var
  Schedule: TTLS13KeySchedule;
  DHE, Hello, ServerFinished: TBytes;
begin
  DHE := HexToBytes(
    '8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d');
  Hello := HexToBytes('0102030405060708');
  ServerFinished := HexToBytes('1112131415161718');

  Schedule := TLS13DeriveKeySchedule(hkSHA256, nil, DHE, Hello,
    ServerFinished);

  AssertEquals('HashKind', Ord(hkSHA256), Ord(Schedule.HashKind));
  AssertEquals('HashLen', 32, Schedule.HashLen);
  AssertEquals('EarlySecret', BytesToHex(TLS13EarlySecret(hkSHA256, nil)),
    BytesToHex(Schedule.EarlySecret));
  AssertEquals('HandshakeSecret', BytesToHex(TLS13HandshakeSecret(hkSHA256,
    Schedule.EarlySecret, DHE)), BytesToHex(Schedule.HandshakeSecret));
  AssertEquals('ClientHandshakeTrafficSecret',
    BytesToHex(TLS13ClientHandshakeTrafficSecret(hkSHA256,
      Schedule.HandshakeSecret, Hello)),
    BytesToHex(Schedule.ClientHandshakeTrafficSecret));
  AssertEquals('ServerHandshakeTrafficSecret',
    BytesToHex(TLS13ServerHandshakeTrafficSecret(hkSHA256,
      Schedule.HandshakeSecret, Hello)),
    BytesToHex(Schedule.ServerHandshakeTrafficSecret));
  AssertEquals('MasterSecret', BytesToHex(TLS13MasterSecret(hkSHA256,
    Schedule.HandshakeSecret)), BytesToHex(Schedule.MasterSecret));
  AssertEquals('ClientApplicationTrafficSecret',
    BytesToHex(TLS13ClientApplicationTrafficSecret(hkSHA256,
      Schedule.MasterSecret, ServerFinished)),
    BytesToHex(Schedule.ClientApplicationTrafficSecret));
  AssertEquals('ServerApplicationTrafficSecret',
    BytesToHex(TLS13ServerApplicationTrafficSecret(hkSHA256,
      Schedule.MasterSecret, ServerFinished)),
    BytesToHex(Schedule.ServerApplicationTrafficSecret));
end;

{ A cipher suite outside 0x1301/02/03 must not silently pick a hash. }
procedure TTLS13Tests.TestKeyScheduleUnsupportedSuite;
var
  Raised: Boolean;
  Kind: THashKind;
begin
  Raised := False;
  try
    Kind := TLS13CipherSuiteHashKind($C02F);
    AssertEquals('unreachable', Ord(hkSHA256), Ord(Kind));
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('TLS 1.2 cipher suite rejected by the key schedule', Raised);
end;

{ ==================================================================== }
{ Record layer (RFC 8446, 5)                                            }
{ ==================================================================== }

procedure TTLS13Tests.TestRecordNonceAndAAD;
const
  ZERO_IV = '000000000000000000000000';
begin
  AssertEquals('protected record opaque type', 23, TLS13RecordOpaqueType);
  AssertEquals('legacy_record_version', $0303, TLS13RecordLegacyVersion);
  AssertEquals('AEAD tag length', 16, TLS13RecordTagLength);
  AssertEquals('write IV and nonce length', 12, TLS13RecordIVLen);

  { nonce = iv XOR seq_num (RFC 8446, 5.3); seq_num is big-endian and is
    XORed into the last eight bytes of the 12-byte IV. }
  AssertEquals('nonce with seq 0 is the IV', ZERO_IV,
    BytesToHex(TLS13RecordNonce(HexToBytes(ZERO_IV), 0)));
  AssertEquals('nonce with seq 0x0102030405060708',
    '000000000102030405060708',
    BytesToHex(TLS13RecordNonce(HexToBytes(ZERO_IV),
      QWord($0102030405060708))));
  AssertEquals('nonce XORs only the last eight IV bytes',
    'b0b1b2b3a59785f3eddfcd33',
    BytesToHex(TLS13RecordNonce(HexToBytes('b0b1b2b3b4b5b6b7b8b9babb'),
      QWord($1122334455667788))));

  { additional_data = opaque_type || legacy_record_version || length
    (RFC 8446, 5.2). }
  AssertEquals('AAD for a 0x0102-byte ciphertext', '1703030102',
    BytesToHex(TLS13RecordAdditionalData($0102)));
  AssertEquals('AAD for an empty ciphertext', '1703030000',
    BytesToHex(TLS13RecordAdditionalData(0)));
  AssertEquals('AAD for the maximum ciphertext', '170303ffff',
    BytesToHex(TLS13RecordAdditionalData(65535)));
end;

procedure TTLS13Tests.TestRecordNonceAndAADBounds;
var
  Back: TBytes;
  Raised: Boolean;
begin
  Raised := False;
  try
    Back := TLS13RecordNonce(HexToBytes('000102030405060708090a0b0c'), 0);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('13-byte IV rejected', Raised);

  Raised := False;
  try
    Back := TLS13RecordNonce(HexToBytes('000102030405060708090a'), 0);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('11-byte IV rejected', Raised);

  Raised := False;
  try
    Back := TLS13RecordAdditionalData(-1);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('negative ciphertext length rejected', Raised);

  Raised := False;
  try
    Back := TLS13RecordAdditionalData(65536);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('ciphertext length above 2^16-1 rejected', Raised);
end;

procedure TTLS13Tests.TestInnerPlaintextEncodeDecode;
var
  Inner, Content: TBytes;
  CType: Byte;
  Padding: Integer;
begin
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentApplicationData,
    HexToBytes('deadbeef'));
  AssertEquals('inner plaintext = content || type', 'deadbeef17',
    BytesToHex(Inner));
  Padding := TLS13DecodeInnerPlaintext(Inner, CType, Content);
  AssertEquals('no padding', 0, Padding);
  AssertEquals('content type', TLS13ContentApplicationData, CType);
  AssertEquals('content', 'deadbeef', BytesToHex(Content));

  { handshake is the inner type of every encrypted handshake record }
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentHandshake,
    HexToBytes('0100'));
  AssertEquals('handshake inner plaintext', '010016', BytesToHex(Inner));
  Padding := TLS13DecodeInnerPlaintext(Inner, CType, Content);
  AssertEquals('handshake content type', TLS13ContentHandshake, CType);
  AssertEquals('handshake content', '0100', BytesToHex(Content));

  { an empty content is only the trailing content-type byte }
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentAlert, nil);
  AssertEquals('empty content', '15', BytesToHex(Inner));
  Padding := TLS13DecodeInnerPlaintext(Inner, CType, Content);
  AssertEquals('alert content type', TLS13ContentAlert, CType);
  AssertEquals('empty content length', 0, Length(Content));
end;

procedure TTLS13Tests.TestInnerPlaintextPaddingAndLength;
var
  Inner, Content: TBytes;
  CType: Byte;
  Padding: Integer;
begin
  AssertEquals('length without padding', 6, TLS13InnerPlaintextLength(5, 0));
  AssertEquals('length with padding', 10, TLS13InnerPlaintextLength(5, 4));
  AssertEquals('maximum inner plaintext length',
    (1 shl 14) + 256 - TLS13RecordTagLength, TLS13InnerPlaintextMaxLength);
  AssertEquals('maximum inner plaintext length accepted',
    TLS13InnerPlaintextMaxLength,
    TLS13InnerPlaintextLength(TLS13InnerPlaintextMaxLength - 1, 0));

  Inner := TLS13EncodeInnerPlaintext(TLS13ContentApplicationData,
    HexToBytes('0102'), 3);
  AssertEquals('content || type || padding', '010217000000',
    BytesToHex(Inner));
  AssertEquals('padded length', 6, Length(Inner));
  Padding := TLS13DecodeInnerPlaintext(Inner, CType, Content);
  AssertEquals('padding reported', 3, Padding);
  AssertEquals('content after padding', '0102', BytesToHex(Content));
  AssertEquals('content type after padding', TLS13ContentApplicationData,
    CType);
end;

procedure TTLS13Tests.TestInnerPlaintextNegative;
var
  Plain, Content: TBytes;
  CType: Byte;
  Padding: Integer;
  Raised: Boolean;
begin
  { An empty record has no content type. }
  Raised := False;
  try
    Padding := TLS13DecodeInnerPlaintext(nil, CType, Content);
    AssertEquals('unreachable', 0, Padding);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('empty record rejected', Raised);

  { A record that is all padding carries no content type. }
  Raised := False;
  try
    Padding := TLS13DecodeInnerPlaintext(HexToBytes('000000'), CType,
      Content);
    AssertEquals('unreachable', 0, Padding);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('padding-only record rejected', Raised);

  { change_cipher_spec must never be protected (RFC 8446, 5). }
  Raised := False;
  try
    Padding := TLS13DecodeInnerPlaintext(HexToBytes('0114'), CType, Content);
    AssertEquals('unreachable', 0, Padding);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('protected change_cipher_spec rejected', Raised);

  { An unknown inner content type is invalid. }
  Raised := False;
  try
    Padding := TLS13DecodeInnerPlaintext(HexToBytes('01ee'), CType, Content);
    AssertEquals('unreachable', 0, Padding);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('unknown content type rejected', Raised);

  { The encoder rejects the same types up front. }
  Raised := False;
  try
    Plain := TLS13EncodeInnerPlaintext(TLS13ContentChangeCipherSpec,
      HexToBytes('01'));
    AssertEquals('unreachable', 0, Length(Plain));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('encoding change_cipher_spec rejected', Raised);

  Raised := False;
  try
    Plain := TLS13EncodeInnerPlaintext($EE, HexToBytes('01'));
    AssertEquals('unreachable', 0, Length(Plain));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('encoding an unknown content type rejected', Raised);

  { Explicit length limits. }
  Raised := False;
  try
    Padding := TLS13InnerPlaintextLength(-1, 0);
    AssertEquals('unreachable', 0, Padding);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('negative content length rejected', Raised);

  Raised := False;
  try
    Padding := TLS13InnerPlaintextLength(0, -1);
    AssertEquals('unreachable', 0, Padding);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('negative padding rejected', Raised);

  Raised := False;
  try
    Padding := TLS13InnerPlaintextLength(TLS13InnerPlaintextMaxLength, 0);
    AssertEquals('unreachable', 0, Padding);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('oversized inner plaintext rejected', Raised);
end;

{ Published trace: RFC 8448, section 3 "Simple 1-RTT Handshake". The client
  Finished handshake message is protected with the client handshake write
  key and IV of the same trace; the complete record is quoted verbatim
  from the RFC. }
procedure TTLS13Tests.TestRecordProtectRFC8448ClientFinished;
const
  KEY = 'dbfaa693d1762c5b666af5d950258d01';
  IV  = '5bd3c71b836e0b76bb73265f';
  MSG = '14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2e'
      + 'dd5ce61';
  FRAGMENT = '75ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f3'
           + '8f80338ac98fc46deb384bd1caeacab6867d726c40546';
var
  Inner, Frag, Back, Content: TBytes;
  CType: Byte;
  Padding: Integer;
begin
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentHandshake, HexToBytes(MSG));
  AssertEquals('inner plaintext length', 37, Length(Inner));
  AssertEquals('inner plaintext', MSG + '16', BytesToHex(Inner));

  Frag := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(KEY), HexToBytes(IV), 0, Inner);
  AssertEquals('fragment length', 53, Length(Frag));
  AssertEquals('RFC 8448 client Finished fragment', FRAGMENT,
    BytesToHex(Frag));
  AssertEquals('record header (AAD) of the published record', '1703030035',
    BytesToHex(TLS13RecordAdditionalData(Length(Frag))));

  Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(KEY), HexToBytes(IV), 0, Frag);
  AssertEquals('unprotected inner plaintext', BytesToHex(Inner),
    BytesToHex(Back));
  Padding := TLS13DecodeInnerPlaintext(Back, CType, Content);
  AssertEquals('padding', 0, Padding);
  AssertEquals('content type', TLS13ContentHandshake, CType);
  AssertEquals('Finished message', MSG, BytesToHex(Content));
end;

{ Published trace: RFC 8448, section 3. The application-data and alert
  records of both directions are protected with the application write
  keys printed in the same trace. The server records carry sequence
  numbers 1 and 2 because its NewSessionTicket used sequence number 0. }
procedure TTLS13Tests.TestRecordProtectRFC8448ApplicationData;
const
  PAYLOAD = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
          + '202122232425262728292a2b2c2d2e2f3031';
  C_KEY = '17422dda596ed5d9acd890e3c63f5051';
  C_IV  = '5b78923dee08579033e523d9';
  C_APP = 'a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5'
        + 'b46b395bd54a9a20441e2b62974e1f5a6292a2977014bd1e3deae63aeebb2169'
        + '4915e4';
  C_ALERT = 'c9872760655666b74d7ff1153efd6db6d0b0e3';
  S_KEY = '9f02283b6c9c07efc26bb9f2ac92e356';
  S_IV  = 'cf782b88dd83549aadf1e984';
  S_APP = '2e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d'
        + '90e6dffc602dcb501a59a8fcc49c4bf2e5f0a21c0047c2abf332540dd032e167'
        + 'c2955d';
  S_ALERT = 'b58fd67166ebf599d24720cfbe7efa7a8864a9';
var
  Inner, Frag, Back, Content: TBytes;
  CType: Byte;
  Padding: Integer;
begin
  { client -> server, application_data, seq 0 }
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentApplicationData,
    HexToBytes(PAYLOAD));
  Frag := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(C_KEY), HexToBytes(C_IV), 0, Inner);
  AssertEquals('client application_data fragment', C_APP, BytesToHex(Frag));
  Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(C_KEY), HexToBytes(C_IV), 0, Frag);
  Padding := TLS13DecodeInnerPlaintext(Back, CType, Content);
  AssertEquals('client content type', TLS13ContentApplicationData, CType);
  AssertEquals('client payload', PAYLOAD, BytesToHex(Content));
  AssertEquals('client padding', 0, Padding);

  { client -> server, alert, seq 1 }
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentAlert, HexToBytes('0100'));
  Frag := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(C_KEY), HexToBytes(C_IV), 1, Inner);
  AssertEquals('client alert fragment', C_ALERT, BytesToHex(Frag));
  AssertEquals('client alert record header', '1703030013',
    BytesToHex(TLS13RecordAdditionalData(Length(Frag))));

  { server -> client, application_data, seq 1 }
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentApplicationData,
    HexToBytes(PAYLOAD));
  Frag := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(S_KEY), HexToBytes(S_IV), 1, Inner);
  AssertEquals('server application_data fragment', S_APP, BytesToHex(Frag));
  Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(S_KEY), HexToBytes(S_IV), 1, Frag);
  Padding := TLS13DecodeInnerPlaintext(Back, CType, Content);
  AssertEquals('server content type', TLS13ContentApplicationData, CType);
  AssertEquals('server payload', PAYLOAD, BytesToHex(Content));

  { server -> client, alert, seq 2 }
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentAlert, HexToBytes('0100'));
  Frag := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(S_KEY), HexToBytes(S_IV), 2, Inner);
  AssertEquals('server alert fragment', S_ALERT, BytesToHex(Frag));
  Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256,
    HexToBytes(S_KEY), HexToBytes(S_IV), 2, Frag);
  Padding := TLS13DecodeInnerPlaintext(Back, CType, Content);
  AssertEquals('server alert content type', TLS13ContentAlert, CType);
  AssertEquals('server alert payload', '0100', BytesToHex(Content));
end;

{ Independent reference vectors for the two remaining AEAD suites,
  produced with a small python3 script on top of the `cryptography`
  library (AESGCM/ChaCha20Poly1305, documented, not the FPC code under
  test). Both records carry the inner plaintext
  content = 00 01 .. 0f, type = application_data (0x17) and three zero
  padding bytes, and the AAD is 17 03 03 00 24. }
procedure TTLS13Tests.TestRecordPublishedSuiteVectors;
const
  INNER = '000102030405060708090a0b0c0d0e0f17000000';
  A256_KEY = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  A256_IV  = 'a0a1a2a3a4a5a6a7a8a9aaab';
  A256_FRAG = 'cefb06f22e73d02d9506a015846f603eeed9853aa116159ba7aa32168f77d5'
            + '1fe1274ab1';
  CC_KEY = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
  CC_IV  = 'b0b1b2b3b4b5b6b7b8b9babb';
  CC_FRAG = '3ae63803ba57d9b9304b32352419bbb86bdaa33394e606322b61d35ad83e264'
          + 'fecec53a5';
begin
  { TLS_AES_256_GCM_SHA384, seq 5 }
  AssertEquals('AES-256-GCM record fragment', A256_FRAG,
    BytesToHex(TLS13ProtectRecordFragment(TLS13CipherAES256GCMSHA384,
      HexToBytes(A256_KEY), HexToBytes(A256_IV), 5, HexToBytes(INNER))));
  AssertEquals('AES-256-GCM round trip', INNER,
    BytesToHex(TLS13UnprotectRecordFragment(TLS13CipherAES256GCMSHA384,
      HexToBytes(A256_KEY), HexToBytes(A256_IV), 5, HexToBytes(A256_FRAG))));

  { TLS_CHACHA20_POLY1305_SHA256, seq 0x1122334455667788 }
  AssertEquals('ChaCha20-Poly1305 nonce for a large sequence number',
    'b0b1b2b3a59785f3eddfcd33',
    BytesToHex(TLS13RecordNonce(HexToBytes(CC_IV),
      QWord($1122334455667788))));
  AssertEquals('ChaCha20-Poly1305 record fragment', CC_FRAG,
    BytesToHex(TLS13ProtectRecordFragment(TLS13CipherChaCha20Poly1305SHA256,
      HexToBytes(CC_KEY), HexToBytes(CC_IV), QWord($1122334455667788),
      HexToBytes(INNER))));
  AssertEquals('ChaCha20-Poly1305 round trip', INNER,
    BytesToHex(TLS13UnprotectRecordFragment(
      TLS13CipherChaCha20Poly1305SHA256, HexToBytes(CC_KEY),
      HexToBytes(CC_IV), QWord($1122334455667788), HexToBytes(CC_FRAG))));
end;

procedure TTLS13Tests.TestRecordRoundTripAllSuites;
var
  Suites: array[0..2] of TTLSCipherSuite;
  Key, IV, Inner, Frag, Back: TBytes;
  I, J: Integer;
  Raised: Boolean;
begin
  Suites[0] := TLS13CipherAES128GCMSHA256;
  Suites[1] := TLS13CipherAES256GCMSHA384;
  Suites[2] := TLS13CipherChaCha20Poly1305SHA256;

  AssertEquals('0x1301 key length', 16,
    TLS13CipherSuiteKeyLength(Suites[0]));
  AssertEquals('0x1302 key length', 32,
    TLS13CipherSuiteKeyLength(Suites[1]));
  AssertEquals('0x1303 key length', 32,
    TLS13CipherSuiteKeyLength(Suites[2]));
  AssertEquals('0x1301 AEAD', Ord(aeadAES128GCM),
    Ord(TLS13CipherSuiteAEADMode(Suites[0])));
  AssertEquals('0x1302 AEAD', Ord(aeadAES256GCM),
    Ord(TLS13CipherSuiteAEADMode(Suites[1])));
  AssertEquals('0x1303 AEAD', Ord(aeadChaCha20Poly1305),
    Ord(TLS13CipherSuiteAEADMode(Suites[2])));

  IV := HexToBytes('000102030405060708090a0b');
  for I := 0 to 2 do
  begin
    SetLength(Key, TLS13CipherSuiteKeyLength(Suites[I]));
    for J := 0 to High(Key) do
      Key[J] := Byte(J * 7 + 1);
    Inner := TLS13EncodeInnerPlaintext(TLS13ContentHandshake,
      HexToBytes('aabbccddeeff'), I);
    Frag := TLS13ProtectRecordFragment(Suites[I], Key, IV, QWord(I), Inner);
    AssertEquals('ciphertext length', Length(Inner) + TLS13RecordTagLength,
      Length(Frag));
    Back := TLS13UnprotectRecordFragment(Suites[I], Key, IV, QWord(I), Frag);
    AssertEquals('round trip', BytesToHex(Inner), BytesToHex(Back));

    { The sequence number is part of the nonce, so the same fragment must
      not authenticate under any other one. }
    Raised := False;
    try
      Back := TLS13UnprotectRecordFragment(Suites[I], Key, IV, QWord(I + 1),
        Frag);
      AssertEquals('unreachable', 0, Length(Back));
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('wrong sequence number rejected', Raised);
  end;
end;

procedure TTLS13Tests.TestRecordNegative;
const
  AES_KEY = '17422dda596ed5d9acd890e3c63f5051';
  IV  = '5b78923dee08579033e523d9';
  PAYLOAD = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
          + '202122232425262728292a2b2c2d2e2f3031';
var
  Key, IVec, Inner, Frag, Bad, Back: TBytes;
  Mode: TTLSAEADMode;
  KeyLen: Integer;
  Raised: Boolean;
begin
  Key := HexToBytes(AES_KEY);
  IVec := HexToBytes(IV);
  Inner := TLS13EncodeInnerPlaintext(TLS13ContentApplicationData,
    HexToBytes(PAYLOAD));
  Frag := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256, Key, IVec,
    0, Inner);

  { A flipped ciphertext byte must fail authentication. }
  Bad := Copy(Frag, 0, Length(Frag));
  Bad[0] := Bad[0] xor $01;
  Raised := False;
  try
    Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256, Key,
      IVec, 0, Bad);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('corrupted ciphertext rejected', Raised);

  { A flipped tag byte must fail authentication. }
  Bad := Copy(Frag, 0, Length(Frag));
  Bad[Length(Bad) - 1] := Bad[Length(Bad) - 1] xor $80;
  Raised := False;
  try
    Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256, Key,
      IVec, 0, Bad);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('corrupted AEAD tag rejected', Raised);

  { The same fragment under the next sequence number must fail. }
  Raised := False;
  try
    Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256, Key,
      IVec, 1, Frag);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('wrong sequence number rejected', Raised);

  { A wrong key (one bit flipped) must fail. }
  Bad := Copy(Key, 0, Length(Key));
  Bad[0] := Bad[0] xor $01;
  Raised := False;
  try
    Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256, Bad,
      IVec, 0, Frag);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('wrong key rejected', Raised);

  { A fragment without the AEAD tag is too short to be a record. }
  Raised := False;
  try
    Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256, Key,
      IVec, 0, Copy(Frag, 0, TLS13RecordTagLength));
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('tag-only fragment rejected', Raised);

  Raised := False;
  try
    Back := TLS13UnprotectRecordFragment(TLS13CipherAES128GCMSHA256, Key,
      IVec, 0, nil);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('empty fragment rejected', Raised);

  { A key of the wrong length is rejected before the AEAD is touched. }
  Raised := False;
  try
    Back := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256,
      HexToBytes('00112233445566778899aabbccddee'), IVec, 0, Inner);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('15-byte key rejected', Raised);

  { A write IV of the wrong length is rejected. }
  Raised := False;
  try
    Back := TLS13ProtectRecordFragment(TLS13CipherAES128GCMSHA256, Key,
      HexToBytes('0001020304050607'), 0, Inner);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('8-byte IV rejected', Raised);

  { Cipher suites outside 0x1301/02/03 are not silently mapped. }
  Raised := False;
  try
    Mode := TLS13CipherSuiteAEADMode($C02F);
    AssertEquals('unreachable', Ord(aeadAES128GCM), Ord(Mode));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('TLS 1.2 suite rejected by AEAD mode', Raised);

  Raised := False;
  try
    KeyLen := TLS13CipherSuiteKeyLength($C02F);
    AssertEquals('unreachable', 0, KeyLen);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('TLS 1.2 suite rejected by key length', Raised);

  Raised := False;
  try
    Back := TLS13ProtectRecordFragment($C02F, Key, IVec, 0, Inner);
    AssertEquals('unreachable', 0, Length(Back));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('TLS 1.2 suite rejected by record protection', Raised);
end;

{ A bare ChangeCipherSpec record (RFC 8446, 5) is a middlebox
  compatibility signal carrying exactly one byte 0x01; anything else must
  abort the handshake. }
procedure TTLS13Tests.TestLegacyChangeCipherSpec;
var
  Raised: Boolean;
begin
  AssertTrue('bare CCS record',
    TLS13IsLegacyChangeCipherSpec(ctChangeCipherSpec, HexToBytes('01')));
  AssertFalse('CCS with the wrong content',
    TLS13IsLegacyChangeCipherSpec(ctChangeCipherSpec, HexToBytes('02')));
  AssertFalse('CCS with two bytes',
    TLS13IsLegacyChangeCipherSpec(ctChangeCipherSpec, HexToBytes('0100')));
  AssertFalse('empty CCS',
    TLS13IsLegacyChangeCipherSpec(ctChangeCipherSpec, nil));
  AssertFalse('handshake is not CCS',
    TLS13IsLegacyChangeCipherSpec(ctHandshake, HexToBytes('01')));

  TLS13CheckLegacyChangeCipherSpec(HexToBytes('01'));

  Raised := False;
  try
    TLS13CheckLegacyChangeCipherSpec(HexToBytes('02'));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('CCS byte other than 0x01 rejected', Raised);

  Raised := False;
  try
    TLS13CheckLegacyChangeCipherSpec(HexToBytes('0100'));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('two-byte CCS rejected', Raised);

  Raised := False;
  try
    TLS13CheckLegacyChangeCipherSpec(nil);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('empty CCS rejected', Raised);
end;

{ ==================================================================== }
{ Handshake messages: ClientHello, ServerHello, EncryptedExtensions,    }
{ Certificate, CertificateVerify                                        }
{ ==================================================================== }

{ ClientHello (RFC 8446, 4.1.2): legacy_version, random, a 32-byte
  compatibility legacy_session_id, the three AEAD cipher suites, a single
  null compression method and the mandatory extensions. The body is decoded
  by hand so the wire layout itself is asserted, not just the builder. }
procedure TTLS13Tests.TestClientHelloStructure;
var
  Opts, Opts2: TTLS13ClientHelloOptions;
  Body, Random, SessID, Msg: TBytes;
  Exts: TTLSExtensions;
  Ext: TTLSExtension;
  Entry: TTLS13KeyShareEntry;
  Groups: TTLSNamedGroups;
  Shares: TTLS13KeyShareOffers;
  Offset, SuitesLen, ExtLen: Integer;
  Raised: Boolean;
begin
  Random := HexToBytes(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  SessID := HexToBytes(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');

  Opts := DefaultTLS13ClientHelloOptions;
  Opts.ServerName := 'example.com';
  Opts.ClientRandom := Random;
  Opts.LegacySessionID := SessID;
  Opts.KeyShareOffers := TLS13GenerateKeyShareOffers(
    TLS13DefaultSupportedGroups);
  try
    Body := BuildTLS13ClientHelloBody(Opts);

    { legacy_version = 0x0303, random, legacy_session_id (32 bytes in
      compatibility mode, RFC 8446, D.4). }
    AssertEquals('legacy_version', Integer(TLS13LegacyVersion),
      Integer(ReadU16(Body, 0)));
    AssertEquals('random', BytesToHex(Random), BytesToHex(Copy(Body, 2, 32)));
    AssertEquals('legacy_session_id length', 32, Integer(Body[34]));
    AssertEquals('legacy_session_id', BytesToHex(SessID),
      BytesToHex(Copy(Body, 35, 32)));

    { cipher_suites: the three TLS 1.3 AEAD suites in preference order. }
    Offset := 35 + 32;
    SuitesLen := ReadU16(Body, Offset);
    AssertEquals('cipher_suites length', 6, SuitesLen);
    AssertEquals('suite[0]', TLS13CipherAES128GCMSHA256,
      ReadU16(Body, Offset + 2));
    AssertEquals('suite[1]', TLS13CipherAES256GCMSHA384,
      ReadU16(Body, Offset + 4));
    AssertEquals('suite[2]', TLS13CipherChaCha20Poly1305SHA256,
      ReadU16(Body, Offset + 6));

    { legacy_compression_methods: exactly one null byte. }
    Offset := Offset + 2 + SuitesLen;
    AssertEquals('compression methods length', 1, Integer(Body[Offset]));
    AssertEquals('compression method', 0, Integer(Body[Offset + 1]));

    { Extension block: it must cover the rest of the body. }
    Offset := Offset + 2;
    ExtLen := ReadU16(Body, Offset);
    AssertEquals('extension block covers the rest of the body',
      Length(Body), Offset + 2 + ExtLen);
    Exts := DecodeTLSExtensions(Copy(Body, Offset, 2 + ExtLen));
    AssertEquals('five default extensions', 5, Length(Exts));

    { server_name (RFC 6066). }
    AssertTrue('server_name present',
      FindTLSExtension(Exts, TLS13ExtServerName, Ext));
    AssertEquals('server_name = example.com',
      '000e' + '00' + '000b' + '6578616d706c652e636f6d',
      BytesToHex(Ext.Data));

    { supported_groups: X25519 and the two usable NIST curves (4.2.7). }
    AssertTrue('supported_groups present',
      FindTLSExtension(Exts, TLS13ExtSupportedGroups, Ext));
    AssertEquals('supported_groups = X25519, P-256, P-384',
      '0006001d00170018', BytesToHex(Ext.Data));

    { signature_algorithms: exactly the verifiable schemes (4.2.3). }
    AssertTrue('signature_algorithms present',
      FindTLSExtension(Exts, TLS13ExtSignatureAlgorithms, Ext));
    AssertEquals('signature_algorithms', '0006040305030804',
      BytesToHex(Ext.Data));

    { supported_versions: exactly 0x0304 (4.2.1). }
    AssertTrue('supported_versions present',
      FindTLSExtension(Exts, TLS13ExtSupportedVersions, Ext));
    AssertEquals('supported_versions = 0x0304', '020304',
      BytesToHex(Ext.Data));

    { key_share: one offer per group, the 32-byte X25519 value and
      uncompressed SEC 1 points (4.2.8). }
    AssertTrue('key_share present',
      FindTLSExtension(Exts, TLS13ExtKeyShare, Ext));
    AssertEquals('client_shares length', 2 + 36 + 69 + 101, Length(Ext.Data));
    AssertEquals('client_shares total length field', 36 + 69 + 101,
      ReadU16(Ext.Data, 0));
    Entry := TLS13ParseKeyShareEntry(Copy(Ext.Data, 2, 36));
    AssertEquals('offer[0] group', TLS13GroupX25519, Entry.Group);
    AssertEquals('offer[0] key length', 32, Length(Entry.KeyExchange));
    Entry := TLS13ParseKeyShareEntry(Copy(Ext.Data, 38, 69));
    AssertEquals('offer[1] group', TLS13GroupSecp256r1, Entry.Group);
    AssertEquals('offer[1] point length', 65, Length(Entry.KeyExchange));
    AssertEquals('offer[1] uncompressed point', $04, Entry.KeyExchange[0]);
    Entry := TLS13ParseKeyShareEntry(Copy(Ext.Data, 107, 101));
    AssertEquals('offer[2] group', TLS13GroupSecp384r1, Entry.Group);
    AssertEquals('offer[2] point length', 97, Length(Entry.KeyExchange));
    AssertEquals('offer[2] uncompressed point', $04, Entry.KeyExchange[0]);

    { The full message is htClientHello || uint24 length || body. }
    Msg := BuildTLS13ClientHello(Opts);
    AssertEquals('handshake type', Integer(TLS13ClientHello), Integer(Msg[0]));
    AssertEquals('handshake length', Length(Body),
      (Integer(Msg[1]) shl 16) or (Integer(Msg[2]) shl 8) or Integer(Msg[3]));
    AssertEquals('handshake body', BytesToHex(Body),
      BytesToHex(Copy(Msg, 4, Length(Msg) - 4)));

    { psk_key_exchange_modes is only sent on request (4.2.9). }
    Opts2 := Opts;
    Opts2.PskKeyExchangeModes := True;
    Exts := BuildTLS13ClientHelloExtensions(Opts2);
    AssertEquals('six extensions with psk modes', 6, Length(Exts));
    AssertTrue('psk_key_exchange_modes present',
      FindTLSExtension(Exts, TLS13ExtPskKeyExchangeModes, Ext));
    AssertEquals('psk_dhe_ke', '0101', BytesToHex(Ext.Data));

    { --- Rejections before a ClientHello is built (4.1.2, 4.2). --- }
    Raised := False;
    try
      Opts2 := Opts;
      Opts2.KeyShareOffers := nil;
      Body := BuildTLS13ClientHelloBody(Opts2);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('missing key_share offer rejected', Raised);

    Raised := False;
    try
      Opts2 := Opts;
      SetLength(Opts2.CipherSuites, 1);
      Opts2.CipherSuites[0] := $C02F;   { a TLS 1.2 suite }
      Body := BuildTLS13ClientHelloBody(Opts2);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('TLS 1.2 cipher suite rejected', Raised);

    Raised := False;
    try
      Opts2 := Opts;
      SetLength(Opts2.SignatureSchemes, 1);
      Opts2.SignatureSchemes[0] := TLSSigRSA_PKCS1_SHA256;
      Body := BuildTLS13ClientHelloBody(Opts2);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('unsupported signature scheme rejected', Raised);

    Raised := False;
    try
      Opts2 := Opts;
      SetLength(Opts2.SupportedGroups, 2);
      Opts2.SupportedGroups[0] := TLS13GroupSecp256r1;
      Opts2.SupportedGroups[1] := 25;   { secp521r1, not implemented }
      Body := BuildTLS13ClientHelloBody(Opts2);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('unsupported group in supported_groups rejected', Raised);

    Raised := False;
    try
      Opts2 := Opts;
      Opts2.ClientRandom := Copy(Random, 0, 16);
      Body := BuildTLS13ClientHelloBody(Opts2);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('short random rejected', Raised);
  finally
    TLS13KeyShareOffersFree(Opts.KeyShareOffers);
  end;

  { A key_share for a group that is not listed in supported_groups is a
    protocol error (RFC 8446, 4.2.8). }
  SetLength(Groups, 1);
  Groups[0] := TLS13GroupSecp384r1;
  Shares := TLS13GenerateKeyShareOffers(Groups);
  try
    Raised := False;
    try
      Opts2 := DefaultTLS13ClientHelloOptions;
      SetLength(Opts2.SupportedGroups, 1);
      Opts2.SupportedGroups[0] := TLS13GroupSecp256r1;
      Opts2.KeyShareOffers := Shares;
      Body := BuildTLS13ClientHelloBody(Opts2);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('key_share group outside supported_groups rejected', Raised);
  finally
    TLS13KeyShareOffersFree(Shares);
  end;
end;

{ ServerHello (RFC 8446, 4.1.3): a well-formed body is parsed field by
  field, the legacy_session_id_echo is checked against what the client
  sent, and a body with the wrong handshake type or a truncation is
  refused. }
procedure TTLS13Tests.TestServerHelloParser;
const
  RANDOM_HEX =
    '9f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f';
  SESSION_HEX =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
var
  Body, Rand, Sess, Bad: TBytes;
  KS: TTLS13KeyShare;
  SH: TTLS13ServerHello;
  Msg: TTLSHandshakeMessage;
  Raised: Boolean;
begin
  Rand := HexToBytes(RANDOM_HEX);
  Sess := HexToBytes(SESSION_HEX);
  KS := TLS13KeyShareGenerate(TLS13GroupSecp256r1);
  try
    Body := BuildServerHelloBody(Rand, Sess, TLS13CipherAES128GCMSHA256,
      TLS13GroupSecp256r1, KS.PublicKey);

    SH := ParseTLS13ServerHello(Body);
    AssertEquals('legacy_version', Integer(TLS13LegacyVersion),
      Integer(SH.LegacyVersion));
    AssertEquals('random', BytesToHex(Rand), BytesToHex(SH.Random));
    AssertEquals('legacy_session_id_echo', BytesToHex(Sess),
      BytesToHex(SH.LegacySessionIDEcho));
    AssertEquals('cipher_suite', TLS13CipherAES128GCMSHA256, SH.CipherSuite);
    AssertEquals('legacy_compression_method', 0,
      Integer(SH.LegacyCompressionMethod));
    AssertEquals('selected_version', Integer(TLS13Version),
      Integer(SH.SupportedVersion));
    AssertTrue('key_share decoded', SH.HasKeyShare);
    AssertEquals('key_share group', TLS13GroupSecp256r1, SH.KeyShare.Group);
    AssertEquals('server_share length', Length(KS.PublicKey),
      Length(SH.KeyShare.KeyExchange));
    AssertEquals('server_share is an uncompressed point', $04,
      SH.KeyShare.KeyExchange[0]);
    AssertEquals('two extensions', 2, Length(SH.Extensions));

    { The echo overload accepts the matching legacy_session_id ... }
    SH := ParseTLS13ServerHello(Body, Sess);
    AssertEquals('matching legacy_session_id accepted', BytesToHex(Sess),
      BytesToHex(SH.LegacySessionIDEcho));

    { ... and rejects a different one (RFC 8446, 4.1.3). }
    Bad := Copy(Sess, 0, Length(Sess));
    Bad[0] := Bad[0] xor $FF;
    Raised := False;
    try
      SH := ParseTLS13ServerHello(Body, Bad);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('mismatched legacy_session_id_echo rejected', Raised);

    { The message-level overload requires htServerHello. }
    Msg.MsgType := htServerHello;
    Msg.Body := Body;
    SH := ParseTLS13ServerHelloMessage(Msg);
    AssertEquals('message overload', TLS13CipherAES128GCMSHA256,
      SH.CipherSuite);

    Raised := False;
    try
      Msg.MsgType := htEncryptedExtensions;
      SH := ParseTLS13ServerHelloMessage(Msg);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('non-ServerHello message rejected', Raised);

    Raised := False;
    try
      SH := ParseTLS13ServerHello(nil);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('empty ServerHello body rejected', Raised);
  finally
    TLS13KeyShareFree(KS);
  end;
end;

{ HelloRetryRequest (RFC 8446, 4.1.3): the sentinel random is recognized,
  and a ServerHello-shaped HRR is rejected explicitly — this client does
  not implement a second ClientHello. }
procedure TTLS13Tests.TestServerHelloHelloRetryRequest;
var
  Sentinel, Body, ExtBytes: TBytes;
  Exts: TTLSExtensions;
  Raised: Boolean;
  ErrMsg: string;
begin
  Sentinel := HelloRetryRequestRandom;

  AssertTrue('sentinel random recognized',
    TLS13IsHelloRetryRequest(Sentinel));
  AssertFalse('nil random is not an HRR', TLS13IsHelloRetryRequest(nil));
  AssertFalse('short random is not an HRR',
    TLS13IsHelloRetryRequest(Copy(Sentinel, 0, 31)));
  AssertFalse('ordinary random is not an HRR',
    TLS13IsHelloRetryRequest(HexToBytes(
      '9f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f')));

  { The HRR is refused as soon as the random is read, before any other
    field is interpreted: a body that stops right after it is still
    rejected with the HRR message. }
  Raised := False;
  ErrMsg := '';
  try
    Body := Cat(W16(TLS13LegacyVersion), Sentinel);
    ParseTLS13ServerHello(Body);
  except
    on E: ETLS13Error do
    begin
      Raised := True;
      ErrMsg := E.Message;
    end;
  end;
  AssertTrue('HRR rejected', Raised);
  AssertTrue('error names the HelloRetryRequest',
    Pos('HelloRetryRequest', ErrMsg) > 0);

  { A complete HRR, with the extensions a server would send, is rejected
    the same way. }
  SetLength(Exts, 2);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Exts[1] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(TLS13GroupSecp256r1, HexToBytes('04')));
  ExtBytes := EncodeTLSExtensions(Exts);
  Raised := False;
  try
    Body := BuildServerHelloBodyRaw(Sentinel, nil,
      TLS13CipherAES128GCMSHA256, 0, ExtBytes);
    ParseTLS13ServerHello(Body);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('complete HRR rejected', Raised);
end;

{ Cipher suites outside the three AEAD suites of RFC 8446, B.4 — including
  a TLS 1.2 suite and an unassigned 0x13xx value — are rejected with a
  clear error instead of being mapped onto a hash or an AEAD. }
procedure TTLS13Tests.TestServerHelloUnknownSuite;
var
  Rand, Sess, Body: TBytes;
  SH: TTLS13ServerHello;
  HashKind: THashKind;
  Raised: Boolean;
  ErrMsg: string;
begin
  AssertTrue('0x1301 is supported',
    TLS13CipherSuiteSupported(TLS13CipherAES128GCMSHA256));
  AssertFalse('TLS 1.2 suite 0xC02F is not a TLS 1.3 suite',
    TLS13CipherSuiteSupported($C02F));
  AssertFalse('unassigned 0x1304 is not supported',
    TLS13CipherSuiteSupported($1304));

  Rand := HexToBytes(
    '9f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f');
  Sess := HexToBytes(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');

  { A ServerHello that selects a TLS 1.2 suite. }
  Raised := False;
  ErrMsg := '';
  try
    Body := BuildServerHelloBody(Rand, Sess, $C02F, TLS13GroupSecp256r1,
      HexToBytes('04'));
    SH := ParseTLS13ServerHello(Body);
    AssertFalse('unreachable: 0xC02F must not be accepted',
      SH.CipherSuite = $C02F);
  except
    on E: ETLS13Error do
    begin
      Raised := True;
      ErrMsg := E.Message;
    end;
  end;
  AssertTrue('TLS 1.2 cipher suite in ServerHello rejected', Raised);
  AssertTrue('error names the offending suite',
    Pos('0xc02f', LowerCase(ErrMsg)) > 0);

  { A ServerHello that selects an unassigned 0x1304 suite. }
  Raised := False;
  try
    Body := BuildServerHelloBody(Rand, Sess, $1304, TLS13GroupSecp256r1,
      HexToBytes('04'));
    SH := ParseTLS13ServerHello(Body);
    AssertFalse('unreachable: 0x1304 must not be accepted',
      SH.CipherSuite = $1304);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('unknown 0x1304 suite rejected', Raised);

  { The key schedule never maps an unsupported suite onto a hash. }
  Raised := False;
  try
    HashKind := TLS13CipherSuiteHashKind($C02F);
    AssertEquals('unreachable: no hash for 0xC02F', 0, Ord(HashKind));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('unsupported suite rejected by the key schedule', Raised);
end;

{ Malformed ServerHello bodies (RFC 8446, 4.1.3): every field that can be
  wrong or truncated is checked. }
procedure TTLS13Tests.TestServerHelloGrammarRejections;
var
  Rand, Sess, GoodExt, Good, Bad: TBytes;
  Exts: TTLSExtensions;
  SH: TTLS13ServerHello;
  Raised: Boolean;
begin
  Rand := HexToBytes(
    '9f0e1d2c3b4a5968778695a4b3c2d1e0f0e1d2c3b4a5968778695a4b3c2d1e0f');
  Sess := HexToBytes(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');

  SetLength(Exts, 2);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Exts[1] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(TLS13GroupSecp256r1, HexToBytes('04')));
  GoodExt := EncodeTLSExtensions(Exts);
  Good := BuildServerHelloBodyRaw(Rand, Sess, TLS13CipherAES128GCMSHA256, 0,
    GoodExt);

  { Sanity check: the body used for the negative cases does parse. }
  SH := ParseTLS13ServerHello(Good);
  AssertEquals('well-formed body parses', TLS13CipherAES128GCMSHA256,
    SH.CipherSuite);

  { legacy_version other than 0x0303. }
  Raised := False;
  try
    Bad := Cat(W16($0301), Copy(Good, 2, Length(Good) - 2));
    SH := ParseTLS13ServerHello(Bad);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('legacy_version 0x0301 rejected', Raised);

  { Random truncated before 32 bytes. }
  Raised := False;
  try
    SH := ParseTLS13ServerHello(
      Cat(W16(TLS13LegacyVersion), Copy(Rand, 0, 16)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('truncated random rejected', Raised);

  { Body ending before legacy_session_id_echo. }
  Raised := False;
  try
    SH := ParseTLS13ServerHello(Cat(W16(TLS13LegacyVersion), Rand));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('missing legacy_session_id_echo rejected', Raised);

  { legacy_session_id_echo longer than 32 bytes. }
  Raised := False;
  try
    Bad := Copy(Good, 0, Length(Good));
    Bad[34] := 33;
    SH := ParseTLS13ServerHello(Bad);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('legacy_session_id_echo > 32 bytes rejected', Raised);

  { legacy_compression_method other than 0. }
  Raised := False;
  try
    Bad := BuildServerHelloBodyRaw(Rand, Sess, TLS13CipherAES128GCMSHA256, 1,
      GoodExt);
    SH := ParseTLS13ServerHello(Bad);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('legacy_compression_method 1 rejected', Raised);

  { Extension block shorter than declared. }
  Raised := False;
  try
    SH := ParseTLS13ServerHello(Copy(Good, 0, Length(Good) - 1));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('truncated extension block rejected', Raised);

  { Missing supported_versions. }
  SetLength(Exts, 1);
  Exts[0] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(TLS13GroupSecp256r1, HexToBytes('04')));
  Raised := False;
  try
    SH := ParseTLS13ServerHello(BuildServerHelloBodyRaw(Rand, Sess,
      TLS13CipherAES128GCMSHA256, 0, EncodeTLSExtensions(Exts)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('missing supported_versions rejected', Raised);

  { supported_versions that does not select TLS 1.3. }
  SetLength(Exts, 2);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13LegacyVersion));
  Exts[1] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(TLS13GroupSecp256r1, HexToBytes('04')));
  Raised := False;
  try
    SH := ParseTLS13ServerHello(BuildServerHelloBodyRaw(Rand, Sess,
      TLS13CipherAES128GCMSHA256, 0, EncodeTLSExtensions(Exts)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('server selecting 0x0303 rejected', Raised);

  { Missing key_share. }
  SetLength(Exts, 1);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Raised := False;
  try
    SH := ParseTLS13ServerHello(BuildServerHelloBodyRaw(Rand, Sess,
      TLS13CipherAES128GCMSHA256, 0, EncodeTLSExtensions(Exts)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('missing key_share rejected', Raised);

  { key_share on a named group this client cannot use (secp521r1). }
  SetLength(Exts, 2);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Exts[1] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(25, HexToBytes('04')));
  Raised := False;
  try
    SH := ParseTLS13ServerHello(BuildServerHelloBodyRaw(Rand, Sess,
      TLS13CipherAES128GCMSHA256, 0, EncodeTLSExtensions(Exts)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('unsupported key_share group rejected', Raised);

  { A duplicated extension (RFC 8446, 4.2). }
  SetLength(Exts, 3);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Exts[1] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(TLS13GroupSecp256r1, HexToBytes('04')));
  Exts[2] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Raised := False;
  try
    SH := ParseTLS13ServerHello(BuildServerHelloBodyRaw(Rand, Sess,
      TLS13CipherAES128GCMSHA256, 0, EncodeTLSExtensions(Exts)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('duplicate extension rejected', Raised);
end;

{ EncryptedExtensions (RFC 8446, 4.3.1): an empty vector is legal, an
  allowed extension is kept, and forbidden extensions, duplicates, bad
  lengths and a wrong handshake type are rejected. }
procedure TTLS13Tests.TestEncryptedExtensionsParser;
var
  EE: TTLS13EncryptedExtensions;
  Exts: TTLSExtensions;
  ExtBytes, Body: TBytes;
  Msg: TTLSHandshakeMessage;
  Raised: Boolean;
begin
  EE := ParseTLS13EncryptedExtensions(W16(0));
  AssertEquals('empty extension list', 0, Length(EE.Extensions));

  SetLength(Exts, 1);
  Exts[0] := SimpleExt(TLS13ExtALPN, HexToBytes('00021068'));
  ExtBytes := EncodeTLSExtensions(Exts);
  EE := ParseTLS13EncryptedExtensions(ExtBytes);
  AssertEquals('one extension', 1, Length(EE.Extensions));
  AssertEquals('ALPN type', TLS13ExtALPN, EE.Extensions[0].ExtType);
  AssertEquals('ALPN data', '00021068', BytesToHex(EE.Extensions[0].Data));

  Msg.MsgType := htEncryptedExtensions;
  Msg.Body := ExtBytes;
  EE := ParseTLS13EncryptedExtensionsMessage(Msg);
  AssertEquals('message overload', 1, Length(EE.Extensions));

  { Rejections. }
  Raised := False;
  try
    EE := ParseTLS13EncryptedExtensions(nil);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('missing extension block rejected', Raised);

  Raised := False;
  try
    EE := ParseTLS13EncryptedExtensions(B1(0));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('short extension block rejected', Raised);

  Raised := False;
  try
    Body := Cat(W16(3), HexToBytes('aabb'));
    EE := ParseTLS13EncryptedExtensions(Body);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('declared block length mismatch rejected', Raised);

  SetLength(Exts, 2);
  Exts[0] := SimpleExt(TLS13ExtALPN, HexToBytes('0002'));
  Exts[1] := SimpleExt(TLS13ExtALPN, HexToBytes('0002'));
  Raised := False;
  try
    EE := ParseTLS13EncryptedExtensions(EncodeTLSExtensions(Exts));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('duplicate extension rejected', Raised);

  SetLength(Exts, 1);
  Exts[0] := SimpleExt(TLS13ExtSupportedVersions, W16(TLS13Version));
  Raised := False;
  try
    EE := ParseTLS13EncryptedExtensions(EncodeTLSExtensions(Exts));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('supported_versions in EncryptedExtensions rejected', Raised);

  SetLength(Exts, 1);
  Exts[0] := SimpleExt(TLS13ExtKeyShare,
    TLS13EncodeKeyShareEntry(TLS13GroupSecp256r1, HexToBytes('04')));
  Raised := False;
  try
    EE := ParseTLS13EncryptedExtensions(EncodeTLSExtensions(Exts));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('key_share in EncryptedExtensions rejected', Raised);

  Raised := False;
  try
    Msg.MsgType := htServerHello;
    Msg.Body := ExtBytes;
    EE := ParseTLS13EncryptedExtensionsMessage(Msg);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('non-EncryptedExtensions message rejected', Raised);
end;

{ Certificate (RFC 8446, 4.4.2): the TLS 1.3 body
  certificate_request_context || certificate_list, with real DER
  certificates from tests/fixtures, and the rejections of an empty list,
  a non-empty context, truncated entries and bad length prefixes. }
procedure TTLS13Tests.TestCertificateParser;
var
  Leaf, Ca, Entry1, Entry2, Body: TBytes;
  Cert: TTLS13Certificate;
  Msg: TTLSHandshakeMessage;
  Raised: Boolean;
begin
  Leaf := LoadFixtureBytes('leaf_ec.der');
  Ca := LoadFixtureBytes('ca_ec.der');
  if (Length(Leaf) = 0) or (Length(Ca) = 0) then
    Exit;   { fixtures are missing — nothing to parse }

  Entry1 := Cat(W24(Length(Leaf)), Cat(Leaf, W16(0)));
  Body := Cat(B1(0), Cat(W24(Length(Entry1)), Entry1));
  Cert := ParseTLS13Certificate(Body);
  AssertEquals('empty certificate_request_context', 0,
    Length(Cert.RequestContext));
  AssertEquals('one entry', 1, Length(Cert.Entries));
  AssertEquals('leaf DER', BytesToHex(Leaf),
    BytesToHex(Cert.Entries[0].Certificate));
  AssertEquals('no entry extensions', 0, Length(Cert.Entries[0].Extensions));

  { Two entries: the leaf first, the issuer after it. }
  Entry2 := Cat(W24(Length(Ca)), Cat(Ca, W16(0)));
  Body := Cat(B1(0), Cat(W24(Length(Entry1) + Length(Entry2)),
    Cat(Entry1, Entry2)));
  Cert := ParseTLS13Certificate(Body);
  AssertEquals('two entries', 2, Length(Cert.Entries));
  AssertEquals('entry[0] = leaf', BytesToHex(Leaf),
    BytesToHex(Cert.Entries[0].Certificate));
  AssertEquals('entry[1] = issuer', BytesToHex(Ca),
    BytesToHex(Cert.Entries[1].Certificate));

  Msg.MsgType := htCertificate;
  Msg.Body := Body;
  Cert := ParseTLS13CertificateMessage(Msg);
  AssertEquals('message overload', 2, Length(Cert.Entries));

  Raised := False;
  try
    Msg.MsgType := htServerHello;
    Cert := ParseTLS13CertificateMessage(Msg);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('non-Certificate message rejected', Raised);

  { An empty certificate_list (RFC 8446, 4.4.2: the server MUST NOT). }
  Raised := False;
  try
    Cert := ParseTLS13Certificate(Cat(B1(0), W24(0)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('empty certificate_list rejected', Raised);

  { A non-empty certificate_request_context cannot belong to 1-RTT. }
  Raised := False;
  try
    Cert := ParseTLS13Certificate(HexToBytes('0100'));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('non-empty certificate_request_context rejected', Raised);

  { certificate_list length that does not match the body. }
  Raised := False;
  try
    Cert := ParseTLS13Certificate(
      Cat(B1(0), Cat(W24(Length(Entry1) + 1), Entry1)));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('certificate_list length mismatch rejected', Raised);

  { An entry with an empty cert_data. }
  Raised := False;
  try
    Cert := ParseTLS13Certificate(
      Cat(B1(0), Cat(W24(5), Cat(W24(0), W16(0)))));
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('empty cert_data rejected', Raised);

  { An entry that stops before its extension block. }
  Raised := False;
  try
    Body := Cat(B1(0), Cat(W24(Length(Leaf) + 3),
      Cat(W24(Length(Leaf)), Leaf)));
    Cert := ParseTLS13Certificate(Body);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('missing entry extension block rejected', Raised);

  { An entry whose extension block overruns the list. }
  Raised := False;
  try
    Body := Cat(B1(0), Cat(W24(Length(Leaf) + 6),
      Cat(W24(Length(Leaf)), Cat(W16(5), B1(0)))));
    Cert := ParseTLS13Certificate(Body);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('entry extension length mismatch rejected', Raised);
end;

{ Certificate chain (RFC 8446, 4.4.2.2): the parsed TLS 1.3
  certificate_list is handed to the shared TLS 1.2 chain builder, and a
  trust store either accepts the chain or makes it fail. }
procedure TTLS13Tests.TestTLS13CertificateChain;
var
  Leaf, Ca, Entry1, Entry2, Body: TBytes;
  Cert: TTLS13Certificate;
  Chain: TTLS12CertChain;
  Store: TCertStore;
  Root: TX509Cert;
  VR: TVerifyResult;
  Raised: Boolean;
begin
  Leaf := LoadFixtureBytes('leaf_ec.der');
  Ca := LoadFixtureBytes('ca_ec.der');
  if (Length(Leaf) = 0) or (Length(Ca) = 0) then
    Exit;

  Entry1 := Cat(W24(Length(Leaf)), Cat(Leaf, W16(0)));
  Entry2 := Cat(W24(Length(Ca)), Cat(Ca, W16(0)));
  Body := Cat(B1(0), Cat(W24(Length(Entry1) + Length(Entry2)),
    Cat(Entry1, Entry2)));
  Cert := ParseTLS13Certificate(Body);

  Chain := TLS13CertificateChain(Cert);
  try
    AssertEquals('chain length', 2, Chain.Count);
  finally
    Chain.Free;
  end;

  { A trust store holding the issuer accepts the chain ... }
  Root := ParseCertificate(Ca);
  Store := TCertStore.Create;
  try
    Store.Add(Root);
    VR := VerifyTLS13Certificate(Cert, Store);
    AssertTrue('trusted chain verifies', VR.OK);
    AssertEquals('no failure reason', '', VR.Reason);
    CheckTLS13Certificate(Cert, Store);
  finally
    Store.Free;
    Root.Free;
  end;

  { ... while an unrelated CA makes it fail and Check raises. }
  Root := ParseCertificate(LoadFixtureBytes('ca_rsa.der'));
  Store := TCertStore.Create;
  try
    Store.Add(Root);
    VR := VerifyTLS13Certificate(Cert, Store);
    AssertFalse('untrusted chain rejected', VR.OK);
    AssertTrue('reason mentions the issuer',
      Pos('issuer', LowerCase(VR.Reason)) > 0);

    Raised := False;
    try
      CheckTLS13Certificate(Cert, Store);
    except
      on E: ETLS13Error do Raised := True;
    end;
    AssertTrue('CheckTLS13Certificate raises on an untrusted chain', Raised);
  finally
    Store.Free;
    Root.Free;
  end;
end;

{ CertificateVerify content (RFC 8446, 4.4.3):
  0x20 * 64 || context string || 0x00 || Transcript-Hash. }
procedure TTLS13Tests.TestCertificateVerifyContent;
const
  THASH = 'f2267da2d4d49a4c715b424a314f1e9285887db82c11932c4d6eab35d4d8d277';
var
  Pad, Hash, Expected, Content: TBytes;
  Raised: Boolean;
begin
  Hash := HexToBytes(THASH);
  SetLength(Pad, 64);
  FillChar(Pad[0], 64, $20);

  Expected := Cat3(Pad,
    StrBytes(TLS13ContextStringServerCertificateVerify), B1(0));
  Expected := Cat(Expected, Hash);
  Content := TLS13CertificateVerifyContent(
    TLS13ContextStringServerCertificateVerify, Hash);
  AssertEquals('CertificateVerify content', BytesToHex(Expected),
    BytesToHex(Content));

  { The server and the client context strings give different content, so a
    signature made for one role can never be replayed in the other. }
  AssertFalse('client context differs',
    BytesToHex(Content) = BytesToHex(TLS13CertificateVerifyContent(
      TLS13ContextStringClientCertificateVerify, Hash)));

  { The FromTranscript variant hashes the raw transcript first. }
  AssertEquals('FromTranscript applies Transcript-Hash',
    BytesToHex(TLS13ServerCertificateVerifyContent(hkSHA256,
      TLS13TranscriptHash(hkSHA256, HexToBytes('deadbeef')))),
    BytesToHex(TLS13CertificateVerifyContentFromTranscript(
      TLS13ContextStringServerCertificateVerify, hkSHA256,
      HexToBytes('deadbeef'))));

  { An empty context string would leave the signature unbound to its role. }
  Raised := False;
  try
    Content := TLS13CertificateVerifyContent('', Hash);
  except
    on E: ETLS13Error do Raised := True;
  end;
  AssertTrue('empty context string rejected', Raised);
end;

{ CertificateVerify signature verification (RFC 8446, 4.4.3):
  - the two openssl-generated reference signatures below must verify;
  - every "bad CertificateVerify" — the wrong scheme, a key on the wrong
    curve, a non-matching key type, tampered content, a flipped or
    truncated signature — must be refused, never silently accepted.

  References (independent of this library) over the content
      0x20 * 64 || "TLS 1.3, server CertificateVerify" || 0x00 ||
      SHA-256("tls13 test transcript"):
      openssl dgst -sha256 -sign tests/fixtures/leaf_ec.key \
        -out ec.sig content
      openssl dgst -sha256 -sigopt rsa_padding_mode:pss \
        -sigopt rsa_pss_saltlen:32 -sign tests/fixtures/leaf_rsa.key \
        -out rsa.sig content
  with SHA-256("tls13 test transcript") =
      f2267da2d4d49a4c715b424a314f1e9285887db82c11932c4d6eab35d4d8d277.

  Both signatures are tied to the fixture keys, so they are regenerated
  whenever `make fixtures` rebuilds the certificates. }
procedure TTLS13Tests.TestCertificateVerifySignatures;
const
  THASH = 'f2267da2d4d49a4c715b424a314f1e9285887db82c11932c4d6eab35d4d8d277';
  EC_SIG =
    '304602210098d289f8daa044bb216114ad8b8267b3d4ab222e0b6e400078017d934ea0186502210088aed4df5044f2ab505f4d9403e86904503d16962faffc2633507e062a0a1481';
  RSA_SIG =
    'd309fb9334054cf1d946206f35feaf1766a10efc100b912abe050acb14de0e9b8265dbf4ddd1d41b6f7eeb3e8e4a5eea325418595510f6c03222c6a29553e1e8e46038e9b19f1e19f0158810741235f0d380dc906ba4bf37d86ef596330bb0dd8cb9e14ce5049c3fcbba48452a47461fc3ecdea41d41a76034d1ed984cb800259b3c8bfd7ce1677d6a2bd1c20929859277abb1a3b0202f6654ebfae43ab9263b64715fd033822150a0f17ae030f83825d5cc4e417e83f2787dbdfdb1a809631ac3199e911c08dca01eef3e0edb525993b3e68c3810df6b6c9392a3a9d2d3b5f4028acd6f55e80cf141d0fa645e5174f0c96c06d67f966c5a06e85197a399ea0c';
var
  LeafEC, LeafRSA: TX509Cert;
  Content, ECSig, RSASig, Bad, Zeros: TBytes;
begin
  if (Length(LoadFixtureBytes('leaf_ec.der')) = 0) or
     (Length(LoadFixtureBytes('leaf_rsa.der')) = 0) then
    Exit;   { fixtures are missing — nothing to verify }

  LeafEC := ParseCertificate(LoadFixtureBytes('leaf_ec.der'));
  LeafRSA := ParseCertificate(LoadFixtureBytes('leaf_rsa.der'));
  Content := TLS13CertificateVerifyContent(
    TLS13ContextStringServerCertificateVerify, HexToBytes(THASH));
  ECSig := HexToBytes(EC_SIG);
  RSASig := HexToBytes(RSA_SIG);
  try
    { Positive checks against the openssl-generated references. }
    AssertTrue('openssl ECDSA P-256 signature verifies',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        Content, ECSig));
    AssertTrue('openssl RSA-PSS-SHA256 signature verifies',
      VerifyTLS13RSAPSSSignature(LeafRSA, TLSSigRSA_PSS_RSAE_SHA256,
        Content, RSASig));

    { --- Bad CertificateVerify: everything must be refused. --- }
    AssertFalse('nil certificate (ECDSA)',
      VerifyTLS13ECDSASignature(nil, TLSSigECDSA_Secp256r1_SHA256,
        Content, ECSig));
    AssertFalse('nil certificate (RSA-PSS)',
      VerifyTLS13RSAPSSSignature(nil, TLSSigRSA_PSS_RSAE_SHA256,
        Content, RSASig));
    AssertFalse('empty content (ECDSA)',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        nil, ECSig));
    AssertFalse('empty content (RSA-PSS)',
      VerifyTLS13RSAPSSSignature(LeafRSA, TLSSigRSA_PSS_RSAE_SHA256,
        nil, RSASig));
    AssertFalse('empty signature (ECDSA)',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        Content, nil));
    AssertFalse('empty signature (RSA-PSS)',
      VerifyTLS13RSAPSSSignature(LeafRSA, TLSSigRSA_PSS_RSAE_SHA256,
        Content, nil));

    { A scheme this client never advertises. }
    AssertFalse('rsa_pkcs1_sha256 is not a TLS 1.3 scheme',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigRSA_PKCS1_SHA256,
        Content, ECSig));
    AssertFalse('rsa_pkcs1_sha256 rejected by the PSS path',
      VerifyTLS13RSAPSSSignature(LeafRSA, TLSSigRSA_PKCS1_SHA256,
        Content, RSASig));
    AssertFalse('rsa_pss_rsae_sha384 rejected',
      VerifyTLS13RSAPSSSignature(LeafRSA, TLSSigRSA_PSS_RSAE_SHA384,
        Content, RSASig));
    AssertFalse('ed25519 rejected',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigEd25519, Content, ECSig));

    { A key that does not match the scheme. }
    AssertFalse('P-384 scheme with a P-256 key',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp384r1_SHA384,
        Content, ECSig));
    AssertFalse('RSA key with an ECDSA scheme',
      VerifyTLS13ECDSASignature(LeafRSA, TLSSigECDSA_Secp256r1_SHA256,
        Content, ECSig));
    AssertFalse('EC key with RSA-PSS',
      VerifyTLS13RSAPSSSignature(LeafEC, TLSSigRSA_PSS_RSAE_SHA256,
        Content, RSASig));

    { Tampered content, tampered signatures, truncation. }
    Bad := Copy(Content, 0, Length(Content));
    Bad[64] := Bad[64] xor $01;   { inside the context string }
    AssertFalse('tampered content',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        Bad, ECSig));
    AssertFalse('content built for the client role rejected',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        TLS13ClientCertificateVerifyContent(hkSHA256, HexToBytes(THASH)),
        ECSig));

    Bad := Copy(ECSig, 0, Length(ECSig));
    Bad[Length(Bad) - 1] := Bad[Length(Bad) - 1] xor $01;
    AssertFalse('tampered ECDSA signature',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        Content, Bad));
    Bad := Copy(RSASig, 0, Length(RSASig));
    Bad[0] := Bad[0] xor $80;
    AssertFalse('tampered RSA-PSS signature',
      VerifyTLS13RSAPSSSignature(LeafRSA, TLSSigRSA_PSS_RSAE_SHA256,
        Content, Bad));

    AssertFalse('truncated ECDSA signature',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        Content, Copy(ECSig, 0, 10)));
    AssertFalse('malformed DER ECDSA signature',
      VerifyTLS13ECDSASignature(LeafEC, TLSSigECDSA_Secp256r1_SHA256,
        Content, HexToBytes('3000')));
    SetLength(Zeros, 256);
    FillChar(Zeros[0], 256, 0);
    AssertFalse('all-zero RSA signature',
      VerifyTLS13RSAPSSSignature(LeafRSA, TLSSigRSA_PSS_RSAE_SHA256,
        Content, Zeros));
  finally
    LeafEC.Free;
    LeafRSA.Free;
  end;
end;

initialization
  RegisterTest(TTLS13Tests);

end.
