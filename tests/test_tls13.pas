{ SPDX-License-Identifier: Apache-2.0 }
unit test_tls13;
{TLS 1.3 (RFC 8446) unit tests: HKDF (RFC 5869), HKDF-Expand-Label, the
  key schedule (checked against the RFC 8448 §3 values and against an
  independent Python reference), the record layer (nonce, AAD, AEAD
  round-trip and tamper rejection), the handshake message encoders/parsers
  and CertificateVerify. The full client handshake against a real server is
  covered by test_tls13_e2e.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TTLS13Tests = class(TTestCase)
  published
    { --- HKDF (RFC 5869) --- }
    procedure TestHKDFRFC5869TestCase1;
    procedure TestHKDFRFC5869TestCase3;
    procedure TestHKDFExpandLabelLengthField;

    { --- key schedule --- }
    procedure TestKeyScheduleRFC8448Intermediates;
    procedure TestKeyScheduleTrafficSecrets;
    procedure TestTrafficKeys;
    procedure TestFinishedVerifyData;

    { --- record layer --- }
    procedure TestNonceXorSeq;
    procedure TestRecordAAD;
    procedure TestRecordRoundTripAllSuites;
    procedure TestRecordTamperRejected;
    procedure TestRecordWrongSequenceRejected;
    procedure TestRecordInnerContentType;

    { --- ClientHello --- }
    procedure TestClientHelloDefaults;
    procedure TestClientHelloStructure;
    procedure TestClientHelloRejectsUnsupportedSuite;

    { --- ServerHello --- }
    procedure TestParseServerHello;
    procedure TestParseServerHelloHelloRetryRequest;
    procedure TestParseServerHelloWithoutKeyShare;

    { --- Certificate and CertificateVerify --- }
    procedure TestParseCertificateMessage;
    procedure TestParseCertificateRejectsTruncated;
    procedure TestCertificateVerifyContentPrefix;
    procedure TestFinishedBody;
  end;

implementation

uses
  SysUtils, Classes, tls.tls13, tls.tls12, tls.sha2, tls.hmac, tls.ec;

{ ==================================================================== }
{ Helpers                                                              }
{ ==================================================================== }

function W16(AValue: Word): TBytes;
begin
  SetLength(Result, 2);
  Result[0] := Byte((AValue shr 8) and $FF);
  Result[1] := Byte(AValue and $FF);
end;

function B1(AValue: Byte): TBytes;
begin
  SetLength(Result, 1);
  Result[0] := AValue;
end;

function Triple(AValue: LongWord): TBytes;
begin
  SetLength(Result, 3);
  Result[0] := Byte((AValue shr 16) and $FF);
  Result[1] := Byte((AValue shr 8) and $FF);
  Result[2] := Byte(AValue and $FF);
end;

function Cat(const A, B: TBytes): TBytes;
begin
  SetLength(Result, Length(A) + Length(B));
  if Length(A) > 0 then
    Move(A[0], Result[0], Length(A));
  if Length(B) > 0 then
    Move(B[0], Result[Length(A)], Length(B));
end;

function SeqBytes(ACount: Integer; AStart: Byte): TBytes;
var
  i: Integer;
begin
  SetLength(Result, ACount);
  for i := 0 to ACount - 1 do
    Result[i] := Byte((AStart + i) and $FF);
end;

function StrBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

function BytesEqual(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and
    ((Length(A) = 0) or CompareMem(@A[0], @B[0], Length(A)));
end;

function RepeatByte(AByte: Byte; ACount: Integer): TBytes;
begin
  SetLength(Result, ACount);
  if ACount > 0 then
    FillChar(Result[0], ACount, AByte);
end;

function FixturePath(const AName: string): string;
begin
  Result := ExtractFilePath(ParamStr(0)) + '..' + PathDelim + 'tests' +
    PathDelim + 'fixtures' + PathDelim + AName;
  if not FileExists(Result) then
    Result := 'tests' + PathDelim + 'fixtures' + PathDelim + AName;
end;

function ReadFileBytes(const APath: string): TBytes;
var
  FS: TFileStream;
begin
  FS := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
  try
    SetLength(Result, FS.Size);
    if FS.Size > 0 then
      FS.ReadBuffer(Result[0], FS.Size);
  finally
    FS.Free;
  end;
end;

function EncodeExtensions(const AExts: TTLSExtensions): TBytes;
begin
  Result := EncodeTLSExtensions(AExts);
end;

{ ==================================================================== }
{ HKDF                                                                 }
{ ==================================================================== }

procedure TTLS13Tests.TestHKDFRFC5869TestCase1;
var
  IKM, Salt, Info, PRK, OKM: TBytes;
begin
  { RFC 5869, Appendix A.1 (SHA-256). }
  IKM := RepeatByte($0b, 22);
  Salt := HexToBytes('000102030405060708090a0b0c');
  Info := HexToBytes('f0f1f2f3f4f5f6f7f8f9');

  PRK := HKDFExtract(hkSHA256, Salt, IKM);
  AssertEquals('PRK', '077709362c2e32df0ddc3f0dc47bba63' +
    '90b6c73bb50f9c3122ec844ad7c2b3e5', BytesToHex(PRK));

  OKM := HKDFExpand(hkSHA256, PRK, Info, 42);
  AssertEquals('OKM', '3cb25f25faacd57a90434f64d0362f2a' +
    '2d2d0a90cf1a5a4c5db02d56ecc4c5bf' +
    '34007208d5b887185865', BytesToHex(OKM));
end;

procedure TTLS13Tests.TestHKDFRFC5869TestCase3;
var
  IKM, PRK, OKM: TBytes;
begin
  { RFC 5869, Appendix A.3: zero-length salt and info (SHA-256). }
  IKM := RepeatByte($0b, 22);
  PRK := HKDFExtract(hkSHA256, nil, IKM);
  AssertEquals('PRK', '19ef24a32c717b167f33a91d6f648bdf' +
    '96596776afdb6377ac434c1c293ccb04', BytesToHex(PRK));
  OKM := HKDFExpand(hkSHA256, PRK, nil, 42);
  AssertEquals('OKM', '8da4e775a563c18f715f802a063c5a31' +
    'b8a11f5c5ee1879ec3454e5f3c738d2d' +
    '9d201395faa4b61a96c8', BytesToHex(OKM));
end;

procedure TTLS13Tests.TestHKDFExpandLabelLengthField;
var
  Secret, Context, Key: TBytes;
begin
  { HKDF-Expand-Label encoding of the "key" label is exercised through the
    traffic-key derivation in TestTrafficKeys. Here we check the "derived"
    label against the RFC 8448 §3 value: derived = 6f2615a1... }
  Secret := HexToBytes('33ad0a1c607ec03b09e6cd9893680ce2' +
    '10adf300aa1f2660e1b22e10f170f92a');
  Context := SHA256(nil);
  Key := HKDFExpandLabel(hkSHA256, Secret, 'derived', Context, 32);
  AssertEquals('derived', '6f2615a108c702c5678f54fc9dbab697' +
    '16c076189c48250cebeac3576c3611ba', BytesToHex(Key));
end;

{ ==================================================================== }
{ Key schedule                                                         }
{ ==================================================================== }

procedure TTLS13Tests.TestKeyScheduleRFC8448Intermediates;
var
  Early, Derived, Shared, Handshake: TBytes;
begin
  { RFC 8448 §3 "Simple 1-RTT Handshake": the shared secret and the first
    key-schedule steps. }
  Early := TLS13EarlySecret(hkSHA256);
  AssertEquals('early_secret', '33ad0a1c607ec03b09e6cd9893680ce2' +
    '10adf300aa1f2660e1b22e10f170f92a', BytesToHex(Early));

  Derived := TLS13DeriveSecret(hkSHA256, Early, 'derived', nil);
  AssertEquals('derived_secret', '6f2615a108c702c5678f54fc9dbab697' +
    '16c076189c48250cebeac3576c3611ba', BytesToHex(Derived));

  Shared := HexToBytes('8bd4054fb55b9d63fdfbacf9f04b9f0d' +
    '35e6d63f537563efd46272900f89492d');
  Handshake := TLS13HandshakeSecret(hkSHA256, Shared);
  AssertEquals('handshake_secret', '1dc826e93606aa6fdc0aadc12f741b01' +
    '046aa6b99f691ed221a9f0ca043fbeac', BytesToHex(Handshake));
end;

procedure TTLS13Tests.TestKeyScheduleTrafficSecrets;
var
  Shared, Handshake, Master, Transcript: TBytes;
  ExpectedC, ExpectedS: string;
begin
  { Expected values computed with an independent Python reference
    (hmac+hashlib) using the RFC 8448 §3 shared secret; the early/derived/
    handshake intermediates above match the RFC itself. }
  Shared := HexToBytes('8bd4054fb55b9d63fdfbacf9f04b9f0d' +
    '35e6d63f537563efd46272900f89492d');
  Handshake := TLS13HandshakeSecret(hkSHA256, Shared);
  Master := TLS13MasterSecret(hkSHA256, Handshake);
  Transcript := StrBytes('ClientHello...ServerHello');

  AssertEquals('master_secret',
    '18df06843d13a08bf2a449844c5f8a47' +
    '8001bc4d4c627984d5a41da8d0402919', BytesToHex(Master));

  ExpectedC := '28a36648aa4c89e33bf53faa0471afc9' +
    '7acfc52462f59aac630b1501c99d0186';
  ExpectedS := '1d32ec46d267839f856ee5b40776047e' +
    'eb558a85b0460d897d22580f9c288608';
  AssertEquals('c hs traffic', ExpectedC,
    BytesToHex(TLS13TrafficSecret(hkSHA256, Handshake, 'c hs traffic',
      Transcript)));
  AssertEquals('s hs traffic', ExpectedS,
    BytesToHex(TLS13TrafficSecret(hkSHA256, Handshake, 's hs traffic',
      Transcript)));

  AssertEquals('c ap traffic',
    'd2509f4ef09dc86d84d0fa2cd8f88c78' +
    '69cbf3419afde72c74db469d184e5985',
    BytesToHex(TLS13TrafficSecret(hkSHA256, Master, 'c ap traffic',
      Transcript)));
  AssertEquals('s ap traffic',
    '99d1a32888bcc3c0c359ec7a671cbf28' +
    '548d16e4b0f6760675d3d711cabd31b5',
    BytesToHex(TLS13TrafficSecret(hkSHA256, Master, 's ap traffic',
      Transcript)));
end;

procedure TTLS13Tests.TestTrafficKeys;
var
  Secret: TBytes;
  Keys: TTLS13TrafficKeys;
begin
  Secret := HexToBytes('28a36648aa4c89e33bf53faa0471afc9' +
    '7acfc52462f59aac630b1501c99d0186');
  Keys := TLS13TrafficKeys(hkSHA256, aeadAES128GCM, Secret);
  AssertEquals('client hs key', 'd1907171623b1db5fa071963b21028f1',
    BytesToHex(Keys.Key));
  AssertEquals('client hs iv', '51a723898c92b56c72a66993',
    BytesToHex(Keys.IV));
end;

procedure TTLS13Tests.TestFinishedVerifyData;
var
  Secret, Transcript, VD: TBytes;
begin
  Secret := HexToBytes('1dc826e93606aa6fdc0aadc12f741b01' +
    '046aa6b99f691ed221a9f0ca043fbeac');
  Transcript := StrBytes('ClientHello...CertificateVerify');
  VD := TLS13FinishedVerifyData(hkSHA256, Secret, Transcript);
  AssertEquals('verify_data',
    '96c802ecfd09742458c571fb19432a8c' +
    '5189a4426dfd35277689e8c65f7acb74', BytesToHex(VD));
end;

{ ==================================================================== }
{ Record layer                                                         }
{ ==================================================================== }

procedure TTLS13Tests.TestNonceXorSeq;
var
  IV, Nonce: TBytes;
begin
  IV := HexToBytes('000102030405060708090a0b');
  Nonce := TLS13Nonce(IV, QWord($0102030405060708));
  AssertEquals('nonce', '00010203050705030d0f0d03', BytesToHex(Nonce));
end;

procedure TTLS13Tests.TestRecordAAD;
var
  AAD: TBytes;
begin
  AAD := TLS13RecordAAD(23, 100);
  AssertEquals('AAD', '1703030064', BytesToHex(AAD));
end;

procedure TTLS13Tests.TestRecordRoundTripAllSuites;
var
  Plain, Fragment, Got: TBytes;
  Ct: TTLSContentType;
  Key16, Key32, IV: TBytes;
begin
  Plain := StrBytes('GET / HTTP/1.0'#13#10#13#10);
  Key16 := SeqBytes(16, 1);
  Key32 := SeqBytes(32, 1);
  IV := SeqBytes(12, $10);

  Fragment := TLS13ProtectRecord(aeadAES128GCM, Key16, IV, 0,
    ctApplicationData, Plain);
  AssertTrue('AES-128-GCM decrypt',
    TLS13UnprotectRecord(aeadAES128GCM, Key16, IV, 0, Fragment, Ct, Got));
  AssertTrue('AES-128-GCM type', Ct = ctApplicationData);
  AssertTrue('AES-128-GCM data', BytesEqual(Plain, Got));

  Fragment := TLS13ProtectRecord(aeadAES256GCM, Key32, IV, 7,
    ctApplicationData, Plain);
  AssertTrue('AES-256-GCM decrypt',
    TLS13UnprotectRecord(aeadAES256GCM, Key32, IV, 7, Fragment, Ct, Got));
  AssertTrue('AES-256-GCM data', BytesEqual(Plain, Got));

  Fragment := TLS13ProtectRecord(aeadChaCha20Poly1305, Key32, IV, 9,
    ctApplicationData, Plain);
  AssertTrue('ChaCha20 decrypt',
    TLS13UnprotectRecord(aeadChaCha20Poly1305, Key32, IV, 9, Fragment,
      Ct, Got));
  AssertTrue('ChaCha20 data', BytesEqual(Plain, Got));
end;

procedure TTLS13Tests.TestRecordTamperRejected;
var
  Plain, Fragment, Got: TBytes;
  Ct: TTLSContentType;
  Key, IV: TBytes;
begin
  Plain := StrBytes('secret');
  Key := SeqBytes(16, 1);
  IV := SeqBytes(12, $10);
  Fragment := TLS13ProtectRecord(aeadAES128GCM, Key, IV, 3,
    ctApplicationData, Plain);
  Fragment[0] := Fragment[0] xor $01;
  AssertFalse('tampered ciphertext rejected',
    TLS13UnprotectRecord(aeadAES128GCM, Key, IV, 3, Fragment, Ct, Got));

  Fragment := TLS13ProtectRecord(aeadAES128GCM, Key, IV, 3,
    ctApplicationData, Plain);
  Fragment[Length(Fragment) - 1] :=
    Fragment[Length(Fragment) - 1] xor $01;
  AssertFalse('tampered tag rejected',
    TLS13UnprotectRecord(aeadAES128GCM, Key, IV, 3, Fragment, Ct, Got));
end;

procedure TTLS13Tests.TestRecordWrongSequenceRejected;
var
  Plain, Fragment, Got: TBytes;
  Ct: TTLSContentType;
  Key, IV: TBytes;
begin
  Plain := StrBytes('secret');
  Key := SeqBytes(16, 1);
  IV := SeqBytes(12, $10);
  Fragment := TLS13ProtectRecord(aeadAES128GCM, Key, IV, 3,
    ctApplicationData, Plain);
  AssertFalse('wrong seq rejected',
    TLS13UnprotectRecord(aeadAES128GCM, Key, IV, 4, Fragment, Ct, Got));
end;

procedure TTLS13Tests.TestRecordInnerContentType;
var
  Plain, Fragment, Got: TBytes;
  Ct: TTLSContentType;
  Key, IV: TBytes;
begin
  Plain := StrBytes('alert');
  Key := SeqBytes(16, 2);
  IV := SeqBytes(12, $20);
  Fragment := TLS13ProtectRecord(aeadAES128GCM, Key, IV, 0, ctAlert, Plain);
  AssertTrue('decrypt alert',
    TLS13UnprotectRecord(aeadAES128GCM, Key, IV, 0, Fragment, Ct, Got));
  AssertTrue('inner type alert', Ct = ctAlert);
  AssertTrue('alert payload', BytesEqual(Plain, Got));
end;

{ ==================================================================== }
{ ClientHello                                                          }
{ ==================================================================== }

procedure TTLS13Tests.TestClientHelloDefaults;
var
  Suites: TTLSCipherSuites;
  Groups: TTLSNamedGroups;
  Sigs: TTLSSignatureSchemes;
begin
  Suites := TLS13DefaultCipherSuites;
  AssertEquals('3 suites', 3, Length(Suites));
  AssertEquals('AES-128', 'TLS_AES_128_GCM_SHA256',
    TLS13CipherSuiteName(Suites[0]));
  AssertEquals('AES-256', 'TLS_AES_256_GCM_SHA384',
    TLS13CipherSuiteName(Suites[1]));
  AssertEquals('ChaCha20', 'TLS_CHACHA20_POLY1305_SHA256',
    TLS13CipherSuiteName(Suites[2]));

  Groups := TLS13DefaultSupportedGroups;
  AssertEquals('X25519 first', TLSNamedGroupX25519, Groups[0]);

  Sigs := TLS13DefaultSignatureAlgorithms;
  AssertTrue('ECDSA P-256 present',
    Sigs[0] = TLSSigECDSA_Secp256r1_SHA256);
  AssertTrue('RSA-PSS SHA-256 present',
    Sigs[2] = TLSSigRSA_PSS_RSAE_SHA256);
end;

procedure TTLS13Tests.TestClientHelloStructure;
var
  Options: TTLS13ClientHelloOptions;
  Body: TBytes;
  Parsed: TTLSClientHello;
  Ext: TTLSExtension;
  Share: TBytes;
  Group: Word;
begin
  Options := Default(TTLS13ClientHelloOptions);
  Options.ServerName := 'localhost';
  Options.ClientRandom := SeqBytes(32, 1);
  Options.SessionID := SeqBytes(32, $80);
  SetLength(Options.KeyShares, 1);
  Options.KeyShares[0].Group := TLSNamedGroupX25519;
  Options.KeyShares[0].KeyExchange := SeqBytes(32, $40);
  Options.PskKeyExchangeModes := True;
  Body := TLS13BuildClientHelloBody(Options);

  Parsed := ParseTLS12ClientHello(Body);
  AssertEquals('legacy version', TLS13LegacyVersion, Parsed.Version);
  AssertEquals('SNI', 'localhost', Parsed.ServerName);
  AssertEquals('session id', 32, Length(Parsed.SessionID));
  AssertEquals('suite count', 3, Length(Parsed.CipherSuites));
  AssertEquals('first suite', TLSCipherAES128GCM_SHA256,
    Parsed.CipherSuites[0]);
  AssertTrue('supported_groups',
    FindTLSExtension(Parsed.Extensions, TLSExtSupportedGroups, Ext));

  AssertTrue('supported_versions present',
    FindTLSExtension(Parsed.Extensions, TLSExtSupportedVersions, Ext));
  AssertEquals('supported_versions data', '020304', BytesToHex(Ext.Data));

  AssertTrue('key_share present',
    FindTLSExtension(Parsed.Extensions, TLSExtKeyShare, Ext));
  { key_share extension data = client_shares<2> || KeyShareEntry, so the
    group starts after the two-byte vector length. }
  Share := Ext.Data;
  AssertEquals('share list length', 36,
    (Integer(Share[0]) shl 8) or Integer(Share[1]));
  Group := (Word(Share[2]) shl 8) or Word(Share[3]);
  AssertEquals('key share group', TLSNamedGroupX25519, Group);
  AssertEquals('key share length', 32,
    (Integer(Share[4]) shl 8) or Integer(Share[5]));

  AssertTrue('psk_key_exchange_modes',
    FindTLSExtension(Parsed.Extensions, TLSExtPSKKeyExchangeModes, Ext));
  AssertEquals('psk mode dhe', '0101', BytesToHex(Ext.Data));
end;

procedure TTLS13Tests.TestClientHelloRejectsUnsupportedSuite;
var
  Options: TTLS13ClientHelloOptions;
  Raised: Boolean;
begin
  Options := Default(TTLS13ClientHelloOptions);
  Options.ClientRandom := SeqBytes(32, 1);
  SetLength(Options.CipherSuites, 1);
  Options.CipherSuites[0] := TLSCipherECDHE_RSA_AES128GCM_SHA256;
  SetLength(Options.KeyShares, 1);
  Options.KeyShares[0].Group := TLSNamedGroupX25519;
  Options.KeyShares[0].KeyExchange := SeqBytes(32, $40);
  Raised := False;
  try
    TLS13BuildClientHelloBody(Options);
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('unsupported 1.2 suite rejected', Raised);
end;

{ ==================================================================== }
{ ServerHello                                                          }
{ ==================================================================== }

function BuildServerHelloBody(ACipher: Word; AGroup: Word;
  const AKey: TBytes; AHelloRetry: Boolean; AIncludeKeyShare: Boolean): TBytes;
var
  Exts: TTLSExtensions;
  Rnd: TBytes;
  N: Integer;
begin
  Exts := nil;
  N := 0;
  SetLength(Exts, N + 1);
  Exts[N].ExtType := TLSExtSupportedVersions;
  Exts[N].Data := W16(TLS13Version);
  Inc(N);
  if AIncludeKeyShare then
  begin
    SetLength(Exts, N + 1);
    Exts[N].ExtType := TLSExtKeyShare;
    Exts[N].Data := Cat(W16(AGroup), Cat(W16(Length(AKey)), AKey));
    Inc(N);
  end;
  if AHelloRetry then
    Rnd := HexToBytes(TLS13HelloRetryRequestRandomHex)
  else
    Rnd := SeqBytes(32, 1);
  Result := Cat(W16(TLS13LegacyVersion), Rnd);
  Result := Cat(Result, B1(0));  { empty session_id echo }
  Result := Cat(Result, W16(ACipher));
  Result := Cat(Result, B1(0));  { compression }
  Result := Cat(Result, EncodeExtensions(Exts));
end;

procedure TTLS13Tests.TestParseServerHello;
var
  Body: TBytes;
  Hello: TTLS13ServerHello;
begin
  Body := BuildServerHelloBody(TLSCipherAES128GCM_SHA256,
    TLSNamedGroupX25519, SeqBytes(32, $55), False, True);
  Hello := TLS13ParseServerHello(Body);
  AssertFalse('not HRR', Hello.IsHelloRetryRequest);
  AssertEquals('legacy version', TLS13LegacyVersion, Hello.LegacyVersion);
  AssertEquals('version', TLS13Version, Hello.SupportedVersion);
  AssertEquals('cipher suite', TLSCipherAES128GCM_SHA256, Hello.CipherSuite);
  AssertTrue('key share present', Hello.HasKeyShare);
  AssertEquals('group', TLSNamedGroupX25519, Hello.KeyShareGroup);
  AssertEquals('key share', BytesToHex(SeqBytes(32, $55)),
    BytesToHex(Hello.KeyShare));
end;

procedure TTLS13Tests.TestParseServerHelloHelloRetryRequest;
var
  Body: TBytes;
  Hello: TTLS13ServerHello;
begin
  Body := BuildServerHelloBody(TLSCipherAES128GCM_SHA256,
    TLSNamedGroupSecp256r1, nil, True, True);
  Hello := TLS13ParseServerHello(Body);
  AssertTrue('HRR', Hello.IsHelloRetryRequest);
  AssertEquals('retry group', TLSNamedGroupSecp256r1, Hello.RetryGroup);
end;

procedure TTLS13Tests.TestParseServerHelloWithoutKeyShare;
var
  Body: TBytes;
  Hello: TTLS13ServerHello;
begin
  Body := BuildServerHelloBody(TLSCipherAES128GCM_SHA256,
    TLSNamedGroupX25519, nil, False, False);
  Hello := TLS13ParseServerHello(Body);
  AssertFalse('no key share', Hello.HasKeyShare);
end;

{ ==================================================================== }
{ Certificate and CertificateVerify                                    }
{ ==================================================================== }

procedure TTLS13Tests.TestParseCertificateMessage;
var
  Der, Entry, List, Body: TBytes;
  CertMsg: TTLSCertificateMessage;
begin
  if not FileExists(FixturePath('ca_rsa.der')) then
    Exit;  { fixtures missing — test skipped }
  Der := ReadFileBytes(FixturePath('ca_rsa.der'));
  { CertificateEntry = cert_data<3> || extensions<2> (empty). }
  Entry := Cat(Triple(Length(Der)), Der);
  Entry := Cat(Entry, W16(0));
  List := Cat(Triple(Length(Entry)), Entry);
  { Certificate = certificate_request_context<1> (empty) ||
    certificate_list<3>. }
  Body := Cat(B1(0), List);
  CertMsg := TLS13ParseCertificate(Body);
  AssertEquals('one certificate', 1, Length(CertMsg.Certificates));
  AssertTrue('DER matches', BytesEqual(Der, CertMsg.Certificates[0].Data));
end;

procedure TTLS13Tests.TestParseCertificateRejectsTruncated;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    TLS13ParseCertificate(B1(0));
  except
    on E: ETLS13Error do
      Raised := True;
  end;
  AssertTrue('truncated certificate message rejected', Raised);
end;

procedure TTLS13Tests.TestCertificateVerifyContentPrefix;
var
  Content, Hash: TBytes;
  i: Integer;
  Prefix, Expected: TBytes;
begin
  Hash := SeqBytes(32, 1);
  Content := TLS13CertificateVerifyContent(TLS13ContextStringServer, Hash);
  AssertEquals('length', 64 + Length(TLS13ContextStringServer) + 1 + 32,
    Length(Content));
  for i := 0 to 63 do
    if Content[i] <> $20 then
    begin
      Fail('byte ' + IntToStr(i) + ' is not a space');
      Exit;
    end;
  Prefix := StrBytes(TLS13ContextStringServer);
  for i := 0 to High(Prefix) do
    if Content[64 + i] <> Prefix[i] then
    begin
      Fail('context string mismatch');
      Exit;
    end;
  AssertEquals('separator', 0, Content[64 + Length(TLS13ContextStringServer)]);
  AssertTrue('hash appended', BytesEqual(Hash,
    Copy(Content, 64 + Length(TLS13ContextStringServer) + 1, 32)));
end;

procedure TTLS13Tests.TestFinishedBody;
var
  VD, Body: TBytes;
begin
  VD := SeqBytes(32, $AA);
  Body := TLS13FinishedBody(VD);
  AssertTrue('finished body', BytesEqual(VD, Body));
end;

initialization
  RegisterTest(TTLS13Tests);

end.
