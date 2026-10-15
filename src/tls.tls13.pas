{ SPDX-License-Identifier: Apache-2.0 }
unit tls.tls13;

{ TLS 1.3 (RFC 8446) client — HKDF key schedule, AEAD record protection and
  the 1-RTT handshake (ClientHello, encrypted server flight, client Finished,
  application data).

  This unit builds on the TLS 1.2 building blocks in tls.tls12 (byte
  transport, record/handshake encoding, cipher-suite constants, certificate
  chain, AEAD helpers) and adds the TLS 1.3 specific parts:

    * HKDF (RFC 5869) and HKDF-Expand-Label (RFC 8446, 7.1);
    * the TLS 1.3 key schedule (early/handshake/master secrets and the
      client/server traffic secrets);
    * the TLS 1.3 record layer (application_data outer type, sequence-number
      nonce XOR, inner content type, AEAD-only protection);
    * the 1-RTT client handshake with (EC)DHE key shares (X25519, P-256,
      P-384), CertificateVerify (ECDSA P-256/P-384, RSA-PSS SHA-256) and
      Finished;
    * a transport-agnostic TTLS13Client that drives a session over
      ITLSTransport.

  Not implemented (out of scope): 0-RTT/early data, PSK resumption,
  HelloRetryRequest, post-handshake KeyUpdate and the SHA-384/SHA-512
  RSA-PSS salt variants (the RSA unit only implements SHA-256 PSS).
  Unsupported input produces a clear ETLS13Error, never a silent
  misbehaviour.

  Implementation for task 13 (docs/tasks/13-tls13.md). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, tls.tls12, tls.sha2, tls.hmac, tls.rand, tls.ec,
  tls.x509, tls.certstore, tls.rsa, tls.bn, tls.x25519;

const
  { TLS 1.3 uses legacy_version = 0x0303 on the wire and a supported_versions
    extension carrying the real version 0x0304 (RFC 8446, 4.1.2). }
  TLS13Version = $0304;
  TLS13LegacyVersion = $0303;

  { TLS 1.3 cipher suites (RFC 8446, B.4). }
  TLSCipherAES128GCM_SHA256 = $1301;
  TLSCipherAES256GCM_SHA384 = $1302;
  TLSCipherCHACHA20_POLY1305_SHA256 = $1303;

  { Extensions used by TLS 1.3 (RFC 8446, 4.2). }
  TLSExtSupportedVersions = 43;
  TLSExtCookie = 44;
  TLSExtPSKKeyExchangeModes = 45;
  TLSExtKeyShare = 51;
  TLSExtPreSharedKey = 41;
  TLSExtSignatureAlgorithmsCert = 50;

  { psk_key_exchange_modes value: psk_dhe_ke (RFC 8446, 4.2.9). }
  TLS13PskModeDHE = 1;

  { Maximum hash / traffic-key / IV sizes for the supported suites. }
  TLS13MaxHashLen = 48;
  TLS13MaxKeyLen = 32;
  TLS13MaxIVLen = 12;

  { Context strings for CertificateVerify (RFC 8446, 4.4.3). }
  TLS13ContextStringServer = 'TLS 1.3, server CertificateVerify';
  TLS13ContextStringClient = 'TLS 1.3, client CertificateVerify';

  { The label prefix used by HKDF-Expand-Label (RFC 8446, 7.1). }
  TLS13LabelPrefix = 'tls13 ';

  { SHA-256 of "HelloRetryRequest" (RFC 8446, 4.1.3). }
  TLS13HelloRetryRequestRandomHex =
    'CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C';

type
  ETLS13Error = class(ETLS12Error);

  { One key_share entry: named group + public key_exchange bytes. }
  TTLS13KeyShare = record
    Group: TTLSNamedGroup;
    KeyExchange: TBytes;
  end;
  TTLS13KeyShares = array of TTLS13KeyShare;

  { ClientHello build options. Empty fields are replaced with defaults. }
  TTLS13ClientHelloOptions = record
    ServerName: string;
    ClientRandom: TBytes;
    SessionID: TBytes;
    CipherSuites: TTLSCipherSuites;
    SupportedGroups: TTLSNamedGroups;
    SignatureAlgorithms: TTLSSignatureSchemes;
    KeyShares: TTLS13KeyShares;
    PskKeyExchangeModes: Boolean;
  end;

  { Ephemeral (EC)DHE key for one named group. Used both to build the
    key_share entry and to compute the shared secret once the server has
    chosen a group. }
  TTLS13ECDHEKey = class
  private
    FGroup: TTLSNamedGroup;
    FX25519Private: TBytes;
    FECCurve: TECCurve;
    FECKeyPair: TECKeypair;
  public
    constructor Create(AGroup: TTLSNamedGroup);
    destructor Destroy; override;
    class function IsSupportedGroup(AGroup: TTLSNamedGroup): Boolean;
    class function GroupName(AGroup: TTLSNamedGroup): string;
    property Group: TTLSNamedGroup read FGroup;
    { Client public key in the key_share encoding (32 bytes for X25519,
      SEC 1 uncompressed point for the NIST curves). }
    function PublicKey: TBytes;
    { Shared secret (ECDHE) with the server peer key. Raises ETLS13Error on
      an invalid peer key. }
    function SharedSecret(const APeerKey: TBytes): TBytes;
  end;

  { Parsed TLS 1.3 ServerHello (RFC 8446, 4.1.3). }
  TTLS13ServerHello = record
    LegacyVersion: Word;
    ServerRandom: TBytes;
    SessionID: TBytes;
    CipherSuite: TTLSCipherSuite;
    SupportedVersion: Word;
    HasKeyShare: Boolean;
    KeyShareGroup: TTLSNamedGroup;
    KeyShare: TBytes;
    IsHelloRetryRequest: Boolean;
    { In a HelloRetryRequest the key_share extension carries only the group
      the server wants. }
    RetryGroup: TTLSNamedGroup;
  end;

  { A pair of AEAD traffic keys derived from one traffic secret. }
  TTLS13TrafficKeys = record
    Key: TBytes;
    IV: TBytes;
  end;

  { Transport-agnostic TLS 1.3 client. Performs the 1-RTT handshake and then
    reads/writes application data. Never touches a socket or a file: all
    I/O goes through ITLSTransport. The trust store and transport are owned
    by the caller. }
  TTLS13Client = class
  private
    FTransport: ITLSTransport;
    FTrustStore: TCertStore;
    FServerName: string;
    FBuffer: TTLSHandshakeBuffer;
    FKeys: array of TTLS13ECDHEKey;
    FHashKind: THashKind;
    FCipherSuite: TTLSCipherSuite;
    FMode: TTLSAEADMode;
    FNegotiatedGroup: TTLSNamedGroup;
    FReadKeys, FWriteKeys: TTLS13TrafficKeys;
    FReadSeq, FWriteSeq: QWord;
    FClientHSSecret, FServerHSSecret: TBytes;
    FClientAppSecret, FServerAppSecret: TBytes;
    FConnected: Boolean;
    FClosed: Boolean;
    FClientRandom, FSessionID: TBytes;
    FLeafCert: TX509Cert;

    procedure SetTrafficKeys(const ASecret: TBytes;
      out AKeys: TTLS13TrafficKeys);
    function BuildOptions(
      const AOptions: TTLS13ClientHelloOptions): TTLS13ClientHelloOptions;
    function KeyForGroup(AGroup: TTLSNamedGroup): TTLS13ECDHEKey;
    function ReadRawRecord(out ARec: TTLSRecord): Boolean;
    function ReadHandshakeMessage(out AMsg: TTLSHandshakeMessage): Boolean;
    procedure ProcessServerFlight(
      out ATranscriptThroughServerFinished: TBytes);
    procedure VerifyServerCertificate(const ACertMsg: TTLSCertificateMessage);
    procedure VerifyCertificateVerify(const ABody: TBytes;
      const ATranscriptHash: TBytes);
    procedure SwitchToApplicationKeys;
  public
    constructor Create(ATransport: ITLSTransport; ATrustStore: TCertStore;
      const AServerName: string);
    destructor Destroy; override;

    { Runs the full 1-RTT handshake. On success Connected is True and the
      application traffic keys are active. Raises ETLS13Error on failure. }
    procedure Connect;
    { Convenience: Connect with the supplied ClientHello options (for example
      a restricted key-share list in tests). Unsupported options (such as
      pre-supplied KeyShares without private keys) are replaced by freshly
      generated key shares. }
    procedure Connect(const AOptions: TTLS13ClientHelloOptions);

    procedure SendApplicationData(const AData: TBytes);
    { Reads one application-data record. Returns False when the peer sends
      close_notify or closes the stream cleanly. Post-handshake
      NewSessionTicket messages are skipped; KeyUpdate is rejected. }
    function ReceiveApplicationData(out AData: TBytes): Boolean;
    procedure SendCloseNotify;

    property Connected: Boolean read FConnected;
    property CipherSuite: TTLSCipherSuite read FCipherSuite;
    property NegotiatedGroup: TTLSNamedGroup read FNegotiatedGroup;
    property ServerCertificate: TX509Cert read FLeafCert;
  end;

{ --- Transcript hash -------------------------------------------------- }

function TLS13TranscriptHash(AKind: THashKind;
  const ATranscript: TBytes): TBytes;

{ --- HKDF (RFC 5869) and HKDF-Expand-Label (RFC 8446, 7.1) ------------- }

function HKDFExtract(AKind: THashKind; const ASalt, AIKM: TBytes): TBytes;
function HKDFExpand(AKind: THashKind; const APRK, AInfo: TBytes;
  ALen: Integer): TBytes;
{ HKDF-Expand-Label(Secret, Label, Context, Length) with the "tls13 " prefix. }
function HKDFExpandLabel(AKind: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const AContext: TBytes; ALen: Integer): TBytes;

{ --- TLS 1.3 helpers -------------------------------------------------- }

function TLS13HashLen(AKind: THashKind): Integer;
function TLS13CipherSuiteName(ASuite: TTLSCipherSuite): string;
function TLS13CipherSuiteSupported(ASuite: TTLSCipherSuite): Boolean;
function TLS13CipherSuiteHashKind(ASuite: TTLSCipherSuite): THashKind;
function TLS13CipherSuiteAEADMode(ASuite: TTLSCipherSuite): TTLSAEADMode;
function TLS13DefaultCipherSuites: TTLSCipherSuites;
function TLS13DefaultSupportedGroups: TTLSNamedGroups;
function TLS13DefaultSignatureAlgorithms: TTLSSignatureSchemes;

{ Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label,
  Hash(Messages), Hash.length). }
function TLS13DeriveSecret(AKind: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;

{ Key schedule building blocks (RFC 8446, 7.1). Early Secret uses an
  all-zero PSK, so Early Secret = HKDF-Extract(0, 0). }
function TLS13EarlySecret(AKind: THashKind): TBytes;
function TLS13HandshakeSecret(AKind: THashKind;
  const ASharedSecret: TBytes): TBytes;
function TLS13MasterSecret(AKind: THashKind;
  const AHandshakeSecret: TBytes): TBytes;

{ Traffic secrets: Derive-Secret(Base, "c hs traffic"/"s hs traffic"/
  "c ap traffic"/"s ap traffic", Transcript). }
function TLS13TrafficSecret(AKind: THashKind; const ABaseSecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;

{ key = HKDF-Expand-Label(Secret, "key", "", key_length),
  iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length). }
function TLS13TrafficKeys(AKind: THashKind; AMode: TTLSAEADMode;
  const ATrafficSecret: TBytes): TTLS13TrafficKeys;

{ finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length),
  verify_data  = HMAC(finished_key, Transcript-Hash(Messages)). }
function TLS13FinishedKey(AKind: THashKind;
  const ABaseSecret: TBytes): TBytes;
function TLS13FinishedVerifyData(AKind: THashKind;
  const ABaseSecret, ATranscript: TBytes): TBytes;
{TLS 1.3 Finished body: verify_data (Hash.length bytes).}
function TLS13FinishedBody(const AVerifyData: TBytes): TBytes;

{ --- Record protection (RFC 8446, 5.2/5.3) ---------------------------- }

{ AAD = opaque_type || legacy_record_version || length (5 bytes). }
function TLS13RecordAAD(AContentType: Byte; AEncryptedLength: Integer): TBytes;
{ nonce = static_iv XOR (0...0 || seq) with the sequence number in network
  byte order. }
function TLS13Nonce(const AIV: TBytes; ASeq: QWord): TBytes;

function TLS13ProtectRecord(AMode: TTLSAEADMode; const AKey, AIV: TBytes;
  ASeq: QWord; AContentType: TTLSContentType;
  const APlain: TBytes): TBytes;
function TLS13UnprotectRecord(AMode: TTLSAEADMode; const AKey, AIV: TBytes;
  ASeq: QWord; const AFragment: TBytes; out AContentType: TTLSContentType;
  out APlain: TBytes): Boolean;

procedure TLS13WriteRecord(ATransport: ITLSTransport; AMode: TTLSAEADMode;
  const AKey, AIV: TBytes; var ASeq: QWord; AContentType: TTLSContentType;
  const APlain: TBytes);
function TLS13ReadRecord(ATransport: ITLSTransport; AMode: TTLSAEADMode;
  const AKey, AIV: TBytes; var ASeq: QWord; out AContentType: TTLSContentType;
  out APlain: TBytes): Boolean;

{ --- Handshake messages ----------------------------------------------- }

function TLS13EncodeKeyShareExtension(
  const AShares: TTLS13KeyShares): TTLSExtension;
function TLS13EncodeSupportedVersionsExtension: TTLSExtension;
function TLS13EncodePSKKeyExchangeModesExtension: TTLSExtension;
function TLS13BuildClientHelloBody(
  const AOptions: TTLS13ClientHelloOptions): TBytes;
function TLS13BuildClientHello(
  const AOptions: TTLS13ClientHelloOptions): TBytes;

function TLS13ParseServerHello(const ABody: TBytes): TTLS13ServerHello;
function TLS13ParseEncryptedExtensions(const ABody: TBytes): TTLSExtensions;
function TLS13ParseCertificate(const ABody: TBytes): TTLSCertificateMessage;
function TLS13ParseCertificateVerify(const ABody: TBytes;
  out AScheme: TTLSSignatureScheme; out ASignature: TBytes): Boolean;

{ Content signed by CertificateVerify:
  64 spaces || context_string || 0x00 || Transcript-Hash(Messages). }
function TLS13CertificateVerifyContent(const AContextString: string;
  const ATranscriptHash: TBytes): TBytes;

{ Verifies a CertificateVerify signature. Supported schemes: ECDSA with
  P-256/P-384 and rsa_pss_rsae_sha256 (the PSS implementation is SHA-256). }
function TLS13VerifyCertificateVerify(ACert: TX509Cert;
  const AContent, ASignature: TBytes;
  AScheme: TTLSSignatureScheme): Boolean;

implementation

uses
  tls.aes, tls.chacha20;

{ ==================================================================== }
{ Local byte helpers                                                   }
{ ==================================================================== }

function TLS13Cat(const A, B: TBytes): TBytes;
var
  LA, LB: Integer;
begin
  LA := Length(A);
  LB := Length(B);
  SetLength(Result, LA + LB);
  if LA > 0 then
    Move(A[0], Result[0], LA);
  if LB > 0 then
    Move(B[0], Result[LA], LB);
end;

function TLS13Byte(const A: TBytes; B: Byte): TBytes;
var
  LA: Integer;
begin
  LA := Length(A);
  SetLength(Result, LA + 1);
  if LA > 0 then
    Move(A[0], Result[0], LA);
  Result[LA] := B;
end;

function TLS13Word(const A: TBytes; W: Word): TBytes;
begin
  Result := TLS13Byte(A, Byte((W shr 8) and $FF));
  Result := TLS13Byte(Result, Byte(W and $FF));
end;

function TLS13ReadWordAt(const AData: TBytes; AOffset: Integer): Word;
begin
  Result := (Word(AData[AOffset]) shl 8) or Word(AData[AOffset + 1]);
end;

function TLS13ReadTripleAt(const AData: TBytes; AOffset: Integer): LongWord;
begin
  Result := (LongWord(AData[AOffset]) shl 16) or
            (LongWord(AData[AOffset + 1]) shl 8) or
            LongWord(AData[AOffset + 2]);
end;

function TLS13StrToBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Byte(S[i]);
end;

function TLS13ZeroBytes(ACount: Integer): TBytes;
begin
  SetLength(Result, ACount);
  if ACount > 0 then
    FillChar(Result[0], ACount, 0);
end;

function TLS13PadLeft(const AData: TBytes; ALen: Integer): TBytes;
begin
  if Length(AData) > ALen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: value %d bytes does not fit into %d', [Length(AData), ALen]);
  Result := TLS13ZeroBytes(ALen);
  if Length(AData) > 0 then
    Move(AData[0], Result[ALen - Length(AData)], Length(AData));
end;

function TLS13ConstEq(const A, B: TBytes): Boolean;
var
  i, diff: Integer;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  diff := 0;
  for i := 0 to High(A) do
    diff := diff or (A[i] xor B[i]);
  Result := diff = 0;
end;

function TLS13HexToBytes(const S: string): TBytes;
var
  i: Integer;
  function Nib(C: Char): Byte;
  begin
    case C of
      '0'..'9': Result := Ord(C) - Ord('0');
      'a'..'f': Result := Ord(C) - Ord('a') + 10;
      'A'..'F': Result := Ord(C) - Ord('A') + 10;
    else
      Result := 0;
    end;
  end;
begin
  SetLength(Result, Length(S) div 2);
  for i := 0 to High(Result) do
    Result[i] := (Nib(S[2 * i + 1]) shl 4) or Nib(S[2 * i + 2]);
end;

{ ==================================================================== }
{ Transcript hash                                                      }
{ ==================================================================== }

function TLS13TranscriptHash(AKind: THashKind;
  const ATranscript: TBytes): TBytes;
begin
  case AKind of
    hkSHA256: Result := SHA256(ATranscript);
    hkSHA384: Result := SHA384(ATranscript);
    hkSHA512: Result := SHA512(ATranscript);
  else
    raise ETLS13Error.Create('TLS 1.3: unknown transcript hash');
  end;
end;

{ ==================================================================== }
{ HKDF                                                                 }
{ ==================================================================== }

function HKDFExtract(AKind: THashKind; const ASalt, AIKM: TBytes): TBytes;
var
  Salt: TBytes;
begin
  Salt := ASalt;
  if Length(Salt) = 0 then
    Salt := TLS13ZeroBytes(TLS13HashLen(AKind));
  Result := THMAC.Compute(AKind, Salt, AIKM);
end;

function HKDFExpand(AKind: THashKind; const APRK, AInfo: TBytes;
  ALen: Integer): TBytes;
var
  T, Block: TBytes;
  HL, N, i, ToCopy, Pos: Integer;
begin
  if ALen < 0 then
    raise ETLS13Error.Create('HKDF-Expand: negative length');
  HL := TLS13HashLen(AKind);
  if ALen > 255 * HL then
    raise ETLS13Error.Create('HKDF-Expand: length exceeds 255*HashLen');
  SetLength(Result, ALen);
  if ALen = 0 then
    Exit;
  T := nil;
  Pos := 0;
  N := (ALen + HL - 1) div HL;
  for i := 1 to N do
  begin
    { T(i) = HMAC(PRK, T(i-1) || info || counter), counter is one byte. }
    Block := TLS13Cat(T, AInfo);
    Block := TLS13Byte(Block, Byte(i));
    T := THMAC.Compute(AKind, APRK, Block);
    ToCopy := ALen - Pos;
    if ToCopy > HL then
      ToCopy := HL;
    Move(T[0], Result[Pos], ToCopy);
    Inc(Pos, ToCopy);
  end;
end;

function HKDFExpandLabel(AKind: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const AContext: TBytes; ALen: Integer): TBytes;
var
  FullLabel, Info: TBytes;
begin
  FullLabel := TLS13StrToBytes(TLS13LabelPrefix + ALabel);
  if Length(FullLabel) > 255 then
    raise ETLS13Error.Create('HKDF-Expand-Label: label too long');
  if Length(AContext) > 255 then
    raise ETLS13Error.Create('HKDF-Expand-Label: context too long');
  Info := TLS13Word(nil, ALen);
  Info := TLS13Byte(Info, Length(FullLabel));
  Info := TLS13Cat(Info, FullLabel);
  Info := TLS13Byte(Info, Length(AContext));
  Info := TLS13Cat(Info, AContext);
  Result := HKDFExpand(AKind, ASecret, Info, ALen);
end;

{ ==================================================================== }
{ Cipher suites and helpers                                            }
{ ==================================================================== }

function TLS13HashLen(AKind: THashKind): Integer;
begin
  case AKind of
    hkSHA256: Result := 32;
    hkSHA384: Result := 48;
    hkSHA512: Result := 64;
  else
    raise ETLS13Error.Create('TLS 1.3: unknown hash kind');
  end;
end;

function TLS13CipherSuiteName(ASuite: TTLSCipherSuite): string;
begin
  case ASuite of
    TLSCipherAES128GCM_SHA256: Result := 'TLS_AES_128_GCM_SHA256';
    TLSCipherAES256GCM_SHA384: Result := 'TLS_AES_256_GCM_SHA384';
    TLSCipherCHACHA20_POLY1305_SHA256: Result := 'TLS_CHACHA20_POLY1305_SHA256';
  else
    Result := Format('unknown_tls13_suite(0x%.4x)', [ASuite]);
  end;
end;

function TLS13CipherSuiteSupported(ASuite: TTLSCipherSuite): Boolean;
begin
  Result := (ASuite = TLSCipherAES128GCM_SHA256) or
    (ASuite = TLSCipherAES256GCM_SHA384) or
    (ASuite = TLSCipherCHACHA20_POLY1305_SHA256);
end;

function TLS13CipherSuiteHashKind(ASuite: TTLSCipherSuite): THashKind;
begin
  case ASuite of
    TLSCipherAES256GCM_SHA384: Result := hkSHA384;
    TLSCipherAES128GCM_SHA256,
    TLSCipherCHACHA20_POLY1305_SHA256: Result := hkSHA256;
  else
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: unknown cipher suite 0x%.4X', [ASuite]);
  end;
end;

function TLS13CipherSuiteAEADMode(ASuite: TTLSCipherSuite): TTLSAEADMode;
begin
  case ASuite of
    TLSCipherAES128GCM_SHA256: Result := aeadAES128GCM;
    TLSCipherAES256GCM_SHA384: Result := aeadAES256GCM;
    TLSCipherCHACHA20_POLY1305_SHA256: Result := aeadChaCha20Poly1305;
  else
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: unknown cipher suite 0x%.4X', [ASuite]);
  end;
end;

function TLS13DefaultCipherSuites: TTLSCipherSuites;
const
  Suites: array[0..2] of Word = (TLSCipherAES128GCM_SHA256,
    TLSCipherAES256GCM_SHA384, TLSCipherCHACHA20_POLY1305_SHA256);
var
  i: Integer;
begin
  SetLength(Result, Length(Suites));
  for i := 0 to High(Suites) do
    Result[i] := Suites[i];
end;

function TLS13DefaultSupportedGroups: TTLSNamedGroups;
const
  Groups: array[0..2] of Word = (TLSNamedGroupX25519,
    TLSNamedGroupSecp256r1, TLSNamedGroupSecp384r1);
var
  i: Integer;
begin
  SetLength(Result, Length(Groups));
  for i := 0 to High(Groups) do
    Result[i] := Groups[i];
end;

{ Only the schemes our verifier supports: ECDSA P-256/P-384 and
  rsa_pss_rsae_sha256 (the PSS code is SHA-256 based; SHA-384/512 PSS are
  deliberately not advertised so the server cannot pick one we cannot
  verify). }
function TLS13DefaultSignatureAlgorithms: TTLSSignatureSchemes;
const
  Schemes: array[0..2] of Word = (TLSSigECDSA_Secp256r1_SHA256,
    TLSSigECDSA_Secp384r1_SHA384, TLSSigRSA_PSS_RSAE_SHA256);
var
  i: Integer;
begin
  SetLength(Result, Length(Schemes));
  for i := 0 to High(Schemes) do
    Result[i] := Schemes[i];
end;

function TLS13DeriveSecret(AKind: THashKind; const ASecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;
var
  Context: TBytes;
begin
  Context := TLS13TranscriptHash(AKind, ATranscript);
  Result := HKDFExpandLabel(AKind, ASecret, ALabel, Context,
    TLS13HashLen(AKind));
end;

function TLS13EarlySecret(AKind: THashKind): TBytes;
var
  Z: TBytes;
begin
  Z := TLS13ZeroBytes(TLS13HashLen(AKind));
  Result := HKDFExtract(AKind, Z, Z);
end;

function TLS13HandshakeSecret(AKind: THashKind;
  const ASharedSecret: TBytes): TBytes;
var
  Early, Derived: TBytes;
begin
  Early := TLS13EarlySecret(AKind);
  Derived := TLS13DeriveSecret(AKind, Early, 'derived', nil);
  Result := HKDFExtract(AKind, Derived, ASharedSecret);
end;

function TLS13MasterSecret(AKind: THashKind;
  const AHandshakeSecret: TBytes): TBytes;
var
  Derived, Z: TBytes;
begin
  Derived := TLS13DeriveSecret(AKind, AHandshakeSecret, 'derived', nil);
  Z := TLS13ZeroBytes(TLS13HashLen(AKind));
  Result := HKDFExtract(AKind, Derived, Z);
end;

function TLS13TrafficSecret(AKind: THashKind; const ABaseSecret: TBytes;
  const ALabel: AnsiString; const ATranscript: TBytes): TBytes;
begin
  Result := TLS13DeriveSecret(AKind, ABaseSecret, ALabel, ATranscript);
end;

function TLS13TrafficKeys(AKind: THashKind; AMode: TTLSAEADMode;
  const ATrafficSecret: TBytes): TTLS13TrafficKeys;
begin
  Result.Key := HKDFExpandLabel(AKind, ATrafficSecret, 'key', nil,
    TLSAEADKeyLength(AMode));
  { TLS 1.3 always uses a 12-byte IV for every AEAD suite (RFC 8446,
    section 5.3), unlike TLS 1.2 where AES-GCM has a 4-byte fixed IV. }
  Result.IV := HKDFExpandLabel(AKind, ATrafficSecret, 'iv', nil,
    TLS13MaxIVLen);
end;

function TLS13FinishedKey(AKind: THashKind;
  const ABaseSecret: TBytes): TBytes;
begin
  Result := HKDFExpandLabel(AKind, ABaseSecret, 'finished', nil,
    TLS13HashLen(AKind));
end;

function TLS13FinishedVerifyData(AKind: THashKind;
  const ABaseSecret, ATranscript: TBytes): TBytes;
var
  FinishedKey, Hash: TBytes;
begin
  FinishedKey := TLS13FinishedKey(AKind, ABaseSecret);
  Hash := TLS13TranscriptHash(AKind, ATranscript);
  Result := THMAC.Compute(AKind, FinishedKey, Hash);
end;

function TLS13FinishedBody(const AVerifyData: TBytes): TBytes;
begin
  Result := Copy(AVerifyData, 0, Length(AVerifyData));
end;

{ ==================================================================== }
{ Record protection                                                    }
{ ==================================================================== }

function TLS13RecordAAD(AContentType: Byte; AEncryptedLength: Integer): TBytes;
begin
  if (AEncryptedLength < 0) or (AEncryptedLength > $FFFF) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record: invalid length %d', [AEncryptedLength]);
  SetLength(Result, TLSRecordHeaderLen);
  Result[0] := AContentType;
  Result[1] := Byte((TLS13LegacyVersion shr 8) and $FF);
  Result[2] := Byte(TLS13LegacyVersion and $FF);
  Result[3] := Byte((AEncryptedLength shr 8) and $FF);
  Result[4] := Byte(AEncryptedLength and $FF);
end;

function TLS13Nonce(const AIV: TBytes; ASeq: QWord): TBytes;
var
  i, Base: Integer;
begin
  if Length(AIV) = 0 then
    raise ETLS13Error.Create('TLS 1.3: empty IV');
  Result := Copy(AIV, 0, Length(AIV));
  Base := Length(Result) - 8;
  for i := 0 to 7 do
    Result[Base + i] := Result[Base + i] xor Byte(ASeq shr (8 * (7 - i)));
end;

function TLS13ProtectRecord(AMode: TTLSAEADMode; const AKey, AIV: TBytes;
  ASeq: QWord; AContentType: TTLSContentType;
  const APlain: TBytes): TBytes;
var
  Inner, Nonce, AAD, Cipher, Tag: TBytes;
  EncLen: Integer;
begin
  if Length(APlain) > TLSRecordMaxPayload then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record: plaintext %d bytes exceeds limit 2^14 (%d)',
      [Length(APlain), TLSRecordMaxPayload]);
  SetLength(Inner, Length(APlain) + 1);
  if Length(APlain) > 0 then
    Move(APlain[0], Inner[0], Length(APlain));
  Inner[Length(Inner) - 1] := TLSContentTypeToByte(AContentType);
  EncLen := Length(Inner) + TLSAEADTagLen;
  AAD := TLS13RecordAAD(TLSContentTypeToByte(ctApplicationData), EncLen);
  Nonce := TLS13Nonce(AIV, ASeq);
  case AMode of
    aeadAES128GCM, aeadAES256GCM:
      begin
        if Length(AKey) <> TLSAEADKeyLength(AMode) then
          raise ETLS13Error.Create('TLS 1.3 AES-GCM: wrong key length');
        AESGCMEncrypt(AKey, Nonce, AAD, Inner, Cipher, Tag);
      end;
    aeadChaCha20Poly1305:
      begin
        if Length(AKey) <> 32 then
          raise ETLS13Error.Create('TLS 1.3 ChaCha20: wrong key length');
        ChaCha20Poly1305Encrypt(AKey, Nonce, AAD, Inner, Cipher, Tag);
      end;
  else
    raise ETLS13Error.Create('TLS 1.3 record: unknown AEAD mode');
  end;
  Result := TLS13Cat(Cipher, Tag);
end;

function TLS13UnprotectRecord(AMode: TTLSAEADMode; const AKey, AIV: TBytes;
  ASeq: QWord; const AFragment: TBytes; out AContentType: TTLSContentType;
  out APlain: TBytes): Boolean;
var
  Inner, Nonce, AAD, Cipher, Tag: TBytes;
  EncLen, i: Integer;
  Ct: Byte;
  DecOk: Boolean;
begin
  Result := False;
  APlain := nil;
  AContentType := ctApplicationData;
  EncLen := Length(AFragment);
  if EncLen < TLSAEADTagLen + 1 then
    Exit;
  AAD := TLS13RecordAAD(TLSContentTypeToByte(ctApplicationData), EncLen);
  Nonce := TLS13Nonce(AIV, ASeq);
  Cipher := Copy(AFragment, 0, EncLen - TLSAEADTagLen);
  Tag := Copy(AFragment, EncLen - TLSAEADTagLen, TLSAEADTagLen);
  case AMode of
    aeadAES128GCM, aeadAES256GCM:
      begin
        if Length(AKey) <> TLSAEADKeyLength(AMode) then
          Exit;
        DecOk := AESGCMDecrypt(AKey, Nonce, AAD, Cipher, Tag, Inner);
      end;
    aeadChaCha20Poly1305:
      begin
        if Length(AKey) <> 32 then
          Exit;
        DecOk := ChaCha20Poly1305Decrypt(AKey, Nonce, AAD, Cipher, Tag, Inner);
      end;
  else
    Exit;
  end;
  if not DecOk then
    Exit;
  { Strip the zero padding; the last non-zero byte is the real content type. }
  i := Length(Inner) - 1;
  while (i >= 0) and (Inner[i] = 0) do
    Dec(i);
  if i < 0 then
    Exit;
  Ct := Inner[i];
  if not IsKnownContentType(Ct) then
    Exit;
  AContentType := ByteToTLSContentType(Ct);
  SetLength(APlain, i);
  if i > 0 then
    Move(Inner[0], APlain[0], i);
  Result := True;
end;

procedure TLS13WriteRecord(ATransport: ITLSTransport; AMode: TTLSAEADMode;
  const AKey, AIV: TBytes; var ASeq: QWord; AContentType: TTLSContentType;
  const APlain: TBytes);
var
  Frag: TBytes;
begin
  Frag := TLS13ProtectRecord(AMode, AKey, AIV, ASeq, AContentType, APlain);
  WriteTLSRecord(ATransport, ctApplicationData, Frag, TLS13LegacyVersion);
  Inc(ASeq);
end;

function TLS13ReadRecord(ATransport: ITLSTransport; AMode: TTLSAEADMode;
  const AKey, AIV: TBytes; var ASeq: QWord; out AContentType: TTLSContentType;
  out APlain: TBytes): Boolean;
var
  Rec: TTLSRecord;
begin
  Rec := ReadTLSRecord(ATransport);
  if Rec.ContentType <> ctApplicationData then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record: expected application_data, got type %d',
      [Ord(Rec.ContentType)]);
  Result := TLS13UnprotectRecord(AMode, AKey, AIV, ASeq, Rec.Fragment,
    AContentType, APlain);
  if Result then
    Inc(ASeq);
end;

{ ==================================================================== }
{ (EC)DHE key shares                                                   }
{ ==================================================================== }

class function TTLS13ECDHEKey.IsSupportedGroup(
  AGroup: TTLSNamedGroup): Boolean;
begin
  Result := (AGroup = TLSNamedGroupX25519) or
    (AGroup = TLSNamedGroupSecp256r1) or
    (AGroup = TLSNamedGroupSecp384r1);
end;

class function TTLS13ECDHEKey.GroupName(AGroup: TTLSNamedGroup): string;
begin
  case AGroup of
    TLSNamedGroupX25519: Result := 'x25519';
    TLSNamedGroupSecp256r1: Result := 'secp256r1';
    TLSNamedGroupSecp384r1: Result := 'secp384r1';
  else
    Result := Format('group(0x%.4x)', [AGroup]);
  end;
end;

constructor TTLS13ECDHEKey.Create(AGroup: TTLSNamedGroup);
var
  KP: TX25519KeyPair;
begin
  inherited Create;
  if not IsSupportedGroup(AGroup) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 key share: unsupported group %s', [GroupName(AGroup)]);
  FGroup := AGroup;
  if AGroup = TLSNamedGroupX25519 then
  begin
    KP := X25519GenerateKeyPair;
    FX25519Private := KP.PrivateKey;
  end
  else
  begin
    case AGroup of
      TLSNamedGroupSecp256r1: FECCurve := CurveP256;
      TLSNamedGroupSecp384r1: FECCurve := CurveP384;
    end;
    FECKeyPair := GenerateKeyPair(FECCurve);
  end;
end;

destructor TTLS13ECDHEKey.Destroy;
begin
  if FECKeyPair <> nil then
    FECKeyPair.Free;
  if FECCurve <> nil then
    FECCurve.Free;
  inherited Destroy;
end;

function TTLS13ECDHEKey.PublicKey: TBytes;
begin
  if FGroup = TLSNamedGroupX25519 then
    Result := X25519PublicKey(FX25519Private)
  else
    Result := EncodePoint(FECCurve, FECKeyPair.PublicKey);
end;

function TTLS13ECDHEKey.SharedSecret(const APeerKey: TBytes): TBytes;
var
  Peer: TECPoint;
  Shared: TECPoint;
  FieldSz: Integer;
begin
  if FGroup = TLSNamedGroupX25519 then
  begin
    if Length(APeerKey) <> X25519KeySize then
      raise ETLS13Error.Create('TLS 1.3 X25519: peer key is not 32 bytes');
    try
      Result := X25519SharedSecret(FX25519Private, APeerKey);
    except
      on E: Exception do
        raise ETLS13Error.Create('TLS 1.3 X25519: ' + E.Message);
    end;
    Exit;
  end;

  if Length(APeerKey) = 0 then
    raise ETLS13Error.Create('TLS 1.3 ECDHE: empty peer key');
  try
    Peer := DecodePoint(FECCurve, APeerKey);
  except
    on E: Exception do
      raise ETLS13Error.Create('TLS 1.3 ECDHE: bad peer point: ' + E.Message);
  end;
  try
    if Peer.Infinity or (not IsOnCurve(FECCurve, Peer)) then
      raise ETLS13Error.Create('TLS 1.3 ECDHE: peer point is not on the curve');
    Shared := ComputeSharedSecret(FECCurve, FECKeyPair.PrivateKey, Peer);
    try
      if Shared.Infinity then
        raise ETLS13Error.Create('TLS 1.3 ECDHE: shared point at infinity');
      case FGroup of
        TLSNamedGroupSecp256r1: FieldSz := 32;
        TLSNamedGroupSecp384r1: FieldSz := 48;
      else
        FieldSz := 0;
      end;
      Result := TLS13PadLeft(Shared.X.ToBytes(True), FieldSz);
    finally
      Shared.Free;
    end;
  finally
    Peer.Free;
  end;
end;

{ ==================================================================== }
{ ClientHello                                                          }
{ ==================================================================== }

function TLS13EncodeKeyShareExtension(
  const AShares: TTLS13KeyShares): TTLSExtension;
var
  Entry, Body: TBytes;
  i: Integer;
begin
  if Length(AShares) = 0 then
    raise ETLS13Error.Create('TLS 1.3 key_share: empty share list');
  Body := nil;
  for i := 0 to High(AShares) do
  begin
    if Length(AShares[i].KeyExchange) > $FFFF then
      raise ETLS13Error.Create('TLS 1.3 key_share: share too long');
    Entry := TLS13Word(nil, AShares[i].Group);
    Entry := TLS13Word(Entry, Length(AShares[i].KeyExchange));
    Entry := TLS13Cat(Entry, AShares[i].KeyExchange);
    Body := TLS13Cat(Body, Entry);
  end;
  Result.ExtType := TLSExtKeyShare;
  Result.Data := TLS13Word(nil, Length(Body));
  Result.Data := TLS13Cat(Result.Data, Body);
end;

function TLS13EncodeSupportedVersionsExtension: TTLSExtension;
var
  Body: TBytes;
begin
  Body := TLS13Byte(nil, 2);
  Body := TLS13Word(Body, TLS13Version);
  Result.ExtType := TLSExtSupportedVersions;
  Result.Data := Body;
end;

function TLS13EncodePSKKeyExchangeModesExtension: TTLSExtension;
begin
  Result.ExtType := TLSExtPSKKeyExchangeModes;
  Result.Data := TLS13Byte(TLS13Byte(nil, 1), TLS13PskModeDHE);
end;

function TLS13EncodeSupportedGroupsExt(
  const AGroups: TTLSNamedGroups): TTLSExtension;
var
  Body, Data: TBytes;
  i: Integer;
begin
  Body := nil;
  for i := 0 to High(AGroups) do
    Body := TLS13Word(Body, AGroups[i]);
  Data := TLS13Word(nil, Length(Body));
  Data := TLS13Cat(Data, Body);
  Result.ExtType := TLSExtSupportedGroups;
  Result.Data := Data;
end;

function TLS13EncodeSignatureAlgorithmsExt(
  const ASchemes: TTLSSignatureSchemes): TTLSExtension;
var
  Body, Data: TBytes;
  i: Integer;
begin
  Body := nil;
  for i := 0 to High(ASchemes) do
    Body := TLS13Word(Body, ASchemes[i]);
  Data := TLS13Word(nil, Length(Body));
  Data := TLS13Cat(Data, Body);
  Result.ExtType := TLSExtSignatureAlgorithms;
  Result.Data := Data;
end;

function TLS13EncodeExtensions(const AExtensions: TTLSExtensions): TBytes;
var
  Body: TBytes;
  i: Integer;
begin
  Body := nil;
  for i := 0 to High(AExtensions) do
  begin
    Body := TLS13Word(Body, AExtensions[i].ExtType);
    Body := TLS13Word(Body, Length(AExtensions[i].Data));
    Body := TLS13Cat(Body, AExtensions[i].Data);
  end;
  Result := TLS13Word(nil, Length(Body));
  Result := TLS13Cat(Result, Body);
end;

function TLS13BuildClientHelloBody(
  const AOptions: TTLS13ClientHelloOptions): TBytes;
var
  Random, SessionID, SuiteBytes, ExtBytes: TBytes;
  Suites: TTLSCipherSuites;
  Groups: TTLSNamedGroups;
  Sigs: TTLSSignatureSchemes;
  Exts: TTLSExtensions;
  i, n: Integer;
begin
  Random := AOptions.ClientRandom;
  if Length(Random) = 0 then
    RandomBytes(Random, TLSClientRandomLen)
  else if Length(Random) <> TLSClientRandomLen then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 ClientHello: random %d bytes (need %d)',
      [Length(Random), TLSClientRandomLen]);
  SessionID := AOptions.SessionID;
  if Length(SessionID) > TLSMaxSessionIDLen then
    raise ETLS13Error.Create('TLS 1.3 ClientHello: session_id too long');
  Suites := AOptions.CipherSuites;
  if Length(Suites) = 0 then
    Suites := TLS13DefaultCipherSuites;
  SuiteBytes := nil;
  for i := 0 to High(Suites) do
  begin
    if not TLS13CipherSuiteSupported(Suites[i]) then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 ClientHello: unsupported cipher suite 0x%.4x', [Suites[i]]);
    SuiteBytes := TLS13Word(SuiteBytes, Suites[i]);
  end;
  Groups := AOptions.SupportedGroups;
  if Length(Groups) = 0 then
    Groups := TLS13DefaultSupportedGroups;
  Sigs := AOptions.SignatureAlgorithms;
  if Length(Sigs) = 0 then
    Sigs := TLS13DefaultSignatureAlgorithms;

  Exts := nil;
  n := 0;
  if AOptions.ServerName <> '' then
  begin
    SetLength(Exts, n + 1);
    Exts[n] := EncodeTLSServerNameExtension(AOptions.ServerName);
    Inc(n);
  end;
  SetLength(Exts, n + 1);
  Exts[n] := TLS13EncodeSupportedGroupsExt(Groups);
  Inc(n);
  SetLength(Exts, n + 1);
  Exts[n] := TLS13EncodeSignatureAlgorithmsExt(Sigs);
  Inc(n);
  SetLength(Exts, n + 1);
  Exts[n] := TLS13EncodeSupportedVersionsExtension;
  Inc(n);
  if AOptions.PskKeyExchangeModes then
  begin
    SetLength(Exts, n + 1);
    Exts[n] := TLS13EncodePSKKeyExchangeModesExtension;
    Inc(n);
  end;
  if Length(AOptions.KeyShares) > 0 then
  begin
    SetLength(Exts, n + 1);
    Exts[n] := TLS13EncodeKeyShareExtension(AOptions.KeyShares);
    Inc(n);
  end;

  Result := TLS13Word(nil, TLS13LegacyVersion);
  Result := TLS13Cat(Result, Random);
  Result := TLS13Byte(Result, Length(SessionID));
  Result := TLS13Cat(Result, SessionID);
  Result := TLS13Word(Result, Length(SuiteBytes));
  Result := TLS13Cat(Result, SuiteBytes);
  Result := TLS13Byte(Result, 1);
  Result := TLS13Byte(Result, 0);
  ExtBytes := TLS13EncodeExtensions(Exts);
  Result := TLS13Cat(Result, ExtBytes);
end;

function TLS13BuildClientHello(
  const AOptions: TTLS13ClientHelloOptions): TBytes;
begin
  Result := EncodeTLSHandshakeMessage(htClientHello,
    TLS13BuildClientHelloBody(AOptions));
end;

{ ==================================================================== }
{ Server flight parsing                                                }
{ ==================================================================== }

function TLS13ParseServerHello(const ABody: TBytes): TTLS13ServerHello;
var
  Pos, SessLen, ExtTotal, ExtLen: Integer;
  Ext: TTLSExtension;
  Exts: TTLSExtensions;
  HrrRandom: TBytes;
begin
  Pos := 0;
  if Length(ABody) < 2 then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated version');
  Result.LegacyVersion := TLS13ReadWordAt(ABody, Pos);
  Inc(Pos, 2);
  if Length(ABody) < Pos + TLSClientRandomLen then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated random');
  Result.ServerRandom := Copy(ABody, Pos, TLSClientRandomLen);
  Inc(Pos, TLSClientRandomLen);
  if Length(ABody) < Pos + 1 then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated session_id');
  SessLen := ABody[Pos];
  Inc(Pos);
  if (SessLen > TLSMaxSessionIDLen) or (Length(ABody) < Pos + SessLen) then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: invalid session_id');
  Result.SessionID := Copy(ABody, Pos, SessLen);
  Inc(Pos, SessLen);
  if Length(ABody) < Pos + 3 then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: truncated suite/compression');
  Result.CipherSuite := TLS13ReadWordAt(ABody, Pos);
  Inc(Pos, 2);
  { legacy_compression_method must be zero. }
  if ABody[Pos] <> 0 then
    raise ETLS13Error.Create(
      'TLS 1.3 ServerHello: non-zero compression method');
  Inc(Pos);

  Result.IsHelloRetryRequest := False;
  Result.HasKeyShare := False;
  Result.KeyShare := nil;
  Result.RetryGroup := 0;
  Result.SupportedVersion := 0;

  HrrRandom := TLS13HexToBytes(TLS13HelloRetryRequestRandomHex);
  if TLS13ConstEq(Result.ServerRandom, HrrRandom) then
    Result.IsHelloRetryRequest := True;

  if Pos = Length(ABody) then
    Exit;
  if Length(ABody) < Pos + 2 then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated extensions');
  ExtTotal := TLS13ReadWordAt(ABody, Pos);
  if Length(ABody) < Pos + 2 + ExtTotal then
    raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated extensions');
  Exts := DecodeTLSExtensions(Copy(ABody, Pos, ExtTotal + 2));

  if FindTLSExtension(Exts, TLSExtSupportedVersions, Ext) then
  begin
    if Length(Ext.Data) <> 2 then
      raise ETLS13Error.Create(
        'TLS 1.3 ServerHello: bad supported_versions length');
    Result.SupportedVersion := TLS13ReadWordAt(Ext.Data, 0);
  end;
  if FindTLSExtension(Exts, TLSExtKeyShare, Ext) then
  begin
    if Length(Ext.Data) < 2 then
      raise ETLS13Error.Create('TLS 1.3 ServerHello: bad key_share');
    Result.HasKeyShare := True;
    Result.KeyShareGroup := TLS13ReadWordAt(Ext.Data, 0);
    if Result.IsHelloRetryRequest then
    begin
      Result.RetryGroup := Result.KeyShareGroup;
      Result.KeyShare := nil;
    end
    else
    begin
      if Length(Ext.Data) < 4 then
        raise ETLS13Error.Create('TLS 1.3 ServerHello: truncated key_share');
      ExtLen := TLS13ReadWordAt(Ext.Data, 2);
      if Length(Ext.Data) <> 4 + ExtLen then
        raise ETLS13Error.Create('TLS 1.3 ServerHello: bad key_share length');
      Result.KeyShare := Copy(Ext.Data, 4, ExtLen);
    end;
  end;
end;

function TLS13ParseEncryptedExtensions(const ABody: TBytes): TTLSExtensions;
begin
  Result := DecodeTLSExtensions(ABody);
end;

function TLS13ParseCertificate(const ABody: TBytes): TTLSCertificateMessage;
var
  Pos, CtxLen, ListLen, EntryLen, ExtLen, i: Integer;
begin
  Result.Certificates := nil;
  Pos := 0;
  if Length(ABody) < 1 then
    raise ETLS13Error.Create('TLS 1.3 Certificate: empty message');
  CtxLen := ABody[Pos];
  Inc(Pos);
  if Length(ABody) < Pos + CtxLen + 3 then
    raise ETLS13Error.Create('TLS 1.3 Certificate: truncated context/list');
  Inc(Pos, CtxLen);  { certificate_request_context (ignored) }
  ListLen := TLS13ReadTripleAt(ABody, Pos);
  Inc(Pos, 3);
  if Length(ABody) < Pos + ListLen then
    raise ETLS13Error.Create('TLS 1.3 Certificate: truncated certificate_list');
  i := 0;
  while Pos < Length(ABody) do
  begin
    if Length(ABody) < Pos + 3 then
      raise ETLS13Error.Create('TLS 1.3 Certificate: truncated entry length');
    EntryLen := TLS13ReadTripleAt(ABody, Pos);
    Inc(Pos, 3);
    if Length(ABody) < Pos + EntryLen then
      raise ETLS13Error.Create('TLS 1.3 Certificate: truncated certificate');
    SetLength(Result.Certificates, i + 1);
    Result.Certificates[i].Data := Copy(ABody, Pos, EntryLen);
    Inc(Pos, EntryLen);
    { per-certificate extensions }
    if Length(ABody) < Pos + 2 then
      raise ETLS13Error.Create('TLS 1.3 Certificate: truncated extensions');
    ExtLen := TLS13ReadWordAt(ABody, Pos);
    Inc(Pos, 2);
    if Length(ABody) < Pos + ExtLen then
      raise ETLS13Error.Create('TLS 1.3 Certificate: truncated extensions');
    Inc(Pos, ExtLen);
    Inc(i);
  end;
  if Pos <> Length(ABody) then
    raise ETLS13Error.Create('TLS 1.3 Certificate: trailing bytes');
end;

function TLS13ParseCertificateVerify(const ABody: TBytes;
  out AScheme: TTLSSignatureScheme; out ASignature: TBytes): Boolean;
var
  Pos, SigLen: Integer;
begin
  Result := False;
  ASignature := nil;
  Pos := 0;
  if Length(ABody) < 4 then
    raise ETLS13Error.Create('TLS 1.3 CertificateVerify: truncated');
  AScheme := TLS13ReadWordAt(ABody, Pos);
  Inc(Pos, 2);
  SigLen := TLS13ReadWordAt(ABody, Pos);
  Inc(Pos, 2);
  if Length(ABody) <> Pos + SigLen then
    raise ETLS13Error.Create(
      'TLS 1.3 CertificateVerify: bad signature length');
  ASignature := Copy(ABody, Pos, SigLen);
  Result := True;
end;

function TLS13CertificateVerifyContent(const AContextString: string;
  const ATranscriptHash: TBytes): TBytes;
var
  i: Integer;
begin
  SetLength(Result, 64 + Length(AContextString) + 1 + Length(ATranscriptHash));
  for i := 0 to 63 do
    Result[i] := $20;
  for i := 1 to Length(AContextString) do
    Result[64 + i - 1] := Byte(AContextString[i]);
  Result[64 + Length(AContextString)] := 0;
  if Length(ATranscriptHash) > 0 then
    Move(ATranscriptHash[0],
      Result[64 + Length(AContextString) + 1], Length(ATranscriptHash));
end;

function TLS13VerifyCertificateVerify(ACert: TX509Cert;
  const AContent, ASignature: TBytes;
  AScheme: TTLSSignatureScheme): Boolean;
var
  Key: TRSAKey;
  SigBN: TBN;
  Hash: TBytes;
begin
  Result := False;
  if ACert = nil then Exit;
  if Length(AContent) = 0 then Exit;
  if Length(ASignature) = 0 then Exit;

  case AScheme of
    TLSSigRSA_PSS_RSAE_SHA256:
      begin
        if ACert.SPKI.KeyType <> pkRSA then Exit;
        Hash := SHA256(AContent);
        Key := TRSAKey.FromPublic(ACert.SPKI.RSAModulus,
          ACert.SPKI.RSAExponent);
        try
          SigBN := TBN.CreateFromBytes(ASignature, True);
          try
            Result := Key.VerifyPSS(SigBN, Hash, 32);
          finally
            SigBN.Free;
          end;
        finally
          Key.Free;
        end;
      end;
    TLSSigECDSA_Secp256r1_SHA256,
    TLSSigECDSA_Secp384r1_SHA384,
    TLSSigECDSA_Secp521r1_SHA512:
      begin
        if ACert.SPKI.KeyType <> pkEC then Exit;
        Result := VerifyDataSignature(ACert, AContent, ASignature,
          TLS12SignatureSchemeX509OID(AScheme));
      end;
  else
    Result := False;
  end;
end;

{ ==================================================================== }
{ TTLS13Client                                                         }
{ ==================================================================== }

constructor TTLS13Client.Create(ATransport: ITLSTransport;
  ATrustStore: TCertStore; const AServerName: string);
begin
  inherited Create;
  if ATransport = nil then
    raise ETLS13Error.Create('TLS 1.3 client: nil transport');
  FTransport := ATransport;
  FTrustStore := ATrustStore;
  FServerName := AServerName;
  FBuffer := TTLSHandshakeBuffer.Create;
  FConnected := False;
  FClosed := False;
end;

destructor TTLS13Client.Destroy;
var
  i: Integer;
begin
  for i := 0 to High(FKeys) do
    FKeys[i].Free;
  FKeys := nil;
  FBuffer.Free;
  FLeafCert.Free;
  inherited Destroy;
end;

procedure TTLS13Client.SetTrafficKeys(const ASecret: TBytes;
  out AKeys: TTLS13TrafficKeys);
begin
  AKeys := TLS13TrafficKeys(FHashKind, FMode, ASecret);
end;

function TTLS13Client.BuildOptions(
  const AOptions: TTLS13ClientHelloOptions): TTLS13ClientHelloOptions;
var
  Groups: TTLSNamedGroups;
  Key: TTLS13ECDHEKey;
  i: Integer;
begin
  Result := AOptions;
  if Length(Result.ClientRandom) = 0 then
    RandomBytes(Result.ClientRandom, TLSClientRandomLen);
  FClientRandom := Result.ClientRandom;
  if Length(Result.SessionID) = 0 then
    RandomBytes(Result.SessionID, TLSMaxSessionIDLen);
  FSessionID := Result.SessionID;
  if not Result.PskKeyExchangeModes then
    Result.PskKeyExchangeModes := True;
  if Length(Result.CipherSuites) = 0 then
    Result.CipherSuites := TLS13DefaultCipherSuites;
  if Length(Result.SignatureAlgorithms) = 0 then
    Result.SignatureAlgorithms := TLS13DefaultSignatureAlgorithms;

  { Always generate fresh ephemeral keys: the previous ones (if any) are
    dropped, and any caller-supplied public shares without a matching
    private key cannot be used for the ECDHE anyway. }
  for i := 0 to High(FKeys) do
    FKeys[i].Free;
  FKeys := nil;
  Groups := Result.SupportedGroups;
  if Length(Groups) = 0 then
    Groups := TLS13DefaultSupportedGroups;
  SetLength(Result.KeyShares, 0);
  for i := 0 to High(Groups) do
    if TTLS13ECDHEKey.IsSupportedGroup(Groups[i]) then
    begin
      Key := TTLS13ECDHEKey.Create(Groups[i]);
      SetLength(FKeys, Length(FKeys) + 1);
      FKeys[High(FKeys)] := Key;
      SetLength(Result.KeyShares, Length(Result.KeyShares) + 1);
      Result.KeyShares[High(Result.KeyShares)].Group := Groups[i];
      Result.KeyShares[High(Result.KeyShares)].KeyExchange := Key.PublicKey;
    end;
  if Length(Result.KeyShares) = 0 then
    raise ETLS13Error.Create('TLS 1.3: no supported key share group');
end;

function TTLS13Client.KeyForGroup(AGroup: TTLSNamedGroup): TTLS13ECDHEKey;
var
  i: Integer;
begin
  for i := 0 to High(FKeys) do
    if FKeys[i].Group = AGroup then
      Exit(FKeys[i]);
  Result := nil;
end;

function TTLS13Client.ReadRawRecord(out ARec: TTLSRecord): Boolean;
var
  Hdr: TBytes;
  Header: TTLSRecordHeader;
  Got, N: LongInt;
begin
  Result := False;
  SetLength(Hdr, TLSRecordHeaderLen);
  Got := 0;
  while Got < TLSRecordHeaderLen do
  begin
    N := FTransport.Read(Hdr[Got], TLSRecordHeaderLen - Got);
    if N = TLSTransportEOF then
    begin
      if Got = 0 then
        Exit(False);  { clean EOF at a record boundary }
      raise ETLS13Error.Create('TLS 1.3: truncated record header at EOF');
    end;
    if N = TLSTransportError then
      raise ETLS13Error.Create(
        'TLS 1.3: transport error reading record header');
    Inc(Got, N);
  end;
  Header := DecodeTLSRecordHeader(Hdr);
  if Header.Length > TLSRecordMaxCiphertext then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3 record: length %d exceeds limit', [Header.Length]);
  SetLength(ARec.Fragment, Header.Length);
  Got := 0;
  while Got < Integer(Header.Length) do
  begin
    N := FTransport.Read(ARec.Fragment[Got], Integer(Header.Length) - Got);
    if N <= 0 then
      raise ETLS13Error.Create('TLS 1.3: truncated record fragment');
    Inc(Got, N);
  end;
  ARec.ContentType := Header.ContentType;
  ARec.Version := Header.Version;
  Result := True;
end;

function TTLS13Client.ReadHandshakeMessage(
  out AMsg: TTLSHandshakeMessage): Boolean;
var
  Rec: TTLSRecord;
  Ct: TTLSContentType;
  Plain: TBytes;
begin
  repeat
    if FBuffer.TryTakeMessage(AMsg) then
      Exit(True);
    if not ReadRawRecord(Rec) then
      Exit(False);
    { Middlebox-compatibility ChangeCipherSpec is not a handshake message. }
    if Rec.ContentType = ctChangeCipherSpec then
      Continue;
    if Rec.ContentType <> ctApplicationData then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 handshake: unexpected record type %d',
        [Ord(Rec.ContentType)]);
    if not TLS13UnprotectRecord(FMode, FReadKeys.Key, FReadKeys.IV,
      FReadSeq, Rec.Fragment, Ct, Plain) then
      raise ETLS13Error.Create(
        'TLS 1.3 handshake: record authentication failed');
    Inc(FReadSeq);
    if Ct <> ctHandshake then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 handshake: unexpected inner content type %d', [Ord(Ct)]);
    FBuffer.Append(Plain);
  until False;
end;

procedure TTLS13Client.VerifyServerCertificate(
  const ACertMsg: TTLSCertificateMessage);
var
  Chain: TTLS12CertChain;
  VR: TVerifyResult;
begin
  if Length(ACertMsg.Certificates) = 0 then
    raise ETLS13Error.Create(
      'TLS 1.3: server sent an empty certificate chain');
  Chain := ParseTLS12CertChain(ACertMsg);
  try
    if FTrustStore = nil then
      raise ETLS13Error.Create('TLS 1.3: no trust store configured');
    VR := Chain.Verify(FTrustStore);
    if not VR.OK then
      raise ETLS13Error.Create('TLS 1.3: certificate chain rejected: ' +
        VR.Reason);
    FLeafCert.Free;
    FLeafCert := ParseCertificate(ACertMsg.Certificates[0].Data);
    if (FServerName <> '') and
      (not CertMatchesHost(FLeafCert, FServerName)) then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: certificate does not match host "%s"', [FServerName]);
  finally
    Chain.Free;
  end;
end;

procedure TTLS13Client.VerifyCertificateVerify(const ABody: TBytes;
  const ATranscriptHash: TBytes);
var
  Scheme: TTLSSignatureScheme;
  Signature, Content: TBytes;
begin
  TLS13ParseCertificateVerify(ABody, Scheme, Signature);
  Content := TLS13CertificateVerifyContent(TLS13ContextStringServer,
    ATranscriptHash);
  if not TLS13VerifyCertificateVerify(FLeafCert, Content, Signature, Scheme)
  then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: CertificateVerify signature invalid (scheme 0x%.4x)',
      [Scheme]);
end;

procedure TTLS13Client.ProcessServerFlight(
  out ATranscriptThroughServerFinished: TBytes);
var
  Msg: TTLSHandshakeMessage;
  CertMsg: TTLSCertificateMessage;
  TranscriptThroughCert, TranscriptThroughCV: TBytes;
  Expected, Actual, FinishedKey: TBytes;
  GotCert: Boolean;
begin
  ATranscriptThroughServerFinished := nil;
  CertMsg.Certificates := nil;
  GotCert := False;
  TranscriptThroughCert := nil;
  TranscriptThroughCV := nil;

  repeat
    if not ReadHandshakeMessage(Msg) then
      raise ETLS13Error.Create(
        'TLS 1.3: connection closed before server Finished');
    case Msg.MsgType of
      htEncryptedExtensions:
        TLS13ParseEncryptedExtensions(Msg.Body);
      htCertificate:
        begin
          CertMsg := TLS13ParseCertificate(Msg.Body);
          VerifyServerCertificate(CertMsg);
          TranscriptThroughCert := Copy(FBuffer.Transcript, 0,
            Length(FBuffer.Transcript));
          GotCert := True;
        end;
      htCertificateVerify:
        begin
          if not GotCert then
            raise ETLS13Error.Create(
              'TLS 1.3: CertificateVerify before Certificate');
          VerifyCertificateVerify(Msg.Body,
            TLS13TranscriptHash(FHashKind, TranscriptThroughCert));
          TranscriptThroughCV := Copy(FBuffer.Transcript, 0,
            Length(FBuffer.Transcript));
        end;
      htFinished:
        begin
          if Length(TranscriptThroughCV) = 0 then
            raise ETLS13Error.Create(
              'TLS 1.3: Finished before CertificateVerify');
          Actual := Msg.Body;
          FinishedKey := TLS13FinishedKey(FHashKind, FServerHSSecret);
          Expected := THMAC.Compute(FHashKind, FinishedKey,
            TLS13TranscriptHash(FHashKind, TranscriptThroughCV));
          if not TLS13ConstEq(Actual, Expected) then
            raise ETLS13Error.Create(
              'TLS 1.3: server Finished does not verify');
          ATranscriptThroughServerFinished := Copy(FBuffer.Transcript, 0,
            Length(FBuffer.Transcript));
          Break;
        end;
      htNewSessionTicket, htKeyUpdate, htCertificateRequest:
        raise ETLS13Error.CreateFmt(
          'TLS 1.3: unexpected handshake message %d during handshake',
          [Ord(Msg.MsgType)]);
    else
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: unexpected handshake message %d', [Ord(Msg.MsgType)]);
    end;
  until False;
end;

procedure TTLS13Client.SwitchToApplicationKeys;
begin
  SetTrafficKeys(FServerAppSecret, FReadKeys);
  SetTrafficKeys(FClientAppSecret, FWriteKeys);
  FReadSeq := 0;
  FWriteSeq := 0;
end;

procedure TTLS13Client.Connect;
begin
  Connect(Default(TTLS13ClientHelloOptions));
end;

procedure TTLS13Client.Connect(const AOptions: TTLS13ClientHelloOptions);
var
  Options: TTLS13ClientHelloOptions;
  CHBody, CHMsg, Shared, TranscriptCHSH: TBytes;
  SrvHello: TTLS13ServerHello;
  Msg: TTLSHandshakeMessage;
  Key: TTLS13ECDHEKey;
  HandshakeSecret, MasterSecret: TBytes;
  TranscriptThroughServerFinished: TBytes;
  Rec: TTLSRecord;
begin
  if FConnected then
    raise ETLS13Error.Create('TLS 1.3 client: already connected');

  Options := BuildOptions(AOptions);
  CHBody := TLS13BuildClientHelloBody(Options);
  CHMsg := EncodeTLSHandshakeMessage(htClientHello, CHBody);
  WriteTLSFragmented(FTransport, ctHandshake, CHMsg, TLS13LegacyVersion);
  FBuffer.AppendTranscript(htClientHello, CHBody);
  { Middlebox compatibility: dummy CCS right after the first ClientHello. }
  WriteTLSRecord(FTransport, ctChangeCipherSpec, EncodeTLSChangeCipherSpec,
    TLS13LegacyVersion);

  { ServerHello (plaintext handshake record; skip CCS records). }
  repeat
    if not ReadRawRecord(Rec) then
      raise ETLS13Error.Create(
        'TLS 1.3: connection closed before ServerHello');
    if Rec.ContentType = ctChangeCipherSpec then
      Continue;
    if Rec.ContentType <> ctHandshake then
      raise ETLS13Error.CreateFmt(
        'TLS 1.3: expected ServerHello record, got %d',
        [Ord(Rec.ContentType)]);
    FBuffer.Append(Rec.Fragment);
  until FBuffer.HasCompleteMessage;
  Msg := FBuffer.TakeMessage;
  if Msg.MsgType <> htServerHello then
    raise ETLS13Error.Create(
      'TLS 1.3: first server message is not ServerHello');
  SrvHello := TLS13ParseServerHello(Msg.Body);
  if SrvHello.IsHelloRetryRequest then
    raise ETLS13Error.Create('TLS 1.3: HelloRetryRequest is not supported');
  if SrvHello.SupportedVersion <> TLS13Version then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: server did not negotiate TLS 1.3 (0x%.4x)',
      [SrvHello.SupportedVersion]);
  if not TLS13CipherSuiteSupported(SrvHello.CipherSuite) then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: server selected unsupported suite 0x%.4x',
      [SrvHello.CipherSuite]);
  if not SrvHello.HasKeyShare then
    raise ETLS13Error.Create('TLS 1.3: ServerHello without key_share');

  FNegotiatedGroup := SrvHello.KeyShareGroup;
  Key := KeyForGroup(FNegotiatedGroup);
  if Key = nil then
    raise ETLS13Error.CreateFmt(
      'TLS 1.3: server chose group %s we did not offer',
      [TTLS13ECDHEKey.GroupName(FNegotiatedGroup)]);
  Shared := Key.SharedSecret(SrvHello.KeyShare);

  FHashKind := TLS13CipherSuiteHashKind(SrvHello.CipherSuite);
  FMode := TLS13CipherSuiteAEADMode(SrvHello.CipherSuite);
  FCipherSuite := SrvHello.CipherSuite;
  TranscriptCHSH := Copy(FBuffer.Transcript, 0, Length(FBuffer.Transcript));

  HandshakeSecret := TLS13HandshakeSecret(FHashKind, Shared);
  FServerHSSecret := TLS13TrafficSecret(FHashKind, HandshakeSecret,
    's hs traffic', TranscriptCHSH);
  FClientHSSecret := TLS13TrafficSecret(FHashKind, HandshakeSecret,
    'c hs traffic', TranscriptCHSH);
  SetTrafficKeys(FServerHSSecret, FReadKeys);
  SetTrafficKeys(FClientHSSecret, FWriteKeys);
  FReadSeq := 0;
  FWriteSeq := 0;

  ProcessServerFlight(TranscriptThroughServerFinished);

  { Master secret and application traffic secrets (transcript through the
    server Finished). }
  MasterSecret := TLS13MasterSecret(FHashKind, HandshakeSecret);
  FServerAppSecret := TLS13TrafficSecret(FHashKind, MasterSecret,
    's ap traffic', TranscriptThroughServerFinished);
  FClientAppSecret := TLS13TrafficSecret(FHashKind, MasterSecret,
    'c ap traffic', TranscriptThroughServerFinished);

  { Client Finished, protected with the client handshake traffic key. }
  Msg.MsgType := htFinished;
  Msg.Body := TLS13FinishedBody(TLS13FinishedVerifyData(FHashKind,
    FClientHSSecret, TranscriptThroughServerFinished));
  FBuffer.AppendTranscript(Msg);
  TLS13WriteRecord(FTransport, FMode, FWriteKeys.Key, FWriteKeys.IV,
    FWriteSeq, ctHandshake,
    EncodeTLSHandshakeMessage(htFinished, Msg.Body));

  SwitchToApplicationKeys;
  FConnected := True;
end;

procedure TTLS13Client.SendApplicationData(const AData: TBytes);
begin
  if not FConnected then
    raise ETLS13Error.Create('TLS 1.3 client: not connected');
  TLS13WriteRecord(FTransport, FMode, FWriteKeys.Key, FWriteKeys.IV,
    FWriteSeq, ctApplicationData, AData);
end;

function TTLS13Client.ReceiveApplicationData(out AData: TBytes): Boolean;
var
  Rec: TTLSRecord;
  Ct: TTLSContentType;
  Plain: TBytes;
  Msg: TTLSHandshakeMessage;
  tmp: TTLSHandshakeBuffer;
begin
  AData := nil;
  if FClosed then
    Exit(False);
  repeat
    if not ReadRawRecord(Rec) then
    begin
      FClosed := True;
      Exit(False);
    end;
    if Rec.ContentType = ctChangeCipherSpec then
      Continue;
    if Rec.ContentType <> ctApplicationData then
    begin
      if Rec.ContentType = ctAlert then
      begin
        FClosed := True;
        Exit(False);
      end;
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 application: unexpected record type %d',
        [Ord(Rec.ContentType)]);
    end;
    if not TLS13UnprotectRecord(FMode, FReadKeys.Key, FReadKeys.IV,
      FReadSeq, Rec.Fragment, Ct, Plain) then
      raise ETLS13Error.Create(
        'TLS 1.3 application: record authentication failed');
    Inc(FReadSeq);
    case Ct of
      ctApplicationData:
        begin
          AData := Plain;
          Exit(True);
        end;
      ctAlert:
        begin
          { close_notify (warning, description 0) ends the session. }
          if (Length(Plain) >= 2) and (Plain[1] = 0) then
          begin
            FClosed := True;
            Exit(False);
          end;
          raise ETLS13Error.CreateFmt(
            'TLS 1.3: received alert %d', [Plain[1]]);
        end;
      ctHandshake:
        begin
          { Post-handshake: skip NewSessionTicket; reject KeyUpdate. }
          tmp := TTLSHandshakeBuffer.Create;
          try
            tmp.Append(Plain);
            while tmp.TryTakeMessage(Msg) do
              if Msg.MsgType = htKeyUpdate then
                raise ETLS13Error.Create(
                  'TLS 1.3: post-handshake KeyUpdate is not supported');
          finally
            tmp.Free;
          end;
        end;
    else
      raise ETLS13Error.CreateFmt(
        'TLS 1.3 application: unexpected inner content type %d', [Ord(Ct)]);
    end;
  until False;
end;

procedure TTLS13Client.SendCloseNotify;
var
  Alert: TBytes;
begin
  if not FConnected then
    Exit;
  SetLength(Alert, 2);
  Alert[0] := TLSAlertLevelWarning;
  Alert[1] := Ord(adCloseNotify);
  try
    TLS13WriteRecord(FTransport, FMode, FWriteKeys.Key, FWriteKeys.IV,
      FWriteSeq, ctAlert, Alert);
  except
    { A close on an already-broken transport is not an error for the caller. }
  end;
  FClosed := True;
end;

end.
