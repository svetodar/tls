unit test_tls12;
{TLS 1.2 tests (RFC 5246): ITLSTransport mock transport, record layer,
  handshake flight and failure/error handling.

  All handshake tests run through the mock transport (no network): the server
  "responds" with pre-assembled bytes, the client reads them with the same code
  it would use to read a socket.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TTLSTests = class(TTestCase)
  published
    { --- mock ITLSTransport --- }
    procedure TestMockTransportReadWrite;
    procedure TestMockTransportEOFSemantics;
    procedure TestMockTransportReadErrorRaises;
    procedure TestMockTransportPartialReads;
    procedure TestMockTransportPartialWrites;

    { --- ClientHello via mock --- }
    procedure TestClientHelloRoundTripThroughMock;
    procedure TestClientHelloDefaultsAreSupported;

    { --- server flight --- }
    procedure TestReadServerFlightSingleRecord;
    procedure TestReadServerFlightSplitAcrossRecords;
    procedure TestReadServerFlightAcrossTransportReads;
    procedure TestHandshakeBufferTranscript;
    procedure TestParseServerFlightWithoutHelloDoneReturnsFalse;
    procedure TestReadHandshakeFlightWrongRecordTypeRaises;
    procedure TestReadHandshakeFlightEOFBeforeTerminatorRaises;

    { --- record layer failures --- }
    procedure TestTruncatedRecordRaises;
    procedure TestTruncatedRecordHeaderRaises;
    procedure TestOversizedPlaintextRecordRaises;
    procedure TestOversizedCiphertextLengthRaises;
    procedure TestUnknownContentTypeRaises;

    { --- ChangeCipherSpec --- }
    procedure TestChangeCipherSpecRoundTrip;
    procedure TestInvalidChangeCipherSpecRaises;
    procedure TestChangeCipherSpecWrongRecordTypeRaises;

    { --- Finished / VerifyData --- }
    procedure TestFinishedVerifyDataCheck;
    procedure TestWrongFinishedVerifyDataRejected;

    { --- Alert --- }
    procedure TestAlertRoundTrip;
    procedure TestFatalAlert;
    procedure TestMalformedAlertRaises;
    procedure TestReadAlertWrongRecordTypeRaises;
  end;

implementation

uses
  SysUtils, tls.tls12, tls.sha2, tls.hmac;

{ ==================================================================== }
{ Helper functions                                              }
{ ==================================================================== }
function W16(AValue: Word): TBytes;
begin
  Result := nil;
  SetLength(Result, 2);
  Result[0] := Byte((AValue shr 8) and $FF);
  Result[1] := Byte(AValue and $FF);
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

function StrBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  Result := nil;
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

function SeqBytes(ACount: Integer; AStart: Byte): TBytes;
var
  i: Integer;
begin
  Result := nil;
  SetLength(Result, ACount);
  for i := 0 to ACount - 1 do
    Result[i] := Byte((AStart + i) and $FF);
end;

function BytesEqual(const A, B: TBytes): Boolean;
begin
  Result := (Length(A) = Length(B)) and
    ((Length(A) = 0) or CompareMem(@A[0], @B[0], Length(A)));
end;

{ Wraps a byte stream into a sequence of handshake records of
  AChunk bytes each: models splitting a handshake message into
  several TLS records. }
function WrapRecords(const AData: TBytes; AChunk: Integer;
  AContentType: TTLSContentType = ctHandshake): TBytes;
var
  Offset, N: Integer;
begin
  Result := nil;
  Offset := 0;
  while Offset < Length(AData) do
  begin
    N := Length(AData) - Offset;
    if (AChunk > 0) and (N > AChunk) then
      N := AChunk;
    Result := Cat(Result,
      EncodeTLSRecord(AContentType, Copy(AData, Offset, N)));
    Inc(Offset, N);
  end;
end;

{ ==================================================================== }
{ Mock ITLSTransport                                                   }
{ ==================================================================== }
type
  { Controlled mock transport: "incoming" bytes are set in advance,
    written bytes are accumulated. Allows limiting the size of
    read/write at a time (partial Read/Write) and simulating a transport
    error at a given position. }
  TMockTLSTransport = class(TObject, ITLSTransport)
  private
    FReadData: TBytes;
    FReadPos: Integer;
    FReadChunk: Integer;
    FReadErrorPos: Integer;
    FWriteData: TBytes;
    FWriteChunk: Integer;
    { IInterface: the mock is not reference-counted and lives until Free.
      _AddRef/_Release do nothing — otherwise a temporary interface
      parameter would free the object on the first call through the interface. }
    function QueryInterface(
      {$IFDEF FPC_HAS_CONSTREF}constref{$ELSE}const{$ENDIF} iid: TGuid;
      out obj): LongInt; {$IFNDEF WINDOWS}cdecl{$ELSE}stdcall{$ENDIF};
    function _AddRef: LongInt; {$IFNDEF WINDOWS}cdecl{$ELSE}stdcall{$ENDIF};
    function _Release: LongInt; {$IFNDEF WINDOWS}cdecl{$ELSE}stdcall{$ENDIF};
  public
    constructor Create;
    procedure SetReadData(const AData: TBytes);
    { Maximum bytes given/received per call (0 — no limit). }
    property ReadChunk: Integer read FReadChunk write FReadChunk;
    property WriteChunk: Integer read FWriteChunk write FWriteChunk;
    { If >= 0: starting from this position Read returns TLSTransportError. }
    property ReadErrorPos: Integer read FReadErrorPos write FReadErrorPos;
    { Written bytes (as "sent" by the client). }
    function WrittenData: TBytes;
    { --- ITLSTransport --- }
    function Read(var ABuffer; ACount: LongInt): LongInt;
    function Write(const ABuffer; ACount: LongInt): LongInt;
    function BytesAvailable: LongInt;
  end;
{ IInterface: reference counting disabled (mock lives until Free). }
function TMockTLSTransport.QueryInterface(
  {$IFDEF FPC_HAS_CONSTREF}constref{$ELSE}const{$ENDIF} iid: TGuid;
  out obj): LongInt; {$IFNDEF WINDOWS}cdecl{$ELSE}stdcall{$ENDIF};
begin
  if GetInterface(iid, obj) then
    Result := 0
  else
    Result := LongInt($80004002);  { E_NOINTERFACE }
end;

function TMockTLSTransport._AddRef: LongInt;
  {$IFNDEF WINDOWS}cdecl{$ELSE}stdcall{$ENDIF};
begin
  Result := -1;
end;

function TMockTLSTransport._Release: LongInt;
  {$IFNDEF WINDOWS}cdecl{$ELSE}stdcall{$ENDIF};
begin
  Result := -1;
end;

constructor TMockTLSTransport.Create;
begin
  inherited Create;
  FReadErrorPos := -1;
end;

procedure TMockTLSTransport.SetReadData(const AData: TBytes);
begin
  FReadData := AData;
  FReadPos := 0;
end;

function TMockTLSTransport.WrittenData: TBytes;
begin
  Result := FWriteData;
end;

function TMockTLSTransport.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  if ACount < 0 then
    raise ETLS12Error.Create('mock transport: negative read length');
  if ACount = 0 then
    Exit(0);
  if (FReadErrorPos >= 0) and (FReadPos >= FReadErrorPos) then
    Exit(TLSTransportError);
  if FReadPos >= Length(FReadData) then
    Exit(TLSTransportEOF);
  Result := Length(FReadData) - FReadPos;
  if (FReadChunk > 0) and (Result > FReadChunk) then
    Result := FReadChunk;
  if Result > ACount then
    Result := ACount;
  Move(FReadData[FReadPos], ABuffer, Result);
  Inc(FReadPos, Result);
end;

function TMockTLSTransport.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  if ACount < 0 then
    raise ETLS12Error.Create('mock transport: negative write length');
  if ACount = 0 then
    Exit(0);
  Result := ACount;
  if (FWriteChunk > 0) and (Result > FWriteChunk) then
    Result := FWriteChunk;
  SetLength(FWriteData, Length(FWriteData) + Result);
  Move(ABuffer, FWriteData[Length(FWriteData) - Result], Result);
end;

function TMockTLSTransport.BytesAvailable: LongInt;
begin
  Result := Length(FReadData) - FReadPos;
  if Result < 0 then
    Result := 0;
end;

{ ==================================================================== }
{ Synthetic server flight                                        }
{ ==================================================================== }

function ServerHelloExtensionBlock: TBytes;
var
  Exts: TTLSExtensions;
begin
  SetLength(Exts, 2);
  Exts[0] := EncodeTLSExtendedMasterSecretExtension;
  Exts[1].ExtType := TLSExtServerName;  { empty ack on SNI }
  Exts[1].Data := nil;
  Result := EncodeTLSExtensions(Exts);
end;

function BuildServerHelloBody(ACipherSuite: TTLSCipherSuite): TBytes;
var
  Rnd: TBytes;
begin
  Rnd := SeqBytes(TLSClientRandomLen, 1);
  Result := Cat(W16(TLS12Version), Rnd);
  Result := Cat(Result, B1(0));                        { session_id: empty }
  Result := Cat(Result, W16(ACipherSuite));
  Result := Cat(Result, B1(0));                        { compression: null }
  Result := Cat(Result, ServerHelloExtensionBlock);
end;

function HSMessage(AType: TTLSHandshakeType;
  const ABody: TBytes): TTLSHandshakeMessage;
begin
  Result.MsgType := AType;
  Result.Body := ABody;
end;

{ Raw stream: ServerHello || ServerHelloDone (without record headers). }
function BuildServerFlightBytes: TBytes;
var
  Msgs: TTLSHandshakeMessages;
begin
  SetLength(Msgs, 2);
  Msgs[0] := HSMessage(htServerHello,
    BuildServerHelloBody(TLSCipherECDHE_RSA_AES128GCM_SHA256));
  Msgs[1] := HSMessage(htServerHelloDone, nil);
  Result := EncodeTLSHandshakeFlight(Msgs);
end;

{ ==================================================================== }
{ Mock transport tests                                                }
{ ==================================================================== }

procedure TTLSTests.TestMockTransportReadWrite;
var
  T: TMockTLSTransport;
  Buf: TBytes;
begin
  T := TMockTLSTransport.Create;
  try
    T.SetReadData(HexToBytes('0102030405'));
    AssertEquals('BytesAvailable=5', 5, T.BytesAvailable);

    SetLength(Buf, 3);
    AssertEquals('Read(3)', 3, T.Read(Buf[0], 3));
    AssertEquals('read 010203', '010203', BytesToHex(Buf, 3));
    AssertEquals('remainder 2', 2, T.BytesAvailable);

    AssertEquals('Read(3) collects 2 more', 2, T.Read(Buf[0], 3));
    AssertEquals('0102030405', '0102030405',
      BytesToHex(Cat(HexToBytes('010203'), Copy(Buf, 0, 2))));

    Buf := HexToBytes('AABBCC');
    AssertEquals('Write(3)', 3, T.Write(Buf[0], 3));
    AssertEquals('wrote aabbcc', 'aabbcc', BytesToHex(T.WrittenData));
  finally
    T.Free;
  end;
end;

procedure TTLSTests.TestMockTransportEOFSemantics;
var
  T: TMockTLSTransport;
  B: Byte;
begin
  T := TMockTLSTransport.Create;
  try
    T.SetReadData(nil);
    AssertEquals('empty stream: BytesAvailable=0', 0, T.BytesAvailable);
    AssertEquals('empty stream: Read=EOF(0)', TLSTransportEOF, T.Read(B, 1));

    T.SetReadData(B1($42));
    AssertEquals('Read(1)', 1, T.Read(B, 1));
    AssertEquals('byte $42', $42, Integer(B));
    AssertEquals('EOF again after read', TLSTransportEOF, T.Read(B, 1));
  finally
    T.Free;
  end;
end;

procedure TTLSTests.TestMockTransportReadErrorRaises;
var
  T: TMockTLSTransport;
  Buf: array[0..7] of Byte;
  Failed: Boolean;
begin
  T := TMockTLSTransport.Create;
  try
    T.SetReadData(SeqBytes(8, 0));
    T.ReadErrorPos := 3;
    T.ReadChunk := 1;  { partial reads so the error triggers }
    Failed := False;
    try
      TLSReadAll(T, Buf, 8);
    except
      on E: ETLS12Error do
        Failed := True;
    end;
    AssertTrue('transport error is converted to ETLS12Error', Failed);

    { Direct Read reports error as a negative value. }
    AssertEquals('Read(-1) on error', TLSTransportError, T.Read(Buf[0], 1));
  finally
    T.Free;
  end;
end;

procedure TTLSTests.TestMockTransportPartialReads;
var
  T: TMockTLSTransport;
  Rec: TTLSRecord;
begin
  T := TMockTLSTransport.Create;
  try
    T.SetReadData(EncodeTLSRecord(ctHandshake, HexToBytes('0102030405')));
    T.ReadChunk := 1;  { one byte per call }
    Rec := ReadTLSRecord(T);
    AssertEquals('handshake record type', Ord(ctHandshake),
      Ord(Rec.ContentType));
    AssertEquals('fragment length', 5, Length(Rec.Fragment));
    AssertEquals('fragment 0102030405', '0102030405',
      BytesToHex(Rec.Fragment));
  finally
    T.Free;
  end;
end;

procedure TTLSTests.TestMockTransportPartialWrites;
var
  T: TMockTLSTransport;
begin
  T := TMockTLSTransport.Create;
  try
    T.WriteChunk := 1;  { transport accepts 1 byte at a time }
    WriteTLSRecord(T, ctHandshake, HexToBytes('DEADBEEF'));
    AssertEquals('TLSWriteAll collects all bytes',
      BytesToHex(EncodeTLSRecord(ctHandshake, HexToBytes('DEADBEEF'))),
      BytesToHex(T.WrittenData));
  finally
    T.Free;
  end;
end;

{ ==================================================================== }
{ ClientHello via mock                                               }
{ ==================================================================== }

procedure TTLSTests.TestClientHelloRoundTripThroughMock;
var
  W: TMockTLSTransport;
  Opts: TTLSClientHelloOptions;
  Raw, ExpectedRandom: TBytes;
  Rec: TTLSRecord;
  Msg: TTLSHandshakeMessage;
  CH: TTLSClientHello;
  i: Integer;
begin
  Opts := DefaultTLS12ClientHelloOptions;
  Opts.ServerName := 'example.com';
  SetLength(ExpectedRandom, TLSClientRandomLen);
  for i := 0 to High(ExpectedRandom) do
    ExpectedRandom[i] := Byte(i);
  Opts.ClientRandom := ExpectedRandom;

  W := TMockTLSTransport.Create;
  try
    WriteTLS12ClientHello(W, Opts);
    Raw := W.WrittenData;
  finally
    W.Free;
  end;

  W := TMockTLSTransport.Create;
  try
    W.SetReadData(Raw);
    Rec := ReadTLSRecord(W);
    AssertEquals('handshake record', Ord(ctHandshake), Ord(Rec.ContentType));
    Msg := DecodeTLSHandshakeMessage(Rec.Fragment);
    AssertEquals('ClientHello message', Ord(htClientHello), Ord(Msg.MsgType));

    CH := ParseTLS12ClientHello(Msg.Body);
    AssertEquals('version', Integer(TLS12Version), Integer(CH.Version));
    AssertTrue('client_random matched',
      BytesEqual(ExpectedRandom, CH.ClientRandom));
    AssertEquals('SNI', 'example.com', CH.ServerName);
    AssertTrue('extended_master_secret', CH.ExtendedMasterSecret);
    AssertTrue('renegotiation_info', CH.RenegotiationInfo);
    AssertTrue('cipher_suites non-empty', Length(CH.CipherSuites) > 0);
    AssertTrue('supported_groups non-empty', Length(CH.SupportedGroups) > 0);
    AssertTrue('signature_algorithms non-empty',
      Length(CH.SignatureAlgorithms) > 0);
  finally
    W.Free;
  end;
end;

procedure TTLSTests.TestClientHelloDefaultsAreSupported;
var
  Suites: TTLSCipherSuites;
  i: Integer;
begin
  Suites := TLS12DefaultCipherSuites;
  AssertTrue('default suites present', Length(Suites) > 0);
  for i := 0 to High(Suites) do
    AssertTrue('suite ' + TLSCipherSuiteName(Suites[i]) + ' supported',
      TLS12CipherSuiteSupported(Suites[i]));
  { CBC/static-RSA intentionally not supported. }
  AssertFalse('CBC not supported',
    TLS12CipherSuiteSupported(TLSCipherECDHE_RSA_AES128CBC_SHA));
  AssertFalse('static RSA not supported',
    TLS12CipherSuiteSupported(TLSCipherRSA_AES128GCM_SHA256));
end;

{ ==================================================================== }
{ Server flight                                                      }
{ ==================================================================== }

procedure TTLSTests.TestReadServerFlightSingleRecord;
var
  T: TMockTLSTransport;
  Buf: TTLSHandshakeBuffer;
  Msgs: TTLSHandshakeMessages;
  Hello: TTLSServerHello;
  Certs: TTLSCertificateMessage;
  SKE: TTLSServerKeyExchange;
  HasCerts, HasKE: Boolean;
begin
  T := TMockTLSTransport.Create;
  Buf := TTLSHandshakeBuffer.Create;
  try
    T.SetReadData(EncodeTLSRecord(ctHandshake, BuildServerFlightBytes));
    AssertTrue('flight read',
      ReadTLSHandshakeFlight(T, Buf, [htServerHelloDone], Msgs));
    AssertEquals('two messages', 2, Length(Msgs));
    AssertEquals('0 = ServerHello', Ord(htServerHello), Ord(Msgs[0].MsgType));
    AssertEquals('1 = ServerHelloDone', Ord(htServerHelloDone),
      Ord(Msgs[1].MsgType));

    AssertTrue('ParseTLS12ServerFlight',
      ParseTLS12ServerFlight(Msgs, Hello, Certs, SKE, HasCerts, HasKE));
    AssertEquals('cipher_suite', Integer(TLSCipherECDHE_RSA_AES128GCM_SHA256),
      Integer(Hello.CipherSuite));
    AssertEquals('version', Integer(TLS12Version), Integer(Hello.Version));
    AssertEquals('compression = null', 0, Integer(Hello.CompressionMethod));
    AssertTrue('EMS confirmed', Hello.ExtendedMasterSecret);
    AssertTrue('SNI confirmed', Hello.ServerNameAcknowledged);
    AssertFalse('no Certificate', HasCerts);
    AssertFalse('no ServerKeyExchange', HasKE);
  finally
    Buf.Free;
    T.Free;
  end;
end;

procedure TTLSTests.TestReadServerFlightSplitAcrossRecords;
var
  T: TMockTLSTransport;
  Buf: TTLSHandshakeBuffer;
  Msgs: TTLSHandshakeMessages;
  Flight: TBytes;
begin
  Flight := BuildServerFlightBytes;
  T := TMockTLSTransport.Create;
  Buf := TTLSHandshakeBuffer.Create;
  try
    { Message split into 7-byte records. }
    T.SetReadData(WrapRecords(Flight, 7));
    AssertTrue('flight assembled from multiple records',
      ReadTLSHandshakeFlight(T, Buf, [htServerHelloDone], Msgs));
    AssertEquals('two messages', 2, Length(Msgs));
    AssertTrue('transcript matched the original flight',
      BytesEqual(Flight, Buf.Transcript));
  finally
    Buf.Free;
    T.Free;
  end;
end;

procedure TTLSTests.TestReadServerFlightAcrossTransportReads;
var
  T: TMockTLSTransport;
  Buf: TTLSHandshakeBuffer;
  Msgs: TTLSHandshakeMessages;
  Flight: TBytes;
begin
  Flight := BuildServerFlightBytes;
  T := TMockTLSTransport.Create;
  Buf := TTLSHandshakeBuffer.Create;
  try
    T.SetReadData(EncodeTLSRecord(ctHandshake, Flight));
    T.ReadChunk := 1;  {transport yields one byte at a time}
    AssertTrue('flight assembled from partial reads',
      ReadTLSHandshakeFlight(T, Buf, [htServerHelloDone], Msgs));
    AssertEquals('two messages', 2, Length(Msgs));
    AssertTrue('transcript matched', BytesEqual(Flight, Buf.Transcript));
  finally
    Buf.Free;
    T.Free;
  end;
end;

procedure TTLSTests.TestHandshakeBufferTranscript;
var
  Buf: TTLSHandshakeBuffer;
  Msg: TTLSHandshakeMessage;
  Flight: TBytes;
  Count: Integer;
begin
  Flight := BuildServerFlightBytes;
  Buf := TTLSHandshakeBuffer.Create;
  try
    Buf.Append(Flight);
    Count := 0;
    while Buf.TryTakeMessage(Msg) do
      Inc(Count);
    AssertEquals('two messages in buffer', 2, Count);
    AssertEquals('buffer empty', 0, Buf.PendingBytes);
    AssertTrue('transcript == raw messages',
      BytesEqual(Flight, Buf.Transcript));
    AssertEquals('transcript length', Length(Flight), Buf.TranscriptLength);
  finally
    Buf.Free;
  end;
end;

procedure TTLSTests.TestParseServerFlightWithoutHelloDoneReturnsFalse;
var
  Msgs: TTLSHandshakeMessages;
  Hello: TTLSServerHello;
  Certs: TTLSCertificateMessage;
  SKE: TTLSServerKeyExchange;
  HasCerts, HasKE: Boolean;
begin
  SetLength(Msgs, 1);
  Msgs[0] := HSMessage(htServerHello,
    BuildServerHelloBody(TLSCipherECDHE_RSA_AES128GCM_SHA256));
  AssertFalse('no ServerHelloDone → False',
    ParseTLS12ServerFlight(Msgs, Hello, Certs, SKE, HasCerts, HasKE));
end;

procedure TTLSTests.TestReadHandshakeFlightWrongRecordTypeRaises;
var
  T: TMockTLSTransport;
  Buf: TTLSHandshakeBuffer;
  Msgs: TTLSHandshakeMessages;
  Failed: Boolean;
begin
  T := TMockTLSTransport.Create;
  Buf := TTLSHandshakeBuffer.Create;
  try
    {An alert arrives in place of handshake.}
    T.SetReadData(EncodeTLSRecord(ctAlert, EncodeTLSAlert(alFatal,
      adHandshakeFailure)));
    Failed := False;
    try
      ReadTLSHandshakeFlight(T, Buf, [htServerHelloDone], Msgs);
    except
      on E: ETLS12Error do
        Failed := True;
    end;
    AssertTrue('foreign record type → ETLS12Error', Failed);
  finally
    Buf.Free;
    T.Free;
  end;
end;

procedure TTLSTests.TestReadHandshakeFlightEOFBeforeTerminatorRaises;
var
  T: TMockTLSTransport;
  Buf: TTLSHandshakeBuffer;
  Msgs: TTLSHandshakeMessages;
  Failed: Boolean;
begin
  T := TMockTLSTransport.Create;
  Buf := TTLSHandshakeBuffer.Create;
  try
    {Only ServerHello was sent, then the stream closed.}
    T.SetReadData(EncodeTLSRecord(ctHandshake,
      EncodeTLSHandshakeMessage(htServerHello,
        BuildServerHelloBody(TLSCipherECDHE_RSA_AES128GCM_SHA256))));
    Failed := False;
    try
      ReadTLSHandshakeFlight(T, Buf, [htServerHelloDone], Msgs);
    except
      on E: ETLS12Error do
        Failed := True;
    end;
    AssertTrue('EOF before terminating message → ETLS12Error', Failed);
  finally
    Buf.Free;
    T.Free;
  end;
end;

{ ==================================================================== }
{Record layer failures}
{ ==================================================================== }

procedure TTLSTests.TestTruncatedRecordRaises;
var
  T: TMockTLSTransport;
  Failed: Boolean;
begin
  T := TMockTLSTransport.Create;
  try
    {Header promises 16 bytes, only 1 is transmitted.}
    T.SetReadData(Cat(HexToBytes('1603010010'), HexToBytes('AA')));
    Failed := False;
    try
      ReadTLSRecord(T);
    except
      on E: ETLS12Error do
        Failed := True;
    end;
    AssertTrue('truncated record → ETLS12Error', Failed);
  finally
    T.Free;
  end;
end;

procedure TTLSTests.TestTruncatedRecordHeaderRaises;
var
  T: TMockTLSTransport;
  Failed: Boolean;
begin
  T := TMockTLSTransport.Create;
  try
    T.SetReadData(HexToBytes('1603'));  {header shorter than 5 bytes}
    Failed := False;
    try
      ReadTLSRecord(T);
    except
      on E: ETLS12Error do
        Failed := True;
    end;
    AssertTrue('truncated header → ETLS12Error', Failed);
  finally
    T.Free;
  end;
end;

procedure TTLSTests.TestOversizedPlaintextRecordRaises;
var
  Failed: Boolean;
begin
  Failed := False;
  try
    EncodeTLSRecord(ctHandshake, SeqBytes(TLSRecordMaxPayload + 1, 0));
  except
    on E: ETLS12Error do
      Failed := True;
  end;
  AssertTrue('fragment > 2^14 → ETLS12Error', Failed);

  {Boundary: exactly 2^14 bytes is allowed (record = header + fragment).}
  AssertEquals('2^14 allowed', TLSRecordHeaderLen + TLSRecordMaxPayload,
    Length(EncodeTLSRecord(ctHandshake, SeqBytes(TLSRecordMaxPayload, 0))));
end;

procedure TTLSTests.TestOversizedCiphertextLengthRaises;
var
  Data: TBytes;
  Failed: Boolean;
begin
  {Length in header exceeds ciphertext limit.}
  Data := Cat(HexToBytes('160303'), W16(TLSRecordMaxCiphertext + 1));
  Failed := False;
  try
    DecodeTLSRecord(Data);
  except
    on E: ETLS12Error do
      Failed := True;
  end;
  AssertTrue('length > 2^14+2048 → ETLS12Error', Failed);
end;

procedure TTLSTests.TestUnknownContentTypeRaises;
var
  Failed: Boolean;
begin
  AssertFalse('99 — unknown type', IsKnownContentType(99));
  Failed := False;
  try
    ByteToTLSContentType(99);
  except
    on E: ETLS12Error do
      Failed := True;
  end;
  AssertTrue('unknown content type → ETLS12Error', Failed);
end;

{ ==================================================================== }
{ ChangeCipherSpec                                                     }
{ ==================================================================== }

procedure TTLSTests.TestChangeCipherSpecRoundTrip;
var
  W: TMockTLSTransport;
  Raw: TBytes;
begin
  W := TMockTLSTransport.Create;
  try
    WriteTLS12ChangeCipherSpec(W);
    Raw := W.WrittenData;
    AssertEquals('CCS body', '01', BytesToHex(EncodeTLSChangeCipherSpec));
  finally
    W.Free;
  end;

  W := TMockTLSTransport.Create;
  try
    W.SetReadData(Raw);
    ReadTLS12ChangeCipherSpec(W);  { must not throw }
    AssertTrue('CCS read', True);
  finally
    W.Free;
  end;
end;

procedure TTLSTests.TestInvalidChangeCipherSpecRaises;
var
  Failed: Boolean;
begin
  { Body is not 0x01. }
  Failed := False;
  try
    CheckTLSChangeCipherSpec(B1($02));
  except
    on E: ETLS12Error do
      Failed := True;
  end;
  AssertTrue('CCS with byte != 0x01 → ETLS12Error', Failed);

  { Empty/two-byte body. }
  Failed := False;
  try
    CheckTLSChangeCipherSpec(nil);
  except
    on E: ETLS12Error do
      Failed := True;
  end;
  AssertTrue('empty CCS → ETLS12Error', Failed);
end;

procedure TTLSTests.TestChangeCipherSpecWrongRecordTypeRaises;
var
  T: TMockTLSTransport;
  Failed: Boolean;
begin
  T := TMockTLSTransport.Create;
  try
    T.SetReadData(EncodeTLSRecord(ctHandshake, HexToBytes('01000000')));
    Failed := False;
    try
      ReadTLS12ChangeCipherSpec(T);
    except
      on E: ETLS12Error do
        Failed := True;
    end;
    AssertTrue('CCS: foreign record type → ETLS12Error', Failed);
  finally
    T.Free;
  end;
end;

{ ==================================================================== }
{ Finished / VerifyData                                                }
{ ==================================================================== }

procedure TTLSTests.TestFinishedVerifyDataCheck;
var
  Master, Transcript, VD, Body: TBytes;
begin
  Master := SeqBytes(48, 7);
  Transcript := StrBytes('transcript-bytes');
  VD := TLS12VerifyData(hkSHA256, Master, TLSFinishedLabelClient, Transcript);
  AssertEquals('verify_data = 12 bytes', TLSFinishedVerifyDataLen,
    Length(VD));

  Body := EncodeTLS12FinishedBody(VD);
  AssertTrue('CheckFinished accepts valid data',
    TLS12CheckFinished(hkSHA256, Master, TLSFinishedLabelClient, Transcript,
      Body));
  AssertTrue('VerifyFinished accepts verify_data',
    TLS12VerifyFinished(hkSHA256, Master, TLSFinishedLabelClient, Transcript,
      VD));

  { Same verify_data for a different hash/suite does not fit. }
  AssertFalse('SHA-384 does not match SHA-256',
    TLS12VerifyFinished(hkSHA384, Master, TLSFinishedLabelClient, Transcript,
      VD));
end;

procedure TTLSTests.TestWrongFinishedVerifyDataRejected;
var
  Master, Transcript, VD: TBytes;
begin
  Master := SeqBytes(48, 3);
  Transcript := StrBytes('some transcript');
  VD := TLS12VerifyData(hkSHA256, Master, TLSFinishedLabelClient, Transcript);

  { Corrupted verify_data. }
  VD[0] := VD[0] xor $FF;
  AssertFalse('corrupted verify_data rejected',
    TLS12VerifyFinished(hkSHA256, Master, TLSFinishedLabelClient, Transcript,
      VD));

  { Valid verify_data, but different role label. }
  VD := TLS12VerifyData(hkSHA256, Master, TLSFinishedLabelClient, Transcript);
  AssertFalse('server finished label does not match',
    TLS12VerifyFinished(hkSHA256, Master, TLSFinishedLabelServer, Transcript,
      VD));

  {Correct verify_data, but different transcript.}
  AssertFalse('different transcript does not match',
    TLS12VerifyFinished(hkSHA256, Master, TLSFinishedLabelClient,
      StrBytes('different'), VD));
end;

{ ==================================================================== }
{ Alert                                                                }
{ ==================================================================== }

procedure TTLSTests.TestAlertRoundTrip;
var
  W: TMockTLSTransport;
  Raw: TBytes;
  A: TTLSAlert;
begin
  W := TMockTLSTransport.Create;
  try
    WriteTLS12Alert(W, alFatal, adHandshakeFailure);
    Raw := W.WrittenData;
  finally
    W.Free;
  end;

  W := TMockTLSTransport.Create;
  try
    W.SetReadData(Raw);
    A := ReadTLS12Alert(W);
    AssertEquals('level', Integer(TLSAlertLevelFatal), Integer(A.Level));
    AssertEquals('description', Integer(adHandshakeFailure),
      Integer(A.Description));
    AssertEquals('name description', 'handshake_failure',
      TLSAlertDescriptionName(A.Description));
  finally
    W.Free;
  end;
end;

procedure TTLSTests.TestFatalAlert;
var
  A: TTLSAlert;
begin
  A.Level := alFatal;
  A.Description := adBadRecordMac;
  AssertTrue('fatal alert is fatal', TLS12AlertIsFatal(A));
  A.Level := alWarning;
  AssertFalse('warning alert is not fatal', TLS12AlertIsFatal(A));
end;

procedure TTLSTests.TestMalformedAlertRaises;
var
  Failed: Boolean;
begin
  {Alert body must be exactly 2 bytes.}
  Failed := False;
  try
    DecodeTLSAlert(B1(2));
  except
    on E: ETLS12Error do
      Failed := True;
  end;
  AssertTrue('short Alert body → ETLS12Error', Failed);

  Failed := False;
  try
    DecodeTLSAlert(HexToBytes('020AFF'));
  except
    on E: ETLS12Error do
      Failed := True;
  end;
  AssertTrue('long Alert body → ETLS12Error', Failed);
end;

procedure TTLSTests.TestReadAlertWrongRecordTypeRaises;
var
  T: TMockTLSTransport;
  Failed: Boolean;
begin
  T := TMockTLSTransport.Create;
  try
    T.SetReadData(EncodeTLSRecord(ctHandshake, HexToBytes('01000000')));
    Failed := False;
    try
      ReadTLS12Alert(T);
    except
      on E: ETLS12Error do
        Failed := True;
    end;
    AssertTrue('Alert: foreign record type → ETLS12Error', Failed);
  finally
    T.Free;
  end;
end;

initialization
  RegisterTest(TTLSTests);

end.
