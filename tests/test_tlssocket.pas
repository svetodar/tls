{ SPDX-License-Identifier: Apache-2.0 }
unit test_tlssocket;
{ Tests for the TLS socket handler (layer 4, task 14).

  The handler is exercised against a real local `openssl s_server` whose
  certificate, key and CA are generated for the run by e2e_support (the same
  external reference used by test_tls12_e2e). When `openssl` is missing the
  tests silently pass (skipped), matching the existing E2E convention; a
  present but broken setup fails with a message instead. One test
  additionally exercises the Windows default system-store fallback (task 18)
  and is skipped off-Windows; a network-required test against example.com
  runs only when TLS_TEST_NETWORK=1. }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TTLSSocketTests = class(TTestCase)
  published
    procedure TestDefaultHandlerRegistered;
    procedure TestNoTrustStoreFails;
    procedure TestWinSystemStoreFallback;
    procedure TestWinSystemStoreExampleDotCom;
    procedure TestUnknownCARejected;
    procedure TestHostMismatchRejected;
    procedure TestVerificationDisabledAccepts;
    procedure TestConnectSendRecvRSA;
    procedure TestConnectSendRecvEC;
    procedure TestStreamingLargeBody;
    procedure TestCleanCloseNotify;
    procedure TestNetworkRequiredExampleDotCom;
  end;

implementation

uses
  SysUtils, Classes, Process, ssockets, sslsockets,
  e2e_support,
  tls.tlssocket, tls.certstore;

{ Result of a single connection attempt. }
type
  TConnectOutcome = (coOK, coNotReady, coFailed);

{ ==================================================================== }
{ Helpers                                                              }
{ ==================================================================== }

{ The end-to-end tests need a server certificate with its private key and a CA
  to trust. Both are generated once per run by e2e_support.TE2EPki instead of
  being read from tests/fixtures, whose keys are git-ignored: a checkout
  either has no keys at all or keys from another generation than the committed
  certificates, and s_server then refuses to start. The shapes the tests need
  (a valid localhost leaf, a leaf for a name that does not match, and an
  unrelated CA for the "unknown CA" case) are generated on demand and kept for
  the rest of the run, because every generation costs an RSA key. }
type
  TPkiKind = (pkRsa, pkEc, pkWrongHost, pkOtherCa);

var
  GPkis: array[TPkiKind] of TE2EPki;

function GetPki(AKind: TPkiKind): TE2EPki;
begin
  if GPkis[AKind] = nil then
    case AKind of
      pkRsa:
        GPkis[AKind] := TE2EPki.Create(ekRSA, 'localhost', 'localhost');
      pkEc:
        GPkis[AKind] := TE2EPki.Create(ekEC, 'localhost', 'localhost');
      pkWrongHost:
        GPkis[AKind] := TE2EPki.Create(ekRSA, 'wrong.example.com',
          'wrong.example.com,other.example.com');
      pkOtherCa:
        GPkis[AKind] := TE2EPki.Create(ekEC, 'unrelated.example.com',
          'unrelated.example.com');
    end;
  Result := GPkis[AKind];
end;

{ Starts `openssl s_server -tls1_2 -www` with the certificate and key of APki.
  Returns nil (and the test skips) when openssl is unavailable. }
function StartServer(const APki: TE2EPki; const ACipher: string;
  out APort: Word): TProcess;
begin
  Result := StartOpenSSLServer(APki.CertPath, APki.KeyPath,
    ['-tls1_2', '-cipher', ACipher, '-www'], APort);
end;

{ Starts `openssl s_server -tls1_2 -WWW` (static file server) rooted at
  AWorkDir, used to exercise a large, multi-record response body. }
function StartWwwServer(const APki: TE2EPki; const AWorkDir: string;
  out APort: Word): TProcess;
begin
  Result := StartOpenSSLServer(APki.CertPath, APki.KeyPath,
    ['-tls1_2', '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256', '-WWW'], APort,
    AWorkDir);
end;

{ One attempt: create the socket + handler and run the handshake. Returns
  coNotReady when the TCP connection itself could not be established (the
  server is probably not listening yet), coFailed for a TLS/verification
  failure and coOK on success. ATrustCAPath is a PEM bundle path, '' for "no
  explicit trust store". }
function AttemptConnect(const AHost: string; APort: Word; AVerify: Boolean;
  const ATrustCAPath: string; out ASock: TInetSocket;
  out AHandler: TTLSSocketHandler; out AError: string;
  ADisableSystemStore: Boolean = False): TConnectOutcome;
const
  { Bounded connect: a blocking connect to a port that nothing listens on can
    wait for the whole SYN retransmit timeout on every attempt. A whole number
    of seconds is required: FPC 3.2.2 truncates the value to tv_sec and zeroes
    tv_usec (fcl-net/ssockets.pp, CheckSocketConnectTimeout), so 1000 ms is the
    smallest useful value. }
  ConnectTimeoutMs = 2000;
var
  H: TTLSSocketHandler;
  Store: TCertStore;
  SockCreated: Boolean;
begin
  ASock := nil;
  AHandler := nil;
  AError := '';
  Store := nil;
  SockCreated := False;
  H := TTLSSocketHandler.Create;
  try
    H.VerifyPeerCert := AVerify;
    H.DisableSystemStore := ADisableSystemStore;
    if ATrustCAPath <> '' then
    begin
      Store := LoadBundle(ATrustCAPath);
      H.TrustStore := Store;
    end;
    try
      ASock := TInetSocket.Create(AHost, APort, ConnectTimeoutMs, H);
      SockCreated := True;
      ASock.IOTimeout := 8000;
      ASock.Connect;
      {The trust store is only needed during the handshake.}
      H.TrustStore := nil;
      AHandler := H;
      Result := coOK;
    except
      on E: Exception do
      begin
        if H.LastErrorString <> '' then
        begin
          AError := H.LastErrorString;
          Result := coFailed;
        end
        else
        begin
          AError := E.Message;
          Result := coNotReady;
        end;
        {Freeing the socket also frees the handler it owns.}
        if SockCreated then
          FreeAndNil(ASock)
        else
          H.Free;
      end;
    end;
  finally
    Store.Free;
  end;
end;

{ Creates a socket with the handler and performs the TLS handshake, retrying
  while the freshly started test server is not yet accepting. The deadline is
  absolute, so a server that died cannot keep the test waiting: on failure the
  function returns nil with the reason. }
function TryConnect(const AHost: string; APort: Word; AVerify: Boolean;
  const ATrustCAPath: string; out AHandler: TTLSSocketHandler;
  out AError: string; ADisableSystemStore: Boolean = False): TInetSocket;
const
  TotalTimeoutMs = 15000;
var
  Deadline: QWord;
  Outcome: TConnectOutcome;
begin
  Result := nil;
  AHandler := nil;
  AError := '';
  Deadline := GetTickCount64 + TotalTimeoutMs;
  repeat
    Outcome := AttemptConnect(AHost, APort, AVerify, ATrustCAPath,
      Result, AHandler, AError, ADisableSystemStore);
    case Outcome of
      coOK:
        Exit;
      coNotReady:
        Sleep(50);
      coFailed:
        begin
          AHandler := nil;
          Result := nil;
          Exit;
        end;
    end;
  until GetTickCount64 >= Deadline;
  AError := 'timed out waiting for ' + AHost + ':' + IntToStr(APort);
  Result := nil;
end;

{ Reads until the server closes the connection. }
function ReadAll(H: TTLSSocketHandler): AnsiString;
var
  Buf: array[0..8191] of Byte;
  N: Integer;
begin
  Result := '';
  repeat
    N := H.Recv(Buf[0], SizeOf(Buf));
    if N <= 0 then
      Break;
    SetLength(Result, Length(Result) + N);
    Move(Buf[0], Result[Length(Result) - N + 1], N);
  until False;
end;

{ Reads until the server closes the connection, requesting at most AChunk
  bytes per Recv call (exercises the buffering of partial records). }
function ReadChunked(H: TTLSSocketHandler; AChunk: Integer): AnsiString;
var
  Buf: TBytes;
  N: Integer;
begin
  Result := '';
  if AChunk <= 0 then
    AChunk := 1;
  SetLength(Buf, AChunk);
  repeat
    N := H.Recv(Buf[0], AChunk);
    if N <= 0 then
      Break;
    SetLength(Result, Length(Result) + N);
    Move(Buf[0], Result[Length(Result) - N + 1], N);
  until False;
end;

{ Content after the first empty line (HTTP response body). }
function ExtractBody(const AResponse: AnsiString): AnsiString;
var
  P: Integer;
begin
  P := Pos(#13#10#13#10, AResponse);
  if P = 0 then
    Result := ''
  else
    Result := Copy(AResponse, P + 4, MaxInt);
end;

{ ==================================================================== }
{ Tests                                                                }
{ ==================================================================== }

procedure TTLSSocketTests.TestDefaultHandlerRegistered;
var
  H: TSSLSocketHandler;
begin
  H := TSSLSocketHandler.GetDefaultHandler;
  try
    AssertTrue('default handler is TTLSSocketHandler',
      H is TTLSSocketHandler);
  finally
    H.Free;
  end;
end;

procedure TTLSSocketTests.TestNoTrustStoreFails;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
begin
  {Disable the Windows system-store fallback so the test still exercises
    the strict "no trust store" failure path on every platform.}
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkRsa),
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, '', H, Err, True);
    AssertTrue('connect must fail without a trust store', Sock = nil);
    AssertTrue('reason mentions the trust store', Pos('trust store', Err) > 0);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

{ On Windows, when no trust store is configured, Connect falls back to the
  system certificate store (Root + CA). The local test server is signed by
  the fixture CA, which is not in the system store, so verification must
  fail with a chain error ("issuer not found in store") rather than the
  strict "no trust store configured" error. Skipped off-Windows. }
procedure TTLSSocketTests.TestWinSystemStoreFallback;
{$ifdef windows}
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
{$endif}
begin
{$ifdef windows}
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkRsa),
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;   { openssl unavailable — skipped }
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, '', H, Err);
    AssertTrue('connect must fail: the fixture CA is not in the system store',
      Sock = nil);
    AssertTrue('failure is a chain verification error, not a missing store',
      Pos('certificate chain verification failed', Err) > 0);
    AssertTrue('issuer lookup failed against the system store',
      Pos('issuer not found in store', Err) > 0);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
{$else}
  { Not on Windows — skipped. }
{$endif}
end;

{ Network-required test of the Windows default system-store fallback
  (task 18): connect to a real public HTTPS endpoint with certificate
  verification enabled and no explicit trust store. On Windows the handler
  falls back to the system store (Root + CA), so the handshake must succeed
  against example.com's real certificate chain. Disabled unless
  TLS_TEST_NETWORK=1 so that `make test` stays offline; skipped off-Windows. }
procedure TTLSSocketTests.TestWinSystemStoreExampleDotCom;
{$ifdef windows}
var
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err, Req, Resp: AnsiString;
{$endif}
begin
{$ifdef windows}
  if GetEnvironmentVariable('TLS_TEST_NETWORK') <> '1' then
    Exit;   { network required — skipped by default }
  Sock := TryConnect('example.com', 443, True, '', H, Err);
  AssertTrue('verified connect against the system store: ' + Err,
    Sock <> nil);
  try
    Req := 'GET / HTTP/1.0'#13#10'Host: example.com'#13#10 +
      'Connection: close'#13#10#13#10;
    AssertEquals('request fully sent', Length(Req),
      H.Send(Req[1], Length(Req)));
    Resp := ReadAll(H);
    AssertTrue('HTTP response received', Pos('HTTP/1.', Resp) = 1);
  finally
    Sock.Free;
  end;
{$else}
  { Not on Windows — skipped. }
{$endif}
end;

procedure TTLSSocketTests.TestUnknownCARejected;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
begin
  {Server offers a chain signed by the RSA test CA, the client trusts an
    unrelated CA.}
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkRsa),
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True,
      GetPki(pkOtherCa).CaCertPath, H, Err);
    AssertTrue('connect must fail with an unknown CA', Sock = nil);
    AssertTrue('reason is not empty', Err <> '');
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

procedure TTLSSocketTests.TestHostMismatchRejected;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
begin
  {The certificate is signed by the trusted CA but has no SAN for localhost.}
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkWrongHost),
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True,
      GetPki(pkWrongHost).CaCertPath, H, Err);
    AssertTrue('connect must fail on host mismatch', Sock = nil);
    AssertTrue('reason mentions the host', Pos('host', Err) > 0);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

procedure TTLSSocketTests.TestVerificationDisabledAccepts;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
  Req, Resp: AnsiString;
begin
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkRsa),
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, False, '', H, Err);
    AssertTrue('connect with verification disabled: ' + Err, Sock <> nil);
    AssertTrue('SSL active', H.SSLActive);
    Req := 'GET / HTTP/1.0'#13#10'Host: localhost'#13#10#13#10;
    AssertEquals('request fully sent', Length(Req),
      H.Send(Req[1], Length(Req)));
    Resp := ReadAll(H);
    AssertTrue('HTTP 200 received', Pos('HTTP/1.0 200', Resp) > 0);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

procedure TTLSSocketTests.TestConnectSendRecvRSA;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
  Req, Resp: AnsiString;
begin
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkRsa),
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True,
      GetPki(pkRsa).CaCertPath, H, Err);
    AssertTrue('verified connect: ' + Err, Sock <> nil);
    AssertTrue('SSL active', H.SSLActive);
    Req := 'GET / HTTP/1.0'#13#10'Host: localhost'#13#10#13#10;
    AssertEquals('request fully sent', Length(Req),
      H.Send(Req[1], Length(Req)));
    Resp := ReadAll(H);
    AssertTrue('HTTP 200 received', Pos('HTTP/1.0 200', Resp) > 0);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

procedure TTLSSocketTests.TestConnectSendRecvEC;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
  Req, Resp: AnsiString;
begin
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkEc),
    'ECDHE-ECDSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True,
      GetPki(pkEc).CaCertPath, H, Err);
    AssertTrue('verified connect: ' + Err, Sock <> nil);
    Req := 'GET / HTTP/1.0'#13#10'Host: localhost'#13#10#13#10;
    AssertEquals('request fully sent', Length(Req),
      H.Send(Req[1], Length(Req)));
    Resp := ReadAll(H);
    AssertTrue('HTTP 200 received', Pos('HTTP/1.0 200', Resp) > 0);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

procedure TTLSSocketTests.TestStreamingLargeBody;
const
  BodySize = 100000;
var
  WorkDir, BodyPath: string;
  F: TFileStream;
  Data: TBytes;
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
  Req, Resp, Body: AnsiString;
begin
  if not OpenSSLAvailable then
    Exit;   { openssl unavailable — skipped }

  WorkDir := IncludeTrailingPathDelimiter(GetTempDir) +
    'tls_www_' + IntToStr(GetProcessID);
  ForceDirectories(WorkDir);
  BodyPath := WorkDir + PathDelim + 'body.bin';
  SetLength(Data, BodySize);
  FillChar(Data[0], BodySize, Ord('A'));
  F := TFileStream.Create(BodyPath, fmCreate);
  try
    F.WriteBuffer(Data[0], BodySize);
  finally
    F.Free;
  end;

  P := StartWwwServer(GetPki(pkRsa), WorkDir, Port);
  if P = nil then
  begin
    DeleteFile(BodyPath);
    RemoveDir(WorkDir);
    Exit;   { openssl unavailable — skipped }
  end;

  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, False, '', H, Err);
    AssertTrue('connect: ' + Err, Sock <> nil);
    Req := 'GET /body.bin HTTP/1.0'#13#10'Host: localhost'#13#10#13#10;
    AssertEquals('request fully sent', Length(Req),
      H.Send(Req[1], Length(Req)));
    {Read in small chunks: the 100 kB body spans several TLS records.}
    Resp := ReadChunked(H, 512);
    Body := ExtractBody(Resp);
    AssertEquals('streamed body length', BodySize, Length(Body));
    AssertTrue('body starts and ends with A',
      (Length(Body) > 0) and (Body[1] = 'A') and
      (Body[Length(Body)] = 'A'));
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
    DeleteFile(BodyPath);
    RemoveDir(WorkDir);
  end;
end;

procedure TTLSSocketTests.TestCleanCloseNotify;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
  Req: AnsiString;
  Buf: array[0..4095] of Byte;
  N: Integer;
begin
  if not OpenSSLAvailable then Exit;
  P := StartServer(GetPki(pkRsa),
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True,
      GetPki(pkRsa).CaCertPath, H, Err);
    AssertTrue('verified connect: ' + Err, Sock <> nil);
    Req := 'GET / HTTP/1.0'#13#10'Host: localhost'#13#10#13#10;
    H.Send(Req[1], Length(Req));
    repeat
      N := H.Recv(Buf[0], SizeOf(Buf));
    until N <= 0;
    {The encrypted close_notify must be decrypted and reported as a clean
      end of stream (0), not as a receive error (-1).}
    AssertEquals('clean close_notify', 0, N);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

{ Network-required smoke test against a real public HTTPS endpoint.
  Disabled unless TLS_TEST_NETWORK=1 so that `make test` stays offline. }
procedure TTLSSocketTests.TestNetworkRequiredExampleDotCom;
var
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err, Req, Resp: AnsiString;
begin
  if GetEnvironmentVariable('TLS_TEST_NETWORK') <> '1' then
    Exit;   { network required — skipped by default }
  Sock := TryConnect('example.com', 443, False, '', H, Err);
  AssertTrue('connect: ' + Err, Sock <> nil);
  try
    Req := 'GET / HTTP/1.0'#13#10'Host: example.com'#13#10 +
      'Connection: close'#13#10#13#10;
    AssertEquals('request fully sent', Length(Req),
      H.Send(Req[1], Length(Req)));
    Resp := ReadAll(H);
    AssertTrue('HTTP response received', Pos('HTTP/1.', Resp) = 1);
  finally
    Sock.Free;
  end;
end;

initialization
  RegisterTest(TTLSSocketTests);

finalization
  { Release the PKIs generated during the run: each one owns a temporary
    directory that its destructor removes. }
  FreeAndNil(GPkis[pkRsa]);
  FreeAndNil(GPkis[pkEc]);
  FreeAndNil(GPkis[pkWrongHost]);
  FreeAndNil(GPkis[pkOtherCa]);

end.
