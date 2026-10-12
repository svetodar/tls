{ SPDX-License-Identifier: Apache-2.0 }
unit test_tlssocket;
{ Tests for the TLS socket handler (layer 4, task 14).

  The handler is exercised against a real local `openssl s_server` with the
  test certificates in tests/fixtures (the same external reference used by
  test_tls12_e2e). When `openssl` or the fixtures are missing the tests
  silently pass (skipped), matching the existing E2E convention. }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TTLSSocketTests = class(TTestCase)
  published
    procedure TestDefaultHandlerRegistered;
    procedure TestNoTrustStoreFails;
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
  SysUtils, Classes, Process, ssockets, sslsockets, Sockets,
  tls.tlssocket, tls.certstore;

{ Result of a single connection attempt. }
type
  TConnectOutcome = (coOK, coNotReady, coFailed);

{ ==================================================================== }
{ Helpers                                                              }
{ ==================================================================== }

function FixturePath(const AName: string): string;
begin
  Result := 'tests' + PathDelim + 'fixtures' + PathDelim + AName;
  if FileExists(Result) then
    Exit;
  Result := ExpandFileName(
    ExtractFilePath(ParamStr(0)) + '..' + PathDelim +
    'tests' + PathDelim + 'fixtures' + PathDelim + AName);
end;

function FindFreePort: Word;
var
  S: LongInt;
  Addr: TInetSockAddr;
  Len: LongInt;
begin
  S := fpSocket(AF_INET, SOCK_STREAM, 0);
  if S < 0 then
    raise Exception.Create('TLS socket test: fpSocket() failed');
  try
    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := 0;
    Addr.sin_addr.s_addr := htonl(INADDR_ANY);
    if fpBind(S, @Addr, SizeOf(Addr)) <> 0 then
      raise Exception.Create('TLS socket test: fpBind() failed');
    Len := SizeOf(Addr);
    if fpGetSockName(S, @Addr, @Len) <> 0 then
      raise Exception.Create('TLS socket test: fpGetSockName() failed');
    Result := ntohs(Addr.sin_port);
  finally
    CloseSocket(S);
  end;
end;

{ Starts `openssl s_server` with the given leaf certificate and cipher suite.
  Returns nil (and the test should skip) when openssl or the fixture files
  are unavailable. }
function StartServer(const ACertName, AKeyName, ACipher: string;
  out APort: Word): TProcess;
var
  CertPath, KeyPath: string;
  P: TProcess;
begin
  Result := nil;
  APort := 0;
  CertPath := FixturePath(ACertName);
  KeyPath := FixturePath(AKeyName);
  if not (FileExists(CertPath) and FileExists(KeyPath)) then
    Exit;
  try
    APort := FindFreePort;
    P := TProcess.Create(nil);
    P.Executable := 'openssl';
    P.Parameters.Add('s_server');
    P.Parameters.Add('-accept');
    P.Parameters.Add(IntToStr(APort));
    P.Parameters.Add('-cert');
    P.Parameters.Add(CertPath);
    P.Parameters.Add('-key');
    P.Parameters.Add(KeyPath);
    P.Parameters.Add('-tls1_2');
    P.Parameters.Add('-cipher');
    P.Parameters.Add(ACipher);
    P.Parameters.Add('-www');
    P.Parameters.Add('-naccept');
    P.Parameters.Add('1');
    P.Parameters.Add('-quiet');
    P.Options := [poUsePipes];
    try
      P.Execute;
      Result := P;
    except
      on E: Exception do
      begin
        P.Free;
        Result := nil;
      end;
    end;
  except
    on E: Exception do
      Result := nil;
  end;
end;

{ Starts `openssl s_server -WWW` (static file server) rooted at AWorkDir.
  Used to exercise a large, multi-record response body. }
function StartWwwServer(const AWorkDir: string; out APort: Word): TProcess;
var
  CertPath, KeyPath: string;
  P: TProcess;
begin
  Result := nil;
  APort := 0;
  {CurrentDirectory is changed, so the certificate paths must be absolute.}
  CertPath := ExpandFileName(FixturePath('leaf_rsa.crt'));
  KeyPath := ExpandFileName(FixturePath('leaf_rsa.key'));
  if not (FileExists(CertPath) and FileExists(KeyPath)) then
    Exit;
  try
    APort := FindFreePort;
    P := TProcess.Create(nil);
    P.Executable := 'openssl';
    P.CurrentDirectory := AWorkDir;
    P.Parameters.Add('s_server');
    P.Parameters.Add('-accept');
    P.Parameters.Add(IntToStr(APort));
    P.Parameters.Add('-cert');
    P.Parameters.Add(CertPath);
    P.Parameters.Add('-key');
    P.Parameters.Add(KeyPath);
    P.Parameters.Add('-tls1_2');
    P.Parameters.Add('-cipher');
    P.Parameters.Add('ECDHE-RSA-AES128-GCM-SHA256');
    P.Parameters.Add('-WWW');
    P.Parameters.Add('-naccept');
    P.Parameters.Add('1');
    P.Parameters.Add('-quiet');
    P.Options := [poUsePipes];
    try
      P.Execute;
      Result := P;
    except
      on E: Exception do
      begin
        P.Free;
        Result := nil;
      end;
    end;
  except
    on E: Exception do
      Result := nil;
  end;
end;

{ One attempt: create the socket + handler and run the handshake. Returns
  coNotReady when the TCP connection itself could not be established (the
  server is probably not listening yet), coFailed for a TLS/verification
  failure and coOK on success. }
function AttemptConnect(const AHost: string; APort: Word; AVerify: Boolean;
  ATrustCA: string; out ASock: TInetSocket;
  out AHandler: TTLSSocketHandler; out AError: string): TConnectOutcome;
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
    if ATrustCA <> '' then
    begin
      Store := LoadBundle(FixturePath(ATrustCA));
      H.TrustStore := Store;
    end;
    try
      ASock := TInetSocket.Create(AHost, APort, H);
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
  briefly while the freshly started test server is not yet accepting.
  On success returns the socket; on failure returns nil with the reason. }
function TryConnect(const AHost: string; APort: Word; AVerify: Boolean;
  ATrustCA: string; out AHandler: TTLSSocketHandler;
  out AError: string): TInetSocket;
const
  MaxAttempts = 100;
var
  Attempt: Integer;
  Outcome: TConnectOutcome;
begin
  Result := nil;
  AHandler := nil;
  AError := '';
  for Attempt := 1 to MaxAttempts do
  begin
    Outcome := AttemptConnect(AHost, APort, AVerify, ATrustCA,
      Result, AHandler, AError);
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
  end;
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
  P := StartServer('leaf_rsa.crt', 'leaf_rsa.key',
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, '', H, Err);
    AssertTrue('connect must fail without a trust store', Sock = nil);
    AssertTrue('reason mentions the trust store', Pos('trust store', Err) > 0);
  finally
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

procedure TTLSSocketTests.TestUnknownCARejected;
var
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  H: TTLSSocketHandler;
  Err: string;
begin
  {Server offers a chain signed by ca_rsa, the client trusts ca_ec.}
  P := StartServer('leaf_rsa.crt', 'leaf_rsa.key',
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, 'ca_ec.crt', H, Err);
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
  P := StartServer('mismatch_rsa.crt', 'mismatch_rsa.key',
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, 'ca_rsa.crt', H, Err);
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
  P := StartServer('leaf_rsa.crt', 'leaf_rsa.key',
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
  P := StartServer('leaf_rsa.crt', 'leaf_rsa.key',
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, 'ca_rsa.crt', H, Err);
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
  P := StartServer('leaf_ec.crt', 'leaf_ec.key',
    'ECDHE-ECDSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, 'ca_ec.crt', H, Err);
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
  if not FileExists(FixturePath('leaf_rsa.crt')) then
    Exit;   { fixtures missing — skipped }

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

  P := StartWwwServer(WorkDir, Port);
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
  P := StartServer('leaf_rsa.crt', 'leaf_rsa.key',
    'ECDHE-RSA-AES128-GCM-SHA256', Port);
  if P = nil then
    Exit;
  Sock := nil;
  try
    Sock := TryConnect('localhost', Port, True, 'ca_rsa.crt', H, Err);
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

end.
