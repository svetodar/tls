{ SPDX-License-Identifier: Apache-2.0 }
unit test_tls13_e2e;
{ E2E test TLS 1.3 (milestone F): full client handshake and data exchange
  with a real `openssl s_server -tls1_3` server, following the pattern of
  tests/test_tls12_e2e.pas.

  The test starts a local `openssl s_server -tls1_3 -www` with a test
  certificate, connects via a TCP socket and drives the whole handshake
  with TTLS13Client (ClientHello -> ServerHello/EncryptedExtensions/
  Certificate/CertificateVerify/Finished, then the client Finished),
  verifies the certificate chain, sends an HTTP request and checks the
  response. If the openssl binary or the fixtures are unavailable, the test
  is skipped. }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TTLS13E2ETests = class(TTestCase)
  published
    procedure TestHandshakeAndHttpWithOpenSSLServerRSA;
    procedure TestHandshakeAndHttpWithOpenSSLServerEC;
    procedure TestHandshakeAndHttpWithOpenSSLServerSHA384;
  end;

implementation

uses
  SysUtils, Classes, Process, ssockets, Sockets, BaseUnix,
  tls.tls12, tls.tls13, tls.rand, tls.x509, tls.certstore;

{ ==================================================================== }
{ Helper functions                                                      }
{ ==================================================================== }

function StrBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  Result := nil;
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

{ Fixture path: first from the current directory, then relative to
  the executable's directory (bin/../tests/fixtures). }
function FixturePath(const AName: string): string;
begin
  Result := 'tests' + PathDelim + 'fixtures' + PathDelim + AName;
  if FileExists(Result) then
    Exit;
  Result := ExpandFileName(
    ExtractFilePath(ParamStr(0)) + '..' + PathDelim +
    'tests' + PathDelim + 'fixtures' + PathDelim + AName);
end;

{ Free TCP port: bind(0) on a temporary socket and read the assigned
  port via getsockname. }
function FindFreePort: Word;
var
  S: LongInt;
  Addr: TInetSockAddr;
  Len: LongInt;
begin
  S := fpSocket(AF_INET, SOCK_STREAM, 0);
  if S < 0 then
    raise Exception.Create('TLS 1.3 E2E: fpSocket() failed');
  try
    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := 0;
    Addr.sin_addr.s_addr := htonl(INADDR_ANY);
    if fpBind(S, @Addr, SizeOf(Addr)) <> 0 then
      raise Exception.Create('TLS 1.3 E2E: fpBind() failed');
    Len := SizeOf(Addr);
    if fpGetSockName(S, @Addr, @Len) <> 0 then
      raise Exception.Create('TLS 1.3 E2E: fpGetSockName() failed');
    Result := ntohs(Addr.sin_port);
  finally
    fpClose(S);
  end;
end;

{ Starts `openssl s_server -tls1_3 -www` with the given certificate,
  cipher suite(s) and named group(s), returning the process (nil if openssl
  is unavailable). }
function StartOpenSSLServer(const ACert, AKey, ACipherSuites,
  AGroups: string; out APort: Word): TProcess;
var
  P: TProcess;
begin
  Result := nil;
  try
    APort := FindFreePort;
    P := TProcess.Create(nil);
    P.Executable := 'openssl';
    P.Parameters.Add('s_server');
    P.Parameters.Add('-accept');
    P.Parameters.Add(IntToStr(APort));
    P.Parameters.Add('-cert');
    P.Parameters.Add(ACert);
    P.Parameters.Add('-key');
    P.Parameters.Add(AKey);
    P.Parameters.Add('-tls1_3');
    P.Parameters.Add('-ciphersuites');
    P.Parameters.Add(ACipherSuites);
    P.Parameters.Add('-groups');
    P.Parameters.Add(AGroups);
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

{ Connect to the local server, waiting for the port to become ready. }
function ConnectToServer(APort: Word): TInetSocket;
var
  i: Integer;
begin
  Result := nil;
  for i := 1 to 100 do
  begin
    try
      Result := TInetSocket.Create('127.0.0.1', APort);
      Result.IOTimeout := 15000;
      Exit;
    except
      on E: Exception do
      begin
        Result := nil;
        Sleep(50);
      end;
    end;
  end;
end;

{ Full TLS 1.3 handshake and HTTP exchange through TTLS13Client.
  Raises ETLS13Error on any protocol/verification error. }
procedure RunTLS13Session(APort: Word; const ACaCertPath: string;
  AExpectedSuite: TTLSCipherSuite; out AResponse: AnsiString);
var
  Sock: TInetSocket;
  Transport: ITLSTransport;
  Client: TTLS13Client;
  Store: TCertStore;
  CaCert: TX509Cert;
  VR: TVerifyResult;
  Chain: TTLS12CertChain;
  Buf: array[0..4095] of Byte;
  N: LongInt;
  Req: TBytes;
  Opts: TTLS13ClientHelloOptions;
begin
  AResponse := '';
  Sock := ConnectToServer(APort);
  if Sock = nil then
    raise ETLS13Error.Create('failed to connect to openssl s_server');

  Transport := nil;
  Client := nil;
  Store := nil;
  CaCert := nil;
  try
    Transport := TTLSStreamTransport.Create(Sock);
    CaCert := LoadPEM(ACaCertPath);
    Store := TCertStore.Create;
    Store.Add(CaCert);

    { Default options: the client generates and owns its key shares. }
    Opts := DefaultTLS13ClientHelloOptions;
    Opts.ServerName := 'localhost';

    Client := TTLS13Client.Create;
    Client.TrustStore := Store;
    Client.Options := Opts;
    Client.Connect(Transport);

    if not Client.HandshakeDone then
      raise ETLS13Error.Create('TLS 1.3 handshake did not complete');
    if Client.CipherSuite <> AExpectedSuite then
      raise ETLS13Error.CreateFmt(
        'negotiated cipher suite 0x%04x, expected 0x%04x',
        [Client.CipherSuite, AExpectedSuite]);

    { The certificate chain must have been verified against the test CA. }
    Chain := Client.CertChain;
    if (Chain = nil) or (Chain.Count = 0) then
      raise ETLS13Error.Create('server certificate was not received');
    VR := Chain.Verify(Store);
    if not VR.OK then
      raise ETLS13Error.Create('chain verification failed: ' + VR.Reason);

    { HTTP request over the encrypted channel. }
    Req := StrBytes('GET / HTTP/1.0'#13#10'Host: localhost'#13#10#13#10);
    Client.Send(Req);

    { Read the response until the server closes the connection. }
    while True do
    begin
      N := Client.Recv(Buf, SizeOf(Buf));
      if N <= 0 then
        Break;
      SetLength(AResponse, Length(AResponse) + N);
      Move(Buf[0], AResponse[Length(AResponse) - N + 1], N);
    end;

    Client.Shutdown;
  finally
    Client.Free;
    Transport := nil;
    CaCert.Free;
    Store.Free;
    Sock.Free;
  end;
end;

{ General scenario: start openssl s_server, handshake, HTTP request. }
procedure RunE2E(const ACertName, AKeyName, ACaName, ACipherSuites,
  AGroups: string; ACipherSuite: TTLSCipherSuite);
var
  CertPath, KeyPath, CaPath: string;
  P: TProcess;
  Port: Word;
  Response: AnsiString;
begin
  CertPath := FixturePath(ACertName);
  KeyPath := FixturePath(AKeyName);
  CaPath := FixturePath(ACaName);
  if not (FileExists(CertPath) and FileExists(KeyPath) and
    FileExists(CaPath)) then
    Exit;   { fixtures missing — test skipped }

  P := StartOpenSSLServer(CertPath, KeyPath, ACipherSuites, AGroups, Port);
  if P = nil then
    Exit;   { openssl unavailable — test skipped }

  Response := '';
  try
    RunTLS13Session(Port, CaPath, ACipherSuite, Response);

    if Length(Response) = 0 then
      raise ETLS13Error.Create('server response not received');
    if Pos('HTTP/1.0 200', Response) = 0 then
      raise ETLS13Error.Create('no HTTP 200 from s_server: ' +
        Copy(Response, 1, 64));
  finally
    P.Terminate(0);
    P.Free;
  end;
end;

{ ==================================================================== }
{ Tests                                                                }
{ ==================================================================== }

procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerRSA;
begin
  RunE2E('leaf_rsa.crt', 'leaf_rsa.key', 'ca_rsa.crt',
    'TLS_AES_128_GCM_SHA256', 'P-256', TLS13CipherAES128GCMSHA256);
end;

procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerEC;
begin
  RunE2E('leaf_ec.crt', 'leaf_ec.key', 'ca_ec.crt',
    'TLS_AES_128_GCM_SHA256', 'P-256', TLS13CipherAES128GCMSHA256);
end;

{ SHA-384 key schedule and a P-384 key share. The certificate is RSA, so
  the server picks rsa_pss_rsae_sha256 for CertificateVerify: the signature
  scheme is independent of the cipher suite hash (RFC 8446, 4.4.3). }
procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerSHA384;
begin
  RunE2E('leaf_rsa.crt', 'leaf_rsa.key', 'ca_rsa.crt',
    'TLS_AES_256_GCM_SHA384', 'P-384', TLS13CipherAES256GCMSHA384);
end;

initialization
  RegisterTest(TTLS13E2ETests);

end.
