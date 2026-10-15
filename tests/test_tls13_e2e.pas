{ SPDX-License-Identifier: Apache-2.0 }
unit test_tls13_e2e;
{ End-to-end TLS 1.3 test (milestone F): a full client handshake and HTTP
  exchange with a real `openssl s_server -tls1_3` over a TCP socket, using
  the TTLS13Client from tls.tls13.

  The test is skipped when the openssl CLI or the certificate fixtures are
  unavailable (the *.key files are git-ignored; regenerate them with
  `make fixtures`). }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TTLS13E2ETests = class(TTestCase)
  published
    procedure TestHandshakeAndHttpWithOpenSSLServerRSA;
    procedure TestHandshakeAndHttpWithOpenSSLServerEC;
    procedure TestHandshakeAES256GCM;
    procedure TestHandshakeChaCha20;
  end;

implementation

uses
  SysUtils, Classes, Process, ssockets, Sockets, BaseUnix,
  tls.tls13, tls.tls12, tls.x509, tls.certstore;

function BytesToStr(const B: TBytes): AnsiString;
var
  i: Integer;
begin
  SetLength(Result, Length(B));
  for i := 0 to High(B) do
    Result[i + 1] := AnsiChar(B[i]);
end;

function StrBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

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

function StartOpenSSLServer(const ACert, AKey, ACipher: string;
  out APort: Word): TProcess;
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

function ConnectToServer(APort: Word): TInetSocket;
var
  i: Integer;
begin
  Result := nil;
  for i := 1 to 100 do
  begin
    try
      Result := TInetSocket.Create('127.0.0.1', APort);
      Result.IOTimeout := 8000;
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

procedure RunTLS13Session(ATransport: ITLSTransport;
  const ACaCertPath: string; out AResponse: AnsiString);
var
  Store: TCertStore;
  CaCert: TX509Cert;
  Client: TTLS13Client;
  Req, Data: TBytes;
begin
  AResponse := '';
  Store := TCertStore.Create;
  CaCert := LoadPEM(ACaCertPath);
  try
    Store.Add(CaCert);
    Client := TTLS13Client.Create(ATransport, Store, 'localhost');
    try
      Client.Connect;
      if not Client.Connected then
        raise ETLS13Error.Create('TLS 1.3 E2E: client not connected');
      Req := StrBytes('GET / HTTP/1.0'#13#10'Host: localhost'#13#10#13#10);
      Client.SendApplicationData(Req);
      while Client.ReceiveApplicationData(Data) do
        AResponse := AResponse + BytesToStr(Data);
      Client.SendCloseNotify;
    finally
      Client.Free;
    end;
  finally
    CaCert.Free;
    Store.Free;
  end;
end;

procedure RunE2E(const ACertName, AKeyName, ACaName, ACipher: string);
var
  CertPath, KeyPath, CaPath: string;
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  Transport: ITLSTransport;
  Response: AnsiString;
begin
  CertPath := FixturePath(ACertName);
  KeyPath := FixturePath(AKeyName);
  CaPath := FixturePath(ACaName);
  if not (FileExists(CertPath) and FileExists(KeyPath) and
    FileExists(CaPath)) then
    Exit;   { fixtures missing — test skipped }

  P := StartOpenSSLServer(CertPath, KeyPath, ACipher, Port);
  if P = nil then
    Exit;   { openssl unavailable — test skipped }

  Sock := nil;
  Transport := nil;
  try
    Sock := ConnectToServer(Port);
    if Sock = nil then
      raise ETLS13Error.Create('failed to connect to openssl s_server');
    Transport := TTLSStreamTransport.Create(Sock);
    RunTLS13Session(Transport, CaPath, Response);
    Transport := nil;

    if Length(Response) = 0 then
      raise ETLS13Error.Create('server response not received');
    if Pos('HTTP/1.0 200', Response) = 0 then
      raise ETLS13Error.Create('no HTTP 200 from s_server: ' +
        Copy(Response, 1, 64));
  finally
    Transport := nil;
    Sock.Free;
    P.Terminate(0);
    P.Free;
  end;
end;

procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerRSA;
begin
  RunE2E('leaf_rsa.crt', 'leaf_rsa.key', 'ca_rsa.crt',
    'TLS_AES_128_GCM_SHA256');
end;

procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerEC;
begin
  RunE2E('leaf_ec.crt', 'leaf_ec.key', 'ca_ec.crt',
    'TLS_AES_128_GCM_SHA256');
end;

procedure TTLS13E2ETests.TestHandshakeAES256GCM;
begin
  RunE2E('leaf_rsa.crt', 'leaf_rsa.key', 'ca_rsa.crt',
    'TLS_AES_256_GCM_SHA384');
end;

procedure TTLS13E2ETests.TestHandshakeChaCha20;
begin
  RunE2E('leaf_rsa.crt', 'leaf_rsa.key', 'ca_rsa.crt',
    'TLS_CHACHA20_POLY1305_SHA256');
end;

initialization
  RegisterTest(TTLS13E2ETests);

end.
