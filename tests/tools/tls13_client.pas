{ SPDX-License-Identifier: Apache-2.0 }
program tls13_client;
{ Manual TLS 1.3 client check (milestone F, docs/tasks/13-tls13.md).

  Drives a full TLS 1.3 1-RTT handshake with TTLS13Client over a real TCP
  connection, verifies the server certificate chain against a trust store,
  performs an HTTPS GET and prints the negotiated cipher suite, the leaf
  certificate subject and the HTTP status line. Standalone debugging tool:
  not part of the fpcunit test run.

  Usage:
    tls13_client <host> [port] [path] [cafile] [--insecure]
    tls13_client example.com 443 / /etc/ssl/certs/ca-certificates.crt

  Without a CA file the well-known system bundles are tried; on Windows
  the system certificate store (Root + CA) is used via
  LoadWindowsSystemStore. --insecure disables chain verification
  (self-signed/openssl s_server only). }

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, ssockets,
  tls.tls12, tls.tls13, tls.certstore, tls.x509;

const
  SystemCaBundles: array[0..3] of string = (
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/tls/certs/ca-bundle.crt',
    '/etc/ssl/cert.pem',
    '/etc/ssl/ca-bundle.pem');

function StrBytes(const S: AnsiString): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Ord(S[i]);
end;

function DefaultCaFile: string;
var
  i: Integer;
begin
  for i := Low(SystemCaBundles) to High(SystemCaBundles) do
    if FileExists(SystemCaBundles[i]) then
      Exit(SystemCaBundles[i]);
  Result := '';
end;

function SuiteName(ASuite: TTLSCipherSuite): string;
begin
  case ASuite of
    TLS13CipherAES128GCMSHA256: Result := 'TLS_AES_128_GCM_SHA256';
    TLS13CipherAES256GCMSHA384: Result := 'TLS_AES_256_GCM_SHA384';
    TLS13CipherCHACHA20POLY1305SHA256: Result := 'TLS_CHACHA20_POLY1305_SHA256';
  else
    Result := Format('0x%.4x', [ASuite]);
  end;
end;

var
  Host, Path, CaFile: string;
  Port: Word;
  Insecure: Boolean;

procedure ParseArgs;
var
  i, Positional: Integer;
  Arg: string;
begin
  Host := ''; Path := '/'; CaFile := ''; Port := 443; Insecure := False;
  Positional := 0;
  for i := 1 to ParamCount do
  begin
    Arg := ParamStr(i);
    if Arg = '--insecure' then
    begin
      Insecure := True;
      Continue;
    end;
    Inc(Positional);
    case Positional of
      1: Host := Arg;
      2: Port := StrToIntDef(Arg, 443);
      3: Path := Arg;
      4: CaFile := Arg;
    else
      WriteLn(ErrOutput, 'too many arguments');
      Halt(2);
    end;
  end;
  if Host = '' then
  begin
    WriteLn(ErrOutput,
      'usage: tls13_client <host> [port] [path] [cafile] [--insecure]');
    Halt(2);
  end;
end;

var
  Sock: TInetSocket;
  Transport: ITLSTransport;
  Client: TTLS13Client;
  Store: TCertStore;
  Opts: TTLS13ClientHelloOptions;
  Chain: TTLS12CertChain;
  VR: TVerifyResult;
  Req: TBytes;
  Buf: array[0..4095] of Byte;
  N, Total: LongInt;
  Text: AnsiString;
  StatusLine: string;
  Failed: Boolean;

begin
  Failed := False;
  ParseArgs;
  if (not Insecure) and (CaFile = '') then
    CaFile := DefaultCaFile;
  if (not Insecure) and (CaFile <> '') and (not FileExists(CaFile)) then
  begin
    WriteLn(ErrOutput, 'CA bundle not found: ', CaFile);
    Halt(3);
  end;

  WriteLn('connecting to ', Host, ':', Port, ' ...');
  Sock := TInetSocket.Create(Host, Port);
  Sock.IOTimeout := 15000;
  Transport := TTLSStreamTransport.Create(Sock);
  Store := nil;
  if (not Insecure) and (CaFile = '') then
  begin
{$ifdef windows}
    {No CA file: use the Windows system certificate store (Root + CA).
      The caller owns this store and frees it in the finally block.}
    Store := LoadWindowsSystemStore;
{$else}
    WriteLn(ErrOutput, 'no CA bundle found; use --insecure for a test server');
    Halt(3);
{$endif}
  end;

  Client := TTLS13Client.Create;
  try
    if not Insecure then
    begin
      if Store = nil then
        Store := LoadBundle(CaFile);
      Client.TrustStore := Store;
    end;

    Opts := DefaultTLS13ClientHelloOptions;
    Opts.ServerName := Host;
    Client.Options := Opts;
    Client.Connect(Transport);
    WriteLn('handshake: OK');
    WriteLn('cipher suite: ', SuiteName(Client.CipherSuite));

    Chain := Client.CertChain;
    if (Chain = nil) or (Chain.Count = 0) then
      WriteLn('certificate: not received')
    else
    begin
      WriteLn('leaf subject: ', Chain.Leaf.Subject.ToNameString);
      if not Insecure then
      begin
        VR := Chain.Verify(Store);
        WriteLn('chain verification: ', BoolToStr(VR.OK, 'OK', 'FAILED'),
          ' (chain length ', VR.ChainLen, ')');
        if not VR.OK then
          WriteLn('  reason: ', VR.Reason);
        if not CertMatchesHost(Chain.Leaf, Host) then
          WriteLn('hostname check: FAILED for ', Host)
        else
          WriteLn('hostname check: OK');
      end;
    end;

    Req := StrBytes('GET ' + Path + ' HTTP/1.0'#13#10 +
      'Host: ' + Host + #13#10 +
      'User-Agent: tls13_client'#13#10#13#10);
    Client.Send(Req);

    Total := 0;
    Text := '';
    while True do
    begin
      N := Client.Recv(Buf, SizeOf(Buf));
      if N <= 0 then
        Break;
      SetLength(Text, Length(Text) + N);
      Move(Buf[0], Text[Length(Text) - N + 1], N);
      Inc(Total, N);
    end;
    Client.Shutdown;

    WriteLn('received bytes: ', Total);
    StatusLine := Copy(Text, 1, Pos(#13#10, Text) - 1);
    if StatusLine = '' then
      StatusLine := Copy(Text, 1, 80);
    WriteLn('status: ', StatusLine);
    if Total = 0 then
    begin
      WriteLn(ErrOutput, 'FAILED: no application data received');
      Failed := True;
    end;
  finally
    Client.Free;
    Transport := nil;
    Store.Free;
    Sock.Free;
  end;
  if Failed then
    Halt(1);
end.
