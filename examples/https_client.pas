{ SPDX-License-Identifier: Apache-2.0 }
program https_client;
{ Minimal OpenSSL-free HTTPS client (layer 4, task 15 — docs/tasks/15-http.md).

  Performs an HTTPS GET using the pure-Pascal TLS stack:
    TInetSocket + TTLSSocketHandler (tls.tlssocket) -> tls.tls12.
  No FPC `openssl`/`opensslsockets` unit and no libssl/libcrypto is used.

  Usage:
    https_client <host> [port] [path] [cafile]
    https_client example.com 443 / /etc/ssl/certs/ca-certificates.crt

  Options:
    --insecure   do not verify the server certificate (demo/self-signed only)

  If no CA file is given and --insecure is not used, the client tries the
  well-known system bundles. Without a trust store the connection is refused
  (strict by default). }

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, ssockets,
  tls.tlssocket, tls.certstore;

const
  SystemCaBundles: array[0..3] of string = (
    '/etc/ssl/certs/ca-certificates.crt',
    '/etc/pki/tls/certs/ca-bundle.crt',
    '/etc/ssl/cert.pem',
    '/etc/ssl/ca-bundle.pem');

var
  Host: string = '';
  Port: Word = 443;
  Path: string = '/';
  CaFile: string = '';
  Insecure: Boolean = False;

procedure Usage;
begin
  WriteLn(ErrOutput, 'usage: https_client <host> [port] [path] [cafile] [--insecure]');
  Halt(2);
end;

procedure ParseArgs;
var
  i: Integer;
  Arg: string;
  Positional: Integer;
begin
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
      Usage;
    end;
  end;
  if Host = '' then
    Usage;
end;

{ Picks the first existing system CA bundle. }
function DefaultCaFile: string;
var
  i: Integer;
begin
  for i := Low(SystemCaBundles) to High(SystemCaBundles) do
    if FileExists(SystemCaBundles[i]) then
      Exit(SystemCaBundles[i]);
  Result := '';
end;

procedure Run;
var
  Handler: TTLSSocketHandler;
  Sock: TInetSocket;
  Request, Response: AnsiString;
  Buf: array[0..8191] of Byte;
  N: Integer;
begin
  Handler := TTLSSocketHandler.Create;
  Handler.VerifyPeerCert := not Insecure;
  if not Insecure then
  begin
    if CaFile = '' then
      CaFile := DefaultCaFile;
    if CaFile = '' then
      raise Exception.Create(
        'no CA bundle found; pass a cafile or use --insecure');
    Handler.TrustStorePath := CaFile;
  end;

  Sock := TInetSocket.Create(Host, Port, Handler);
  try
    Sock.IOTimeout := 30000;
    try
      Sock.Connect;
    except
      on E: Exception do
        raise Exception.Create(E.Message + ' (' +
          Handler.LastErrorString + ')');
    end;
    WriteLn(ErrOutput, 'TLS established with ', Host, ':', Port,
      ' (verify=', BoolToStr(not Insecure, True), ')');

    Request := 'GET ' + Path + ' HTTP/1.0'#13#10 +
      'Host: ' + Host + #13#10 +
      'User-Agent: tls-https_client/1.0'#13#10 +
      'Connection: close'#13#10#13#10;
    if Handler.Send(Request[1], Length(Request)) <> Length(Request) then
      raise Exception.Create('failed to send the HTTP request');

    Response := '';
    repeat
      N := Handler.Recv(Buf[0], SizeOf(Buf));
      if N < 0 then
        raise Exception.Create('TLS receive failed: ' +
          Handler.LastErrorString);
      if N = 0 then
        Break;
      SetLength(Response, Length(Response) + N);
      Move(Buf[0], Response[Length(Response) - N + 1], N);
    until False;
    Write(Response);
  finally
    Sock.Free;   {frees the handler as well}
  end;
end;

begin
  ParseArgs;
  try
    Run;
  except
    on E: Exception do
    begin
      WriteLn(ErrOutput, 'error: ', E.Message);
      Halt(1);
    end;
  end;
end.
