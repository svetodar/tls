{ SPDX-License-Identifier: Apache-2.0 }
unit e2e_support;
{ Shared helpers for the end-to-end tests (tests/test_tls12_e2e.pas,
  tests/test_tls13_e2e.pas and tests/test_tlssocket.pas).

  The e2e tests need a server certificate *and its private key*, plus a CA the
  client is told to trust. The private keys under tests/fixtures are
  git-ignored on purpose (`make fixtures` regenerates them), so a checkout
  cannot rely on them: either they are absent (the test silently skips) or they
  belong to another generation than the committed certificates (openssl then
  refuses to start s_server with "key values mismatch" and the test turns into
  an unexplained failure). TE2EPki removes that dependency: it generates a
  throwaway CA and a localhost leaf certificate with the openssl CLI into a
  private temporary directory, and deletes it again on destruction. The
  certificates the *library* tests parse and verify stay the committed
  fixtures; only the e2e tests, which need live key material, switch to the
  generated PKI.

  Also here: a bounded TCP connect. A hand-rolled retry loop over a blocking
  connect() can wait for the full SYN retransmission timeout on every attempt
  (tens of seconds on Windows), which is how a dead s_server used to hang the
  whole run instead of failing.

  Everything here requires the openssl CLI; callers skip the test when
  OpenSSLAvailable returns False. A present but *failing* openssl raises, so a
  broken setup is never silently reported as a pass. }

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, Process, ssockets, Sockets;

type
  TE2EKeyKind = (ekRSA, ekEC);

  { A self-signed CA and a leaf certificate for AServerNames, signed by it.
    Owns a private temporary directory with the generated PEM files. }
  TE2EPki = class
  private
    FDir: string;
    FCaCertPath: string;
    FCaKeyPath: string;
    FCertPath: string;
    FKeyPath: string;
    procedure RunOpenSSL(AArgs: TStrings; const AWhat: string);
    procedure Generate(AKind: TE2EKeyKind; const ACommonName,
      AServerNames: string);
  public
    { AKind selects the key type of both the CA and the leaf; AServerNames is
      a comma separated list of DNS names for subjectAltName, the first one is
      also the subject CN. Raises when openssl cannot produce the files. }
    constructor Create(AKind: TE2EKeyKind; const ACommonName,
      AServerNames: string);
    destructor Destroy; override;
    property CaCertPath: string read FCaCertPath;
    property CertPath: string read FCertPath;
    property KeyPath: string read FKeyPath;
  end;

{ True when the openssl CLI can be executed at all. }
function OpenSSLAvailable: Boolean;

{ Runs AExe with AArgs, merges stderr into AOutput and returns the exit code.
  Raises EProcess when the program cannot be started. }
function RunCapture(const AExe: string; const AArgs: array of string;
  out AOutput: string): Integer;

{ Free TCP port: bind(0) on a temporary socket and read the assigned port
  via getsockname. }
function FindFreeLocalPort: Word;

{ Connects to 127.0.0.1:APort, retrying until ATimeoutMs expires; nil when the
  port never accepted. Every single attempt uses a bounded connect, so the
  call returns within roughly ATimeoutMs + the per-attempt bound. ATimeoutMs is
  generous enough for a slow machine to load and bind the server, and finite,
  so a server that died (bad key, port in use) fails instead of hanging.
  ALastError reports the last failure reason ('' when the connect succeeded). }
function ConnectLocal(APort: Word; ATimeoutMs: Integer;
  out ALastError: string): TInetSocket; overload;
function ConnectLocal(APort: Word; ATimeoutMs: Integer = 15000): TInetSocket; overload;

{ Starts `openssl s_server -accept <free port> -cert ACertPath -key AKeyPath
  AExtraArgs... -naccept 1 -quiet`. Returns nil when openssl is unavailable
  (the caller skips); raises when openssl is there but cannot start. }
function StartOpenSSLServer(const ACertPath, AKeyPath: string;
  const AExtraArgs: array of string; out APort: Word;
  const AWorkDir: string = ''): TProcess;

{ Human readable state of a started server, for the failure message of a test
  whose connect did not get through ("still running", "exited with code N"). }
function ServerStateText(const AProcess: TProcess): string;

{ Starts a server for ACertPath/AKeyPath and connects to it. A freshly started
  s_server is not always reachable on the first try (the port can be taken
  between the free-port probe and the bind, or the local firewall needs a
  moment for a new listener), so the pair is retried with a fresh port.
  Returns the connected socket, or nil when openssl is unavailable (AProcess is
  nil then) or every attempt failed (AProcess is the last process, which the
  caller must terminate and free; AReasons says what went wrong). }
function StartServerAndConnect(const ACertPath, AKeyPath: string;
  const AExtraArgs: array of string; out AProcess: TProcess; out APort: Word;
  out AReasons: string; const AWorkDir: string = ''): TInetSocket;

implementation

uses
  tls.rand;

const
  { Upper bound for one connect() attempt. Must be a whole number of seconds:
    FPC 3.2.2 turns the value into `tv_sec := Timeout div 1000` and zeroes
    tv_usec (fcl-net/ssockets.pp, CheckSocketConnectTimeout), so anything below
    1000 ms degenerates into a zero timeout and the connect fails at once. }
  ConnectAttemptTimeoutMs = 2000;
  { Buffer size for reading the output of one openssl invocation. }
  ReadChunkSize = 4096;

function RunCapture(const AExe: string; const AArgs: array of string;
  out AOutput: string): Integer;
var
  P: TProcess;
  i, N: LongInt;
  Buf: array[0..ReadChunkSize - 1] of Byte;

  procedure Drain;
  var
    M: LongInt;
  begin
    while P.Output.NumBytesAvailable > 0 do
    begin
      M := P.Output.Read(Buf, SizeOf(Buf));
      if M <= 0 then
        Break;
      SetLength(AOutput, Length(AOutput) + M);
      Move(Buf[0], AOutput[Length(AOutput) - M + 1], M);
    end;
  end;

begin
  AOutput := '';
  P := TProcess.Create(nil);
  try
    P.Executable := AExe;
    for i := 0 to High(AArgs) do
      P.Parameters.Add(AArgs[i]);
    P.Options := [poUsePipes, poStderrToOutPut];
    P.Execute;
    repeat
      Drain;
      if P.Running then
        Sleep(5);
    until not P.Running;
    Drain;
    Result := P.ExitStatus;
  finally
    P.Free;
  end;
end;

function OpenSSLAvailable: Boolean;
var
  Text: string;
begin
  Result := False;
  try
    RunCapture('openssl', ['version'], Text);
    Result := True;
  except
    on E: Exception do
      Result := False;
  end;
end;

function FindFreeLocalPort: Word;
var
  S: LongInt;
  Addr: TInetSockAddr;
  Len: LongInt;
begin
  S := fpSocket(AF_INET, SOCK_STREAM, 0);
  if S < 0 then
    raise Exception.Create('e2e: fpSocket() failed');
  try
    FillChar(Addr, SizeOf(Addr), 0);
    Addr.sin_family := AF_INET;
    Addr.sin_port := 0;
    Addr.sin_addr.s_addr := htonl(INADDR_ANY);
    if fpBind(S, @Addr, SizeOf(Addr)) <> 0 then
      raise Exception.Create('e2e: fpBind() failed');
    Len := SizeOf(Addr);
    if fpGetSockName(S, @Addr, @Len) <> 0 then
      raise Exception.Create('e2e: fpGetSockName() failed');
    Result := ntohs(Addr.sin_port);
  finally
    CloseSocket(S);
  end;
end;

function ConnectLocal(APort: Word; ATimeoutMs: Integer;
  out ALastError: string): TInetSocket;
var
  Deadline: QWord;
begin
  Result := nil;
  ALastError := '';
  Deadline := GetTickCount64 + QWord(ATimeoutMs);
  repeat
    try
      { The third parameter is the connect timeout: without it a connect to a
        port that nothing listens on can block for the whole SYN retransmit
        timeout. }
      Result := TInetSocket.Create('127.0.0.1', APort, ConnectAttemptTimeoutMs);
      Result.IOTimeout := 15000;
      ALastError := '';
      Exit;
    except
      on E: Exception do
      begin
        Result := nil;
        ALastError := E.ClassName + ': ' + E.Message;
        Sleep(25);
      end;
    end;
  until GetTickCount64 >= Deadline;
end;

function ConnectLocal(APort: Word; ATimeoutMs: Integer): TInetSocket;
var
  Ignored: string;
begin
  Result := ConnectLocal(APort, ATimeoutMs, Ignored);
end;

function ServerStateText(const AProcess: TProcess): string;
begin
  if AProcess = nil then
  begin
    Result := 'no server process';
    Exit;
  end;
  if AProcess.Running then
    Result := 'openssl s_server is still running'
  else
    Result := Format('openssl s_server exited with code %d',
      [AProcess.ExitStatus]);
end;

function StartOpenSSLServer(const ACertPath, AKeyPath: string;
  const AExtraArgs: array of string; out APort: Word;
  const AWorkDir: string): TProcess;
var
  P: TProcess;
  i: Integer;
begin
  Result := nil;
  APort := 0;
  if not OpenSSLAvailable then
    Exit;   { openssl unavailable — the caller skips }

  APort := FindFreeLocalPort;
  P := TProcess.Create(nil);
  try
    P.Executable := 'openssl';
    P.Parameters.Add('s_server');
    P.Parameters.Add('-accept');
    P.Parameters.Add(IntToStr(APort));
    P.Parameters.Add('-cert');
    P.Parameters.Add(ACertPath);
    P.Parameters.Add('-key');
    P.Parameters.Add(AKeyPath);
    for i := 0 to High(AExtraArgs) do
      P.Parameters.Add(AExtraArgs[i]);
    P.Parameters.Add('-naccept');
    P.Parameters.Add('1');
    P.Parameters.Add('-quiet');
    if AWorkDir <> '' then
      P.CurrentDirectory := AWorkDir;
    { No pipes: s_server with -quiet writes nothing on success, and leaving
      its stderr alone means a startup error still shows up in the test log
      instead of filling a pipe nobody reads. }
    P.Execute;
    Result := P;
  except
    P.Free;
    raise;
  end;
end;

function StartServerAndConnect(const ACertPath, AKeyPath: string;
  const AExtraArgs: array of string; out AProcess: TProcess; out APort: Word;
  out AReasons: string; const AWorkDir: string): TInetSocket;
const
  MaxAttempts = 3;
  PerAttemptTimeoutMs = 5000;
var
  Attempt: Integer;
  Failure: string;
  Sock: TInetSocket;
  P: TProcess;
begin
  Result := nil;
  AProcess := nil;
  APort := 0;
  AReasons := '';

  for Attempt := 1 to MaxAttempts do
  begin
    P := StartOpenSSLServer(ACertPath, AKeyPath, AExtraArgs, APort, AWorkDir);
    if P = nil then
      Exit;   { openssl unavailable — the caller skips }

    Sock := ConnectLocal(APort, PerAttemptTimeoutMs, Failure);
    if Sock <> nil then
    begin
      AProcess := P;
      Result := Sock;
      Exit;
    end;

    if AReasons <> '' then
      AReasons := AReasons + '; ';
    AReasons := AReasons + Format('attempt %d on port %d: %s [%s]',
      [Attempt, APort, Failure, ServerStateText(P)]);

    P.Terminate(0);
    P.Free;
  end;

  { Every attempt failed: hand the last process back so the caller can report
    its state and free it. }
  AProcess := StartOpenSSLServer(ACertPath, AKeyPath, AExtraArgs, APort,
    AWorkDir);
end;

{ --- TE2EPki ------------------------------------------------------------- }

procedure TE2EPki.RunOpenSSL(AArgs: TStrings; const AWhat: string);
var
  i: Integer;
  Args: array of string;
  Text: string;
  Code: Integer;
begin
  SetLength(Args, AArgs.Count);
  for i := 0 to AArgs.Count - 1 do
    Args[i] := AArgs[i];
  Code := RunCapture('openssl', Args, Text);
  if Code <> 0 then
    raise Exception.CreateFmt('e2e: openssl %s failed (exit code %d): %s',
      [AWhat, Code, Trim(Text)]);
end;

procedure TE2EPki.Generate(AKind: TE2EKeyKind; const ACommonName,
  AServerNames: string);
var
  Cmd: TStringList;
  Ext: TStringList;
  Conf: TStringList;
  ConfPath, CsrPath, ExtPath: string;
  CaName, SanList, Name, Rest: string;
  P: Integer;
begin
  ConfPath := IncludeTrailingPathDelimiter(FDir) + 'ca.cnf';
  CsrPath := IncludeTrailingPathDelimiter(FDir) + 'leaf.csr';
  ExtPath := IncludeTrailingPathDelimiter(FDir) + 'leaf.ext';
  if AKind = ekRSA then
    CaName := 'tls e2e test RSA CA'
  else
    CaName := 'tls e2e test EC CA';

  { CA certificate and key. The subject must differ from the leaf subject:
    with two certificates of the same name the chain builder cannot tell the
    root from the leaf (it rejects the leaf as "not a CA"). The extensions go
    into a private config so that openssl's default req extensions are not
    added on top of them, which would duplicate basicConstraints. }
  Conf := TStringList.Create;
  try
    Conf.Add('[ req ]');
    Conf.Add('prompt = no');
    Conf.Add('distinguished_name = dn');
    Conf.Add('x509_extensions = v3_ca');
    Conf.Add('');
    Conf.Add('[ dn ]');
    Conf.Add('CN = ' + CaName);
    Conf.Add('');
    Conf.Add('[ v3_ca ]');
    Conf.Add('basicConstraints = critical,CA:TRUE');
    Conf.Add('keyUsage = critical,keyCertSign,cRLSign');
    Conf.Add('subjectKeyIdentifier = hash');
    Conf.SaveToFile(ConfPath);
  finally
    Conf.Free;
  end;

  Cmd := TStringList.Create;
  try
    Cmd.Add('req');
    Cmd.Add('-x509');
    Cmd.Add('-nodes');
    Cmd.Add('-sha256');
    Cmd.Add('-days');
    Cmd.Add('3650');
    Cmd.Add('-config');
    Cmd.Add(ConfPath);
    if AKind = ekRSA then
    begin
      Cmd.Add('-newkey');
      Cmd.Add('rsa:2048');
    end
    else
    begin
      Cmd.Add('-newkey');
      Cmd.Add('ec');
      Cmd.Add('-pkeyopt');
      Cmd.Add('ec_paramgen_curve:prime256v1');
    end;
    Cmd.Add('-keyout');
    Cmd.Add(FCaKeyPath);
    Cmd.Add('-out');
    Cmd.Add(FCaCertPath);
    RunOpenSSL(Cmd, 'CA certificate');

    { Leaf private key (s_server takes it as a PEM file). }
    Cmd.Clear;
    if AKind = ekRSA then
    begin
      Cmd.Add('genrsa');
      Cmd.Add('-out');
      Cmd.Add(FKeyPath);
      Cmd.Add('2048');
    end
    else
    begin
      Cmd.Add('ecparam');
      Cmd.Add('-name');
      Cmd.Add('prime256v1');
      Cmd.Add('-genkey');
      Cmd.Add('-noout');
      Cmd.Add('-out');
      Cmd.Add(FKeyPath);
    end;
    RunOpenSSL(Cmd, 'leaf key');

    { Certificate signing request. }
    Cmd.Clear;
    Cmd.Add('req');
    Cmd.Add('-new');
    Cmd.Add('-key');
    Cmd.Add(FKeyPath);
    Cmd.Add('-subj');
    Cmd.Add('/CN=' + ACommonName);
    Cmd.Add('-out');
    Cmd.Add(CsrPath);
    RunOpenSSL(Cmd, 'leaf request');

    { subjectAltName entries: "a,b" -> "DNS:a,DNS:b". }
    SanList := '';
    Rest := AServerNames;
    repeat
      P := Pos(',', Rest);
      if P > 0 then
      begin
        Name := Trim(Copy(Rest, 1, P - 1));
        Rest := Copy(Rest, P + 1, MaxInt);
      end
      else
      begin
        Name := Trim(Rest);
        Rest := '';
      end;
      if Name = '' then
        Continue;
      if SanList <> '' then
        SanList := SanList + ',';
      SanList := SanList + 'DNS:' + Name;
    until Rest = '';

    Ext := TStringList.Create;
    try
      Ext.Add('basicConstraints=critical,CA:FALSE');
      if AKind = ekRSA then
        Ext.Add('keyUsage=critical,digitalSignature,keyEncipherment')
      else
        Ext.Add('keyUsage=critical,digitalSignature');
      Ext.Add('extendedKeyUsage=serverAuth');
      Ext.Add('subjectAltName=' + SanList);
      Ext.Add('subjectKeyIdentifier=hash');
      Ext.Add('authorityKeyIdentifier=keyid,issuer');
      Ext.SaveToFile(ExtPath);
    finally
      Ext.Free;
    end;

    { Sign the leaf with the generated CA. }
    Cmd.Clear;
    Cmd.Add('x509');
    Cmd.Add('-req');
    Cmd.Add('-in');
    Cmd.Add(CsrPath);
    Cmd.Add('-CA');
    Cmd.Add(FCaCertPath);
    Cmd.Add('-CAkey');
    Cmd.Add(FCaKeyPath);
    Cmd.Add('-CAcreateserial');
    Cmd.Add('-days');
    Cmd.Add('365');
    Cmd.Add('-sha256');
    Cmd.Add('-extfile');
    Cmd.Add(ExtPath);
    Cmd.Add('-out');
    Cmd.Add(FCertPath);
    RunOpenSSL(Cmd, 'leaf certificate');
  finally
    Cmd.Free;
    if FileExists(CsrPath) then
      DeleteFile(CsrPath);
    if FileExists(ExtPath) then
      DeleteFile(ExtPath);
  end;
end;

constructor TE2EPki.Create(AKind: TE2EKeyKind; const ACommonName,
  AServerNames: string);
var
  Seed: TBytes;
  i: Integer;
  Hex: string;
begin
  inherited Create;
  RandomBytes(Seed, 12);
  Hex := '';
  for i := 0 to High(Seed) do
    Hex := Hex + IntToHex(Seed[i], 2);
  FDir := IncludeTrailingPathDelimiter(GetTempDir) + 'tls-e2e-' + Hex;
  if not ForceDirectories(FDir) then
    raise Exception.CreateFmt('e2e: cannot create %s', [FDir]);
  FCaCertPath := IncludeTrailingPathDelimiter(FDir) + 'ca.crt';
  FCaKeyPath := IncludeTrailingPathDelimiter(FDir) + 'ca.key';
  FCertPath := IncludeTrailingPathDelimiter(FDir) + 'leaf.crt';
  FKeyPath := IncludeTrailingPathDelimiter(FDir) + 'leaf.key';
  try
    Generate(AKind, ACommonName, AServerNames);
  except
    Free;
    raise;
  end;
end;

destructor TE2EPki.Destroy;
var
  SR: TSearchRec;
  DirName: string;
begin
  if FDir <> '' then
  begin
    DirName := IncludeTrailingPathDelimiter(FDir);
    if FindFirst(DirName + '*', faAnyFile, SR) = 0 then
    begin
      repeat
        if (SR.Name <> '.') and (SR.Name <> '..') then
          DeleteFile(DirName + SR.Name);
      until FindNext(SR) <> 0;
      FindClose(SR);
    end;
    RemoveDir(FDir);
  end;
  inherited Destroy;
end;

end.
