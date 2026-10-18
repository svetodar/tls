{ SPDX-License-Identifier: Apache-2.0 }
unit tls.tlssocket;

{TLS socket handler (layer 4, task 14 — docs/tasks/14-tlssocket.md).

  Wraps the TLS 1.2 client (tls.tls12.TTLS12Client) in a socket handler
  compatible with FPC sslsockets' TSSLSocketHandler, so that a consumer
  (e.g. an HTTP client built on fphttpclient) can use it instead of
  opensslsockets without depending on the system OpenSSL.

  TTLSSocketHandler implements the same interface as TOpenSSLSocketHandler
  (see docs/reference/opensslsockets.pp):
    - Connect: TCP connection + TLS handshake (client).
    - Send/Recv: encrypted read/write.
    - Shutdown, Close, BytesAvailable.
    - DoVerifyCert: certificate chain and host-name verification.
    - CreateCertGenerator: stub (server mode is out of scope).

  TTLSInetSocketTransport is an ITLSTransport adapter that reads/writes raw
  bytes on a connected socket. It deliberately bypasses the socket's own
  handler (which would otherwise recurse into TTLSSocketHandler.Recv/Send)
  and talks to the file descriptor with fprecv/fpsend.

  Registration as the default handler (analogous to initialization in
  opensslsockets): TSSLSocketHandler.SetDefaultHandlerClass(TTLSSocketHandler).

  By default VerifyPeerCert is True: a trust store is resolved from the
  TrustStore/TrustStorePath properties or CertificateData.CertCA.FileName,
  and on Windows falls back to the system certificate store (Root + CA)
  unless DisableSystemStore is True; if no store can be resolved, Connect
  returns False. Set VerifyPeerCert := False only when the caller
  intentionally accepts any server certificate. }

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Sockets, ssockets, sslsockets, sslbase,
  tls.tls12, tls.x509, tls.certstore;

type
  {ITLSTransport adapter over a connected socket.
    Return codes follow the ITLSTransport convention:
      Read:  > 0 — bytes read;  0 — EOF;  -1 — error.
      Write: > 0 — bytes written (possibly fewer than requested); -1 — error. }
  TTLSInetSocketTransport = class(TInterfacedObject, ITLSTransport)
  private
    FSocket: TSocketStream;
  public
    constructor Create(ASocket: TSocketStream);
    function Read(var ABuffer; ACount: LongInt): LongInt;
    function Write(const ABuffer; ACount: LongInt): LongInt;
    function BytesAvailable: LongInt;
    property Socket: TSocketStream read FSocket;
  end;

  {TLS socket handler compatible with FPC sslsockets' TSSLSocketHandler.
    Wraps TTLS12Client for the TLS 1.2 handshake and data exchange.
    Client-only: server mode and certificate generation are out of scope.

    Usage:
      handler := TTLSSocketHandler.Create;
      handler.VerifyPeerCert := True;
      handler.TrustStorePath := '/etc/ssl/certs/ca-certificates.crt';
      sock := TInetSocket.Create('example.com', 443, handler);
      sock.Connect;
      // ... Send / Recv ...
      handler.Shutdown(False);
      sock.Free; }
  TTLSSocketHandler = class(TSSLSocketHandler)
  private
    FClient: TTLS12Client;
    FTransport: ITLSTransport;
    FTrustStore: TCertStore;
    FOwnsTrustStore: Boolean;
    FLastErrorString: string;
    procedure SetTrustStore(const AValue: TCertStore);
    procedure SetTrustStorePath(const AValue: string);
    function GetTransportHost: string;
    procedure ReleaseTLS;
  protected
    {Certificate chain verification is performed by TTLS12Client during
      Connect; this method additionally checks the server name (SNI/host)
      and invokes the inherited OnVerifyCertificate event.}
    function DoVerifyCert: Boolean; override;
  public
    {When True, disables the automatic fallback to the Windows system
      certificate store on Windows (see Connect). Default is False.}
    DisableSystemStore: Boolean;
    constructor Create; override;
    destructor Destroy; override;
    {TCP connection + TLS handshake. Returns True on success. On failure
      LastErrorString carries a human-readable reason.

      Trust store resolution, in order:
        1. the TrustStore property, if set;
        2. a bundle loaded from CertificateData.CertCA.FileName;
        3. on Windows only, the system certificate store (Root + CA) via
           LoadWindowsSystemStore, unless DisableSystemStore is True.
      If VerifyPeerCert is True and no store can be resolved, Connect
      returns False.}
    function Connect: Boolean; override;
    {Closes the TLS connection (sends close_notify).}
    function Close: Boolean; override;
    {Shuts down the TLS connection. If BiDirectional, also shuts down
      the underlying socket.}
    function Shutdown(BiDirectional: Boolean): Boolean; override;
    {Sends application data over the encrypted channel.
      Returns the number of bytes sent, or -1 on error.}
    function Send(const Buffer; Count: Integer): Integer; override;
    {Receives application data from the encrypted channel.
      Returns the number of bytes received:
        > 0 — bytes read;  0 — connection closed;  -1 — error.}
    function Recv(const Buffer; Count: Integer): Integer; override;
    {Number of decrypted bytes buffered in the TLS client.}
    function BytesAvailable: Integer; override;
    {Certificate generator stub — server mode is out of scope.
      Returns nil.}
    function CreateCertGenerator: TX509Certificate; override;
    {Optional trust store for certificate verification. The handler does
      not take ownership; the caller keeps responsibility for freeing it.}
    property TrustStore: TCertStore read FTrustStore write SetTrustStore;
    {Load a bundle of PEM certificates from a file (e.g.
      /etc/ssl/certs/ca-certificates.crt). The handler owns the loaded
      store and frees it in Destroy.}
    property TrustStorePath: string write SetTrustStorePath;
    {Reason for the last Connect/Send/Recv failure (empty if none).}
    property LastErrorString: string read FLastErrorString;
  end;

implementation

{MSG_NOSIGNAL is unavailable on Windows; there SIGPIPE does not exist
  either, so flag 0 is safe.}
{$ifdef windows}
const
  TLSSendFlags = 0;
{$else}
const
  TLSSendFlags = MSG_NOSIGNAL;
{$endif}

{--- TTLSInetSocketTransport ------------------------------------------}

constructor TTLSInetSocketTransport.Create(ASocket: TSocketStream);
begin
  inherited Create;
  FSocket := ASocket;
end;

function TTLSInetSocketTransport.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  if (FSocket = nil) or (ACount <= 0) then
    Exit(TLSTransportError);
  Result := fprecv(FSocket.Handle, @ABuffer, ACount, 0);
  if Result < 0 then
    Result := TLSTransportError;
end;

function TTLSInetSocketTransport.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  if (FSocket = nil) or (ACount <= 0) then
    Exit(TLSTransportError);
  Result := fpsend(FSocket.Handle, @ABuffer, ACount, TLSSendFlags);
  if Result < 0 then
    Result := TLSTransportError;
end;

function TTLSInetSocketTransport.BytesAvailable: LongInt;
begin
  {Raw bytes are not tracked here; decrypted application data is buffered
    by TTLS12Client and exposed through TTLSSocketHandler.BytesAvailable.}
  Result := 0;
end;

{--- Helpers ----------------------------------------------------------}

{Whether AHost is an IPv4 literal. RFC 6066 forbids sending an IP address
  in the SNI server_name extension, and host checking then relies on an
  iPAddress subjectAltName (or the CN).}
function IsIPLiteral(const AHost: string): Boolean;
var
  Addr: in_addr;
begin
  Result := TryStrToHostAddr(AHost, Addr);
end;

{--- TTLSSocketHandler ------------------------------------------------}

constructor TTLSSocketHandler.Create;
begin
  inherited Create;
  FClient := nil;
  FTransport := nil;
  FTrustStore := nil;
  FOwnsTrustStore := False;
  DisableSystemStore := False;
  FLastErrorString := '';
  {Secure default: verify the server certificate.}
  VerifyPeerCert := True;
end;

destructor TTLSSocketHandler.Destroy;
begin
  ReleaseTLS;
  if FOwnsTrustStore and (FTrustStore <> nil) then
    FTrustStore.Free;
  FTrustStore := nil;
  inherited Destroy;
end;

procedure TTLSSocketHandler.ReleaseTLS;
begin
  if FClient <> nil then
  begin
    try
      FClient.Shutdown;
    except
      on E: Exception do
        {Best effort: the connection is being torn down anyway.}
        FLastErrorString := E.Message;
    end;
    FClient.Free;
    FClient := nil;
  end;
  if FTransport <> nil then
  begin
    {Interface reference: releasing it frees the transport as soon as the
      client (already destroyed above) no longer holds a reference.}
    FTransport := nil;
  end;
  SetSSLActive(False);
end;

procedure TTLSSocketHandler.SetTrustStore(const AValue: TCertStore);
begin
  if FOwnsTrustStore and (FTrustStore <> nil) then
    FTrustStore.Free;
  FTrustStore := AValue;
  FOwnsTrustStore := False;
end;

procedure TTLSSocketHandler.SetTrustStorePath(const AValue: string);
begin
  if FOwnsTrustStore and (FTrustStore <> nil) then
    FTrustStore.Free;
  FTrustStore := nil;
  FOwnsTrustStore := False;
  if AValue <> '' then
  begin
    FTrustStore := LoadBundle(AValue);
    FOwnsTrustStore := True;
  end;
end;

function TTLSSocketHandler.GetTransportHost: string;
begin
  if Socket is TInetSocket then
    Result := (Socket as TInetSocket).Host
  else
    Result := '';
end;

function TTLSSocketHandler.DoVerifyCert: Boolean;
var
  Host: string;
  Leaf: TX509Cert;
begin
  Result := inherited DoVerifyCert;   {OnVerifyCertificate event}
  if not Result then
  begin
    if FLastErrorString = '' then
      FLastErrorString := 'certificate rejected by OnVerifyCertificate';
    Exit;
  end;
  if not VerifyPeerCert then
    Exit(True);

  if (FClient = nil) or (FClient.CertChain = nil) then
  begin
    FLastErrorString := 'no server certificate chain available';
    Exit(False);
  end;
  if FClient.CertChain.Count = 0 then
  begin
    FLastErrorString := 'empty server certificate chain';
    Exit(False);
  end;
  Leaf := FClient.CertChain.Leaf;
  if Leaf = nil then
  begin
    FLastErrorString := 'no leaf certificate in the server chain';
    Exit(False);
  end;

  Host := GetTransportHost;
  if Host = '' then
    Exit(True);
  if not CertMatchesHost(Leaf, Host) then
  begin
    FLastErrorString := 'certificate does not match host "' + Host + '"';
    Exit(False);
  end;
  Result := True;
end;

function TTLSSocketHandler.Connect: Boolean;
var
  Opts: TTLSClientHelloOptions;
  Store: TCertStore;
  OwnsLocal: Boolean;
  Host: string;
begin
  Result := False;
  FLastErrorString := '';

  if Socket = nil then
  begin
    FLastErrorString := 'socket not assigned';
    Exit;
  end;

  {Drop any previous TLS session (Connect is single-use).}
  ReleaseTLS;

  Host := GetTransportHost;

  FTransport := TTLSInetSocketTransport.Create(Socket);
  FClient := TTLS12Client.Create;
  Opts := DefaultTLS12ClientHelloOptions;
  if SendHostAsSNI and (Host <> '') and (not IsIPLiteral(Host)) then
    Opts.ServerName := Host;
  FClient.Options := Opts;

  {Resolve the trust store: an explicit store wins, then CertificateData,
    then a transient bundle loaded from the file name.}
  Store := FTrustStore;
  OwnsLocal := False;
  if (Store = nil) and (CertificateData <> nil) and
    (CertificateData.CertCA.FileName <> '') then
  begin
    Store := LoadBundle(CertificateData.CertCA.FileName);
    OwnsLocal := True;
  end;
{$ifdef windows}
  {On Windows, when verification is requested and no store is configured,
    fall back to the system certificate store (Root + CA) unless
    DisableSystemStore is set. The handler owns the loaded store and
    frees it below (OwnsLocal).}
  if VerifyPeerCert and (Store = nil) and not DisableSystemStore then
  begin
    Store := LoadWindowsSystemStore;
    OwnsLocal := True;
  end;
{$endif}

  if VerifyPeerCert and (Store = nil) then
  begin
    FLastErrorString :=
      'certificate verification requested but no trust store configured';
    if OwnsLocal then
      Store.Free;
    ReleaseTLS;
    Exit(False);
  end;

  FClient.TrustStore := Store;
  try
    FClient.Connect(FTransport);
  except
    on E: Exception do
    begin
      FLastErrorString := E.Message;
      FClient.TrustStore := nil;
      if OwnsLocal then
        Store.Free;
      ReleaseTLS;
      Exit(False);
    end;
  end;

  {The chain is parsed and owned by the client; do not leave the trust
    store dangling in the client after Connect.}
  FClient.TrustStore := nil;
  if OwnsLocal then
    Store.Free;

  if not DoVerifyCert then
  begin
    if FLastErrorString = '' then
      FLastErrorString := 'certificate verification failed';
    ReleaseTLS;
    Exit(False);
  end;

  SetSSLActive(True);
  Result := True;
end;

function TTLSSocketHandler.Close: Boolean;
begin
  Result := Shutdown(False);
end;

function TTLSSocketHandler.Shutdown(BiDirectional: Boolean): Boolean;
begin
  Result := True;
  ReleaseTLS;
  if BiDirectional and (Socket <> nil) then
    if fpshutdown(Socket.Handle, SHUT_WR) <> 0 then
      Result := False;
end;

function TTLSSocketHandler.Send(const Buffer; Count: Integer): Integer;
var
  Data: TBytes;
begin
  if (FClient = nil) or (not FClient.HandshakeDone) then
  begin
    FLastErrorString := 'TLS connection is not established';
    Exit(-1);
  end;
  if Count <= 0 then
    Exit(0);
  SetLength(Data, Count);
  Move(Buffer, Data[0], Count);
  try
    FClient.Send(Data);
    Result := Count;
  except
    on E: Exception do
    begin
      FLastErrorString := E.Message;
      Result := -1;
    end;
  end;
end;

function TTLSSocketHandler.Recv(const Buffer; Count: Integer): Integer;
var
  Temp: TBytes;
  N: LongInt;
begin
  if (FClient = nil) or (not FClient.HandshakeDone) then
  begin
    FLastErrorString := 'TLS connection is not established';
    Exit(-1);
  end;
  if Count <= 0 then
    Exit(0);
  try
    SetLength(Temp, Count);
    N := FClient.Recv(Temp[0], Count);
    if N > 0 then
      Move(Temp[0], PByte(@Buffer)[0], N);
    Result := N;
  except
    on E: Exception do
    begin
      FLastErrorString := E.Message;
      Result := -1;
    end;
  end;
end;

function TTLSSocketHandler.BytesAvailable: Integer;
begin
  if FClient = nil then
    Result := 0
  else
    Result := FClient.PendingBytes;
end;

function TTLSSocketHandler.CreateCertGenerator: TX509Certificate;
begin
  {Server mode is out of scope (task 14). Return nil; the base class
    stores it in FCertGenerator and never uses it for client connections.}
  Result := nil;
end;

initialization
  TSSLSocketHandler.SetDefaultHandlerClass(TTLSSocketHandler);

end.
