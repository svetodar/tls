{ SPDX-License-Identifier: Apache-2.0 }
unit test_tls13_e2e;
{ E2E test TLS 1.3 (milestone F): full client handshake and data exchange
  with a real `openssl s_server -tls1_3` server, following the pattern of
  tests/test_tls12_e2e.pas.

  The test starts a local `openssl s_server -tls1_3 -www` with a certificate
  and key, connects via a TCP socket and drives the whole handshake
  with TTLS13Client (ClientHello -> ServerHello/EncryptedExtensions/
  Certificate/CertificateVerify/Finished, then the client Finished),
  verifies the certificate chain, sends an HTTP request and checks the
  response.

  The certificate, its private key and the CA the client trusts are generated
  for the run by e2e_support.TE2EPki, so the test does not depend on the
  git-ignored keys in tests/fixtures. If the openssl binary is unavailable the
  test is skipped; if openssl is present but the PKI or the server cannot be
  set up, it fails with a message instead of hanging or passing silently. }

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
  SysUtils, Classes, Process, ssockets,
  e2e_support,
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

{ The certificate, key, port and bounded connect helpers live in
  e2e_support: this unit only drives the TLS 1.3 session. }

{ Full TLS 1.3 handshake and HTTP exchange through TTLS13Client over an
  already established socket (the caller starts the server and connects, see
  e2e_support.StartServerAndConnect). Raises ETLS13Error on any
  protocol/verification error. }
procedure RunTLS13Session(ASock: TInetSocket; const ACaCertPath: string;
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
  Sock := ASock;
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

{ General scenario: generate a throwaway PKI, start openssl s_server, run the
  handshake and check the HTTP response. Skipped only when openssl itself is
  missing; every other failure raises, so a broken setup never passes silently
  and never hangs (the server start and the connect are bounded and retried,
  see e2e_support.StartServerAndConnect). }
procedure RunE2E(AKind: TE2EKeyKind; const ACipherSuites, AGroups: string;
  ACipherSuite: TTLSCipherSuite);
var
  Pki: TE2EPki;
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  Response: AnsiString;
  Reasons: string;
begin
  if not OpenSSLAvailable then
    Exit;   { openssl unavailable — test skipped }

  Pki := TE2EPki.Create(AKind, 'localhost', 'localhost');
  try
    Sock := StartServerAndConnect(Pki.CertPath, Pki.KeyPath,
      ['-tls1_3', '-ciphersuites', ACipherSuites, '-groups', AGroups, '-www'],
      P, Port, Reasons);
    if (Sock = nil) and (P = nil) then
      Exit;   { openssl disappeared between the check and the start }
    try
      if Sock = nil then
        raise ETLS13Error.CreateFmt(
          'openssl s_server did not accept a connection on port %d: %s',
          [Port, Reasons]);

      Response := '';
      RunTLS13Session(Sock, Pki.CaCertPath, ACipherSuite, Response);

      if Length(Response) = 0 then
        raise ETLS13Error.Create('server response not received');
      if Pos('HTTP/1.0 200', Response) = 0 then
        raise ETLS13Error.Create('no HTTP 200 from s_server: ' +
          Copy(Response, 1, 64));
    finally
      P.Terminate(0);
      P.Free;
    end;
  finally
    Pki.Free;
  end;
end;

{ ==================================================================== }
{ Tests                                                                }
{ ==================================================================== }

procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerRSA;
begin
  RunE2E(ekRSA, 'TLS_AES_128_GCM_SHA256', 'P-256',
    TLS13CipherAES128GCMSHA256);
end;

procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerEC;
begin
  RunE2E(ekEC, 'TLS_AES_128_GCM_SHA256', 'P-256',
    TLS13CipherAES128GCMSHA256);
end;

{ SHA-384 key schedule and a P-384 key share. The certificate is RSA, so
  the server picks rsa_pss_rsae_sha256 for CertificateVerify: the signature
  scheme is independent of the cipher suite hash (RFC 8446, 4.4.3). }
procedure TTLS13E2ETests.TestHandshakeAndHttpWithOpenSSLServerSHA384;
begin
  RunE2E(ekRSA, 'TLS_AES_256_GCM_SHA384', 'P-384',
    TLS13CipherAES256GCMSHA384);
end;

initialization
  RegisterTest(TTLS13E2ETests);

end.
