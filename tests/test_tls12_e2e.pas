{ SPDX-License-Identifier: Apache-2.0 }
unit test_tls12_e2e;
{ E2E test TLS 1.2 (milestone D): full client handshake and data exchange
  with a real `openssl s_server` server.

  The test starts a local `openssl s_server -tls1_2 -www` with a certificate
  and key, connects via TCP socket and performs the full handshake
  using tls.tls12 primitives (ClientHello -> ServerHello/Certificate/
  ServerKeyExchange/ServerHelloDone -> ClientKeyExchange -> CCS/Finished),
  verifies the certificate and the ServerKeyExchange signature, then sends
  an HTTP request and verifies the response.

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
  TTLSE2ETests = class(TTestCase)
  published
    procedure TestHandshakeAndHttpWithOpenSSLServerRSA;
    procedure TestHandshakeAndHttpWithOpenSSLServerEC;
  end;

implementation

uses
  SysUtils, Classes, Process, ssockets,
  e2e_support,
  tls.tls12, tls.prf, tls.rand, tls.sha2, tls.hmac, tls.x509,
  tls.certstore;

{ ==================================================================== }
{ Helper functions                                              }
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

function BytesToStr(const B: TBytes): AnsiString;
var
  i: Integer;
begin
  SetLength(Result, Length(B));
  for i := 0 to High(B) do
    Result[i + 1] := AnsiChar(B[i]);
end;

{ The certificate, key, port and bounded connect helpers live in
  e2e_support: this unit only drives the TLS 1.2 session. }
{ Full TLS 1.2 client handshake and HTTP exchange over the transport.
  Raises ETLS12Error on any protocol/verification error. }
procedure RunTLS12Session(ATransport: ITLSTransport;
  ACipherSuite: TTLSCipherSuite; const ACaCertPath: string;
  out AResponse: AnsiString);
var
  ClientRandom, HelloBody, CKEBody, Premaster, SessionHash, Master: TBytes;
  FinishedBody, FinMsg, ClientVD, ServerVD, Frag, Plain, Req: TBytes;
  Options: TTLSClientHelloOptions;
  Suites: TTLSCipherSuites;
  Groups: TTLSNamedGroups;
  Buffer: TTLSHandshakeBuffer;
  ServerMsgs: TTLSHandshakeMessages;
  Hello: TTLSServerHello;
  CertMsg: TTLSCertificateMessage;
  SKE: TTLSServerKeyExchange;
  HasCert, HasSKE: Boolean;
  Chain: TTLS12CertChain;
  Store: TCertStore;
  CaCert: TX509Cert;
  VR: TVerifyResult;
  EKey: TTLS12ECDHEClientKey;
  KB: TTLS12KeyBlock;
  HashKind: THashKind;
  Mode: TTLSAEADMode;
  Rec: TTLSRecord;
  Fin: TTLSHandshakeMessage;
  ServerSeq: QWord;
begin
  AResponse := '';

  RandomBytes(ClientRandom, 32);
  Options := DefaultTLS12ClientHelloOptions;
  Options.ServerName := 'localhost';
  Options.ClientRandom := ClientRandom;
  SetLength(Suites, 1);
  Suites[0] := ACipherSuite;
  Options.CipherSuites := Suites;
  SetLength(Groups, 1);
  Groups[0] := TLSNamedGroupSecp256r1;
  Options.SupportedGroups := Groups;

  Buffer := TTLSHandshakeBuffer.Create;
  Chain := nil;
  try
    { ClientHello }
    HelloBody := BuildTLS12ClientHelloBody(Options);
    WriteTLSHandshakeMessage(ATransport, htClientHello, HelloBody);
    Buffer.AppendTranscript(htClientHello, HelloBody);

    { ServerHello, Certificate, ServerKeyExchange, ServerHelloDone }
    if not ReadTLSHandshakeFlight(ATransport, Buffer,
      [htServerHelloDone], ServerMsgs) then
      raise ETLS12Error.Create('server closed connection before ServerHelloDone');
    if not ParseTLS12ServerFlight(ServerMsgs, Hello, CertMsg, SKE,
      HasCert, HasSKE) then
      raise ETLS12Error.Create('failed to parse server flight');
    if not HasCert then
      raise ETLS12Error.Create('server did not send Certificate');
    if not HasSKE then
      raise ETLS12Error.Create('server did not send ServerKeyExchange');

    { Verify the certificate chain and the ServerKeyExchange signature. }
    Chain := ParseTLS12CertChain(CertMsg);
    Store := TCertStore.Create;
    CaCert := LoadPEM(ACaCertPath);
    try
      Store.Add(CaCert);
      VR := Chain.Verify(Store);
      if not VR.OK then
        raise ETLS12Error.Create('chain verification failed: ' + VR.Reason);
    finally
      CaCert.Free;
      Store.Free;
    end;
    if not VerifyTLS12ServerKeyExchange(Chain, ClientRandom,
      Hello.ServerRandom, SKE) then
      raise ETLS12Error.Create('ServerKeyExchange signature is invalid');

    { ClientKeyExchange (ECDHE) and premaster secret. }
    EKey := TTLS12ECDHEClientKey.Create(SKE.NamedCurve);
    try
      CKEBody := EKey.ClientKeyExchangeBody;
      WriteTLSHandshakeMessage(ATransport, htClientKeyExchange, CKEBody);
      Buffer.AppendTranscript(htClientKeyExchange, CKEBody);
      Premaster := EKey.PremasterSecret(SKE.ECDHEPublicKey);
    finally
      EKey.Free;
    end;

    { master secret and key block. }
    HashKind := TLS12CipherSuiteHashKind(Hello.CipherSuite);
    Mode := TLS12CipherSuiteAEADMode(Hello.CipherSuite);
    if Hello.ExtendedMasterSecret then
    begin
      SessionHash := TLS12TranscriptHash(HashKind, Buffer.Transcript);
      Master := TLS12ExtendedMasterSecret(HashKind, Premaster, SessionHash);
    end
    else
      Master := TLS12MasterSecret(HashKind, Premaster, ClientRandom,
        Hello.ServerRandom);
    KB := TLS12KeyBlock(HashKind, Master, Hello.ServerRandom, ClientRandom,
      0, TLSAEADKeyLength(Mode), TLSAEADFixedIvLength(Mode));

    { Client Finished (encrypted record under current keys). }
    ClientVD := TLS12VerifyData(HashKind, Master, TLSFinishedLabelClient,
      Buffer.Transcript);
    FinishedBody := EncodeTLS12FinishedBody(ClientVD);
    Buffer.AppendTranscript(htFinished, FinishedBody);
    FinMsg := BuildTLS12Finished(ClientVD);
    WriteTLS12ChangeCipherSpec(ATransport);
    Frag := TLSAEADEncryptFragment(Mode, KB.ClientWriteKey, KB.ClientWriteIV,
      QWord(0), ctHandshake, TLS12Version, FinMsg);
    WriteTLSRecord(ATransport, ctHandshake, Frag);

    { CCS and server Finished. }
    ReadTLS12ChangeCipherSpec(ATransport);
    Rec := ReadTLSRecord(ATransport);
    if Rec.ContentType <> ctHandshake then
      raise ETLS12Error.CreateFmt(
        'expected handshake record after CCS, got type %d',
        [Ord(Rec.ContentType)]);
    if not TLSAEADDecryptFragment(Mode, KB.ServerWriteKey, KB.ServerWriteIV,
      QWord(0), Rec.ContentType, Rec.Version, Rec.Fragment, Plain) then
      raise ETLS12Error.Create('failed to decrypt server Finished');
    Fin := DecodeTLSHandshakeMessage(Plain);
    if Fin.MsgType <> htFinished then
      raise ETLS12Error.Create('server did not send Finished after CCS');
    ServerVD := ParseTLS12FinishedBody(Fin.Body);
    if not TLS12VerifyFinished(HashKind, Master, TLSFinishedLabelServer,
      Buffer.Transcript, ServerVD) then
      raise ETLS12Error.Create('server VerifyData mismatch');

    { HTTP request over the secure channel (seq=1 after Finished). }
    Req := StrBytes('GET / HTTP/1.0'#13#10'Host: localhost'#13#10#13#10);
    Frag := TLSAEADEncryptFragment(Mode, KB.ClientWriteKey, KB.ClientWriteIV,
      QWord(1), ctApplicationData, TLS12Version, Req);
    WriteTLSRecord(ATransport, ctApplicationData, Frag);

    { Reading the response until the server closes the connection. }
    ServerSeq := 1;
    while True do
    begin
      try
        Rec := ReadTLSRecord(ATransport);
      except
        on E: ETLS12Error do
          Break;   { connection close/timeout }
      end;
      if Rec.ContentType = ctAlert then
        Break;
      if Rec.ContentType = ctApplicationData then
      begin
        if not TLSAEADDecryptFragment(Mode, KB.ServerWriteKey,
          KB.ServerWriteIV, ServerSeq, Rec.ContentType, Rec.Version,
          Rec.Fragment, Plain) then
          raise ETLS12Error.Create('failed to decrypt server data');
        AResponse := AResponse + BytesToStr(Plain);
        Inc(ServerSeq);
      end;
    end;
  finally
    Chain.Free;
    Buffer.Free;
  end;
end;

{ General scenario: generate a throwaway PKI, start openssl s_server, run the
  handshake and check the HTTP response. Skipped only when openssl itself is
  missing; every other failure raises, so a broken setup never passes silently
  and never hangs (the server start and the connect are bounded and retried,
  see e2e_support.StartServerAndConnect). }
procedure RunE2E(AKind: TE2EKeyKind; const ACipher: string;
  ACipherSuite: TTLSCipherSuite);
var
  Pki: TE2EPki;
  P: TProcess;
  Port: Word;
  Sock: TInetSocket;
  Transport: ITLSTransport;
  Response: AnsiString;
  Reasons: string;
begin
  if not OpenSSLAvailable then
    Exit;   { openssl unavailable — test skipped }

  Pki := TE2EPki.Create(AKind, 'localhost', 'localhost');
  try
    Sock := StartServerAndConnect(Pki.CertPath, Pki.KeyPath,
      ['-tls1_2', '-cipher', ACipher, '-www'], P, Port, Reasons);
    if (Sock = nil) and (P = nil) then
      Exit;   { openssl disappeared between the check and the start }
    try
      if Sock = nil then
        raise ETLS12Error.CreateFmt(
          'openssl s_server did not accept a connection on port %d: %s',
          [Port, Reasons]);

      Transport := nil;
      try
        Transport := TTLSStreamTransport.Create(Sock);
        RunTLS12Session(Transport, ACipherSuite, Pki.CaCertPath, Response);
        Transport := nil;
      finally
        Transport := nil;
        Sock.Free;
      end;

      if Length(Response) = 0 then
        raise ETLS12Error.Create('server response not received');
      if Pos('HTTP/1.0 200', Response) = 0 then
        raise ETLS12Error.Create('no HTTP 200 from s_server: ' +
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

procedure TTLSE2ETests.TestHandshakeAndHttpWithOpenSSLServerRSA;
begin
  RunE2E(ekRSA, 'ECDHE-RSA-AES128-GCM-SHA256',
    TLSCipherECDHE_RSA_AES128GCM_SHA256);
end;

procedure TTLSE2ETests.TestHandshakeAndHttpWithOpenSSLServerEC;
begin
  RunE2E(ekEC, 'ECDHE-ECDSA-AES128-GCM-SHA256',
    TLSCipherECDHE_ECDSA_AES128GCM_SHA256);
end;

initialization
  RegisterTest(TTLSE2ETests);

end.
