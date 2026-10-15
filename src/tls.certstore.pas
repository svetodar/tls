{ SPDX-License-Identifier: Apache-2.0 }
unit tls.certstore;

{' Certificate store and chain verification (RFC 5280 §6).
  Layer 3 (verification), depends on tls.x509 (TX509Cert), tls.asn1 (DER),
  tls.bn (TBN), tls.ec (ECDSA), tls.rsa (RSA), tls.sha2 (SHA-256/384).

  TCertStore — collection of certificates with lookup by Subject name and
    SubjectKeyIdentifier.

  VerifyChain — chain building and verification:
    1. Checks leaf validity periods.
    2. Finds the issuer in the store (by AKI/SKI or by name).
    3. Verifies each certificate's signature with the issuer's public key.
    4. Checks BasicConstraints (CA:TRUE for issuers, pathLen).
    5. Checks validity periods of each certificate in the chain.

  WildcardMatch — matches hostname against pattern *.example.com
    (single asterisk at the start, replaces exactly one label).

  CertMatchesHost — checks certificate matches hostname
    (first SAN DNS, then CN). '}

{$mode objfpc}{$H+}

interface
uses
  Classes, SysUtils,
  tls.asn1,
  tls.bn,
  tls.ec,
  tls.rsa,
  tls.sha2,
  tls.x509;

type
  {' Chain verification result. '}
  TVerifyResult = record
    OK: Boolean;
    Reason: string;       { "" if OK, otherwise the failure reason "}
    ChainLen: LongInt;    {' length of the built chain (0 = not built) '}
  end;

  {' Certificate store. '}
  TCertStore = class
  private
    FCerts: array of TX509Cert;
    function GetCount: LongInt;
  public
    constructor Create;
    destructor Destroy; override;
    property Count: LongInt read GetCount;
    {' Add a certificate (the store keeps a reference, does not copy). '}
    procedure Add(const Cert: TX509Cert);
    {' Get certificate by index. '}
    function At(i: LongInt): TX509Cert;
    {' Find a certificate whose Subject matches the name AName. '}
    function FindBySubject(const AName: string): TX509Cert;
    {' Find a certificate by SubjectKeyIdentifier (bytes). '}
    function FindBySKI(const ASKI: TBytes): TX509Cert;
    {' Remove all certificates (frees memory). '}
    procedure Clear;
  end;

{' Verify the signature of certificate AChild with the public key of AParent.
  Supports RSA (PKCS#1 v1.5) and ECDSA. '}
function VerifySignature(const AParent, AChild: TX509Cert): Boolean;

{' Verify the signature of arbitrary data AMessage with the public key
  of certificate APubKeyCert. AAlgOID — signature algorithm OID
  (SignatureAlgorithm from X.509/TLS), specifying the hash for RSA
  (SHA-256/384/512); for ECDSA the hash is chosen by the key's curve.
  AMessage — original (unhashed) data, ASignature — signature bytes.
  Returns True on successful verification. '}
function VerifyDataSignature(const APubKeyCert: TX509Cert;
  const AMessage, ASignature: TBytes; const AAlgOID: string): Boolean;

{' Check certificate validity period (notBefore <= now <= notAfter).
  ANow = 0 → use current time. '}
function CheckValidity(const Cert: TX509Cert; const ANow: TDateTime): Boolean;

{ " Wildcard matching of hostname against a name from SAN/CN (RFC 6125 §6.4.1):
    - '*' is allowed only at the start, replaces exactly one label.
    - Case-insensitive.
    - Exact match (no '*') — case-insensitive. "}
function WildcardMatch(const Pattern, Host: string): Boolean;

{' Check that the certificate is suitable for hostname:
  first SAN (DNS names), then CN (if SAN is absent). '}
function CertMatchesHost(const Cert: TX509Cert; const Host: string): Boolean;

{' Build and verify the chain: ALeaf → (intermediates) → CA.
  The store AStore contains the CA and, optionally, intermediate certificates.
  AHops — maximum chain length (default 8).
  ANow — current time (0 = Now).
  Returns TVerifyResult. '}
function VerifyChain(const AStore: TCertStore; const ALeaf: TX509Cert;
  AHops: LongInt = 8; ANow: TDateTime = 0): TVerifyResult;
{' Load a single PEM certificate from a file.
  The file must contain a -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE----- block.
  Returns TX509Cert (owns memory; caller must Free).
  Errors — EASN1Error. '}
function LoadPEM(const APath: string): TX509Cert;

{' Load a bundle of PEM certificates (e.g. /etc/ssl/certs/ca-certificates.crt)
  into a new TCertStore. Returns TCertStore (owns memory; caller must Free).
  Errors — EASN1Error. '}
function LoadBundle(const APath: string): TCertStore;

implementation


{--- TCertStore ---}

constructor TCertStore.Create;
begin
  inherited Create;
  FCerts := nil;
end;

destructor TCertStore.Destroy;
begin
  {' The store does not own the certificates (keeps references);
    freeing is the owner's responsibility (see Add). '}
  FCerts := nil;
  inherited Destroy;
end;

function TCertStore.GetCount: LongInt;
begin
  Result := Length(FCerts);
end;

procedure TCertStore.Add(const Cert: TX509Cert);
begin
  SetLength(FCerts, Length(FCerts) + 1);
  FCerts[Length(FCerts) - 1] := Cert;
end;

function TCertStore.At(i: LongInt): TX509Cert;
begin
  if (i < 0) or (i >= Length(FCerts)) then
    raise EASN1Error.CreateFmt('TCertStore.At: index %d out of range', [i]);
  Result := FCerts[i];
end;

function TCertStore.FindBySubject(const AName: string): TX509Cert;
var
  i: LongInt;
begin
  Result := nil;
  for i := 0 to Length(FCerts) - 1 do
    if FCerts[i].Subject.ToNameString = AName then
    begin
      Result := FCerts[i];
      Exit;
    end;
end;

function TCertStore.FindBySKI(const ASKI: TBytes): TX509Cert;
var
  i, j: LongInt;
  ski: TBytes;
  same: Boolean;
begin
  Result := nil;
  if Length(ASKI) = 0 then Exit;
  for i := 0 to Length(FCerts) - 1 do
  begin
    ski := FCerts[i].GetSubjectKeyIdentifier;
    if Length(ski) = Length(ASKI) then
    begin
      same := True;
      for j := 0 to Length(ASKI) - 1 do
        if ski[j] <> ASKI[j] then
        begin
          same := False;
          Break;
        end;
      if same then
      begin
        Result := FCerts[i];
        Exit;
      end;
    end;
  end;
end;
procedure TCertStore.Clear;
begin
  {Does not own certificates — just resets the list.}
  FCerts := nil;
end;

{--- Helper functions for VerifySignature ---}

{Hash OID from the signature algorithm OID.}
function HashOIDFromSigAlg(const SigAlgOID: string): string;
begin
  case SigAlgOID of
    '1.2.840.113549.1.1.4':  Result := '1.3.14.3.2.26';  { MD5 }
    '1.2.840.113549.1.1.5':  Result := '1.3.14.3.2.29';  { SHA-1 }
    '1.2.840.113549.1.1.11': Result := '2.16.840.1.101.3.4.2.65537'; { SHA-256 }
    '1.2.840.113549.1.1.12': Result := '2.16.840.1.101.3.4.2.65538'; { SHA-384 }
    '1.2.840.113549.1.1.13': Result := '2.16.840.1.101.3.4.2.65539'; { SHA-512 }
  else
    Result := '2.16.840.1.101.3.4.2.65537';  { default SHA-256 }
  end;
end;

{Compute the TBS hash by the signature algorithm OID.
  Returns nil for unsupported hashes (MD5, SHA-1).}
function HashBytes(const Data: TBytes; const SigAlgOID: string): TBytes;
begin
  case SigAlgOID of
    '1.2.840.113549.1.1.4':  Result := nil;  {MD5 — not supported}
    '1.2.840.113549.1.1.5':  Result := nil;  {SHA-1 — not supported}
    '1.2.840.113549.1.1.12': Result := SHA384(Data);
    '1.2.840.113549.1.1.13': Result := SHA512(Data);
  else
    Result := SHA256(Data);
  end;
end;

{Verify RSA signature: S^E mod N → PKCS1v15Decode → compare with hash.}
function VerifyRSASignature(const N, E: TBN; const Signature: TBytes;
  const Hash: TBytes; const HashOID: string): Boolean;
var
  sigBN, aem: TBN;
  decoded: TBytes;
  modLen: LongInt;
  i: LongInt;
begin
  Result := False;
  if (N = nil) or (E = nil) then Exit;
  if Length(Signature) = 0 then Exit;
  if Length(Hash) = 0 then Exit;

  modLen := (N.BitLength + 7) div 8;

  sigBN := TBN.CreateFromBytes(Signature, True);
  try
    { aem = S^E mod N }
    aem := sigBN.ModPow(E, N);
    try
      decoded := PKCS1v15Decode(aem, HashOID, modLen, False);
      if (decoded = nil) or (Length(decoded) <> Length(Hash)) then
        Exit;
      Result := True;
      for i := 0 to Length(Hash) - 1 do
        if decoded[i] <> Hash[i] then
        begin
          Result := False;
          Break;
        end;
    finally
      aem.Free;
    end;
  finally
    sigBN.Free;
  end;
end;

{Verify ECDSA signature: DER SEQUENCE (r, s) → ECDSAVerify.
  AMessage — raw TBS bytes (ECDSAVerify hashes them itself by the curve).}
function VerifyECDSASignature(const Curve: TECCurve; const Point: TECPoint;
  const Signature: TBytes; const AMessage: TBytes): Boolean;
var
  tree: TASN1Node;
  rBN, sBN: TBN;
  ecSig: TECDsaSig;
begin
  Result := False;
  if (Curve = nil) or (Point = nil) or Point.Infinity then Exit;
  if Length(Signature) = 0 then Exit;
  if Length(AMessage) = 0 then Exit;
  try
    tree := ParseDER(Signature);
    try
      if (tree.TagClass <> tcUniversal) or (tree.TagNumber <> Ord(atSequence)) then
        Exit;
      if tree.ChildCount < 2 then Exit;
      rBN := ReadInteger(tree.ChildAt(0));
      sBN := ReadInteger(tree.ChildAt(1));
      ecSig := TECDsaSig.Create;
      try
        ecSig.R := rBN;
        ecSig.S := sBN;
        Result := ECDSAVerify(Curve, Point, AMessage, ecSig);
      finally
        ecSig.Free;
      end;
    finally
      tree.Free;
    end;
  except
    Result := False;
  end;
end;

{--- VerifySignature ---}

function VerifySignature(const AParent, AChild: TX509Cert): Boolean;
var
  hash: TBytes;
  hashOID: string;
begin
  Result := False;
  if (AParent = nil) or (AChild = nil) then Exit;
  if Length(AChild.Signature) = 0 then Exit;
  if Length(AChild.TBSCertificate) = 0 then Exit;

  hash := HashBytes(AChild.TBSCertificate, AChild.SignatureAlgorithm);
  if hash = nil then Exit;  {unsupported hash (MD5, SHA-1)}

  hashOID := HashOIDFromSigAlg(AChild.SignatureAlgorithm);

  case AParent.SPKI.KeyType of
    pkRSA:
      Result := VerifyRSASignature(AParent.SPKI.RSAModulus,
        AParent.SPKI.RSAExponent, AChild.Signature, hash, hashOID);

    pkEC:
      Result := VerifyECDSASignature(AParent.SPKI.Curve,
        AParent.SPKI.Point, AChild.Signature, AChild.TBSCertificate);
  end;
end;

{--- VerifyDataSignature ---}

function VerifyDataSignature(const APubKeyCert: TX509Cert;
  const AMessage, ASignature: TBytes; const AAlgOID: string): Boolean;
var
  hash: TBytes;
  hashOID: string;
begin
  Result := False;
  if APubKeyCert = nil then Exit;
  if Length(AMessage) = 0 then Exit;
  if Length(ASignature) = 0 then Exit;

  case APubKeyCert.SPKI.KeyType of
    pkRSA:
      begin
        hash := HashBytes(AMessage, AAlgOID);
        if hash = nil then Exit;  {unsupported hash (MD5, SHA-1)}
        hashOID := HashOIDFromSigAlg(AAlgOID);
        Result := VerifyRSASignature(APubKeyCert.SPKI.RSAModulus,
          APubKeyCert.SPKI.RSAExponent, ASignature, hash, hashOID);
      end;

    pkEC:
      {ECDSAVerify hashes the message itself (by the key's curve).}
      Result := VerifyECDSASignature(APubKeyCert.SPKI.Curve,
        APubKeyCert.SPKI.Point, ASignature, AMessage);
  end;
end;

{--- CheckValidity ---}

function CheckValidity(const Cert: TX509Cert; const ANow: TDateTime): Boolean;
var
  t: TDateTime;
begin
  if ANow <= 0 then
    t := Now
  else
    t := ANow;
  Result := (Cert.NotBefore <= t) and (t <= Cert.NotAfter);
end;

{--- WildcardMatch ---}

function WildcardMatch(const Pattern, Host: string): Boolean;
var
  p, h: string;
  right: string;
  hostLabel: string;
begin
  p := LowerCase(Trim(Pattern));
  h := LowerCase(Trim(Host));

  {Exact match (no '*').}
  if Pos('*', p) = 0 then
  begin
    Result := (p = h);
    Exit;
  end;

  {'*' must be at the start and occupy the entire first label (RFC 6125 §6.4.1).}
  if (Length(p) < 2) or (p[1] <> '*') then
  begin
    Result := False;
    Exit;
  end;
  if p[2] <> '.' then
  begin
    Result := False;
    Exit;
  end;

  {right — the part after '*.'}
  right := Copy(p, 3, Length(p) - 2);
  if right = '' then
  begin
    Result := False;
    Exit;
  end;

  {Host must end with '.' + right (the asterisk replaces exactly one label).}
  if Length(h) <= Length(right) + 1 then
  begin
    Result := False;
    Exit;
  end;
  if Copy(h, Length(h) - Length(right), Length(right) + 1) <> '.' + right then
  begin
    Result := False;
    Exit;
  end;

  {hostLabel — the part before '.' + right; must be a single label (no dots).}
  hostLabel := Copy(h, 1, Length(h) - Length(right) - 1);
  if (hostLabel = '') or (Pos('.', hostLabel) > 0) then
  begin
    Result := False;
    Exit;
  end;

  Result := True;
end;

{--- CertMatchesHost ---}

function CertMatchesHost(const Cert: TX509Cert; const Host: string): Boolean;
var
  san: TSANList;
  i: LongInt;
  cn: string;
  hasSAN: Boolean;
begin
  Result := False;
  if (Cert = nil) or (Host = '') then Exit;

  san := Cert.GetSubjectAltNames;
  try
    hasSAN := False;
    for i := 0 to san.Count - 1 do
    begin
      case san.At(i).Kind of
        sanDNS:
          begin
            hasSAN := True;
            if WildcardMatch(san.At(i).Value, Host) then
            begin
              Result := True;
              Exit;
            end;
          end;
        sanIP:
          begin
            hasSAN := True;
            {RFC 6125: an IP address is matched byte-for-byte against an
              iPAddress subjectAltName, never against a DNS wildcard.}
            if san.At(i).Value = Host then
            begin
              Result := True;
              Exit;
            end;
          end;
      end;
    end;
    {If SAN is present — do not check CN (RFC 6125 §6.4.3).}
    if hasSAN then Exit;
  finally
    san.Free;
  end;

  {No SAN — check CN.}
  cn := Cert.Subject.GetByOID('2.5.4.3');
  if cn <> '' then
    Result := WildcardMatch(cn, Host);
end;

{--- VerifyChain ---}

function VerifyChain(const AStore: TCertStore; const ALeaf: TX509Cert;
  AHops: LongInt; ANow: TDateTime): TVerifyResult;
var
  current, issuer: TX509Cert;
  bc: TBasicConstraints;
  hops: LongInt;
  issuerName: string;
  aki: TBytes;
begin
  Result.OK := False;
  Result.Reason := '';
  Result.ChainLen := 0;

  if ALeaf = nil then
  begin
    Result.Reason := 'leaf is nil';
    Exit;
  end;

  if AHops <= 0 then AHops := 8;

  {1. Check leaf validity periods.}
  if not CheckValidity(ALeaf, ANow) then
  begin
    Result.Reason := 'leaf certificate expired or not yet valid';
    Exit;
  end;

  current := ALeaf;
  hops := 0;

  {2. Build the chain: current → issuer → ... → self-signed CA.}
  while True do
  begin
    {2a. Self-signed: issuer == subject → this is the root CA.}
    if current.Issuer.ToNameString = current.Subject.ToNameString then
    begin
      bc := current.GetBasicConstraints;
      if not bc.IsCA then
      begin
        Result.Reason := 'root certificate is not a CA';
        Exit;
      end;
      if not CheckValidity(current, ANow) then
      begin
        Result.Reason := 'root certificate expired or not yet valid';
        Exit;
      end;
      Result.OK := True;
      Result.ChainLen := hops + 1;
      Exit;
    end;

    { 2b. Look up issuer in the store. }
    issuerName := current.Issuer.ToNameString;

    issuer := nil;
    { First by AKI → SKI, then by name. }
    aki := current.GetAuthorityKeyIdentifier;
    if Length(aki) > 0 then
      issuer := AStore.FindBySKI(aki);
    if issuer = nil then
      issuer := AStore.FindBySubject(issuerName);

    if issuer = nil then
    begin
      Result.Reason := 'issuer not found in store: ' + issuerName;
      Exit;
    end;

    { 2c. Verify current's signature with issuer's signature. }
    if not VerifySignature(issuer, current) then
    begin
      Result.Reason := 'signature verification failed for: ' +
        current.Subject.ToNameString;
      Exit;
    end;

    { 2d. Verify that issuer is a CA. }
    bc := issuer.GetBasicConstraints;
    if not bc.IsCA then
    begin
      Result.Reason := 'issuer is not a CA: ' + issuer.Subject.ToNameString;
      Exit;
    end;

    { 2e. pathLenConstraint (X.509 BasicConstraints): the maximum number of
      ADDITIONAL certificates that may appear in the certification path
      below this CA, not counting the certificate being verified (the leaf).
      The issuer sits at position hops + 1 from the leaf, so below it there
      are hops + 1 certificates, of which hops are additional (CAs).
      Require hops <= PathLen. (The old code counted the leaf too:
      hops + 1 > PathLen — off-by-one, broke real chains like
      example.com: issuer CA has pathlen:0 and issues the leaf directly.) }
    if (bc.PathLen >= 0) and (hops > bc.PathLen) then
    begin
      Result.Reason := 'path length constraint exceeded';
      Exit;
    end;

    { 2f. Check issuer validity periods. }
    if not CheckValidity(issuer, ANow) then
    begin
      Result.Reason := 'issuer certificate expired or not yet valid: ' +
        issuer.Subject.ToNameString;
      Exit;
    end;

    Inc(hops);
    if hops >= AHops then
    begin
      Result.Reason := 'chain too long (max ' + IntToStr(AHops) + ' hops)';
      Exit;
    end;

    current := issuer;
  end;
end;
{--- Base64 ---}

const
  B64Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function B64Index(c: Char): LongInt;
begin
  Result := Pos(c, B64Alphabet) - 1;
end;

function Base64Decode(const S: string): TBytes;
var
  i, outPos, qCount, n: LongInt;
  quad: array[0..3] of LongInt;
begin
  { Count the number of significant characters (excluding '=' and whitespace). }
  n := 0;
  for i := 1 to Length(S) do
    if (S[i] <> '=') and (S[i] <> #10) and (S[i] <> #13)
      and (S[i] <> ' ') and (S[i] <> #9) then
      Inc(n);

  if n < 4 then
    raise EASN1Error.Create('Base64Decode: input too short');

  SetLength(Result, (n div 4) * 3);
  case n mod 4 of
    2: SetLength(Result, Length(Result) + 1);
    3: SetLength(Result, Length(Result) + 2);
  end;

  outPos := 0;
  qCount := 0;
  for i := 1 to Length(S) do
  begin
    if (S[i] = '=') or (S[i] = #10) or (S[i] = #13)
      or (S[i] = ' ') or (S[i] = #9) then
      Continue;
    quad[qCount] := B64Index(S[i]);
    if quad[qCount] < 0 then
      raise EASN1Error.CreateFmt('Base64Decode: invalid character #%d', [Ord(S[i])]);
    Inc(qCount);
    if qCount = 4 then
    begin
      Result[outPos]     := Byte((quad[0] shl 2) or (quad[1] shr 4));
      Result[outPos + 1] := Byte(((quad[1] and $0F) shl 4) or (quad[2] shr 2));
      Result[outPos + 2] := Byte(((quad[2] and $03) shl 6) or quad[3]);
      Inc(outPos, 3);
      qCount := 0;
    end;
  end;

  { Handle the tail (2 or 3 remaining characters). }
  if qCount = 2 then
  begin
    Result[outPos] := Byte((quad[0] shl 2) or (quad[1] shr 4));
    Inc(outPos);
  end
  else if qCount = 3 then
  begin
    Result[outPos]     := Byte((quad[0] shl 2) or (quad[1] shr 4));
    Result[outPos + 1] := Byte(((quad[1] and $0F) shl 4) or (quad[2] shr 2));
    Inc(outPos, 2);
  end;

  if outPos < Length(Result) then
    SetLength(Result, outPos);
end;

{--- LoadPEM ---}

function LoadPEM(const APath: string): TX509Cert;
const
  PEM_HDR = '-----BEGIN CERTIFICATE-----';
  PEM_FTR = '-----END CERTIFICATE-----';
var
  sl: TStringList;
  content: string;
  start, finish: LongInt;
  b64: string;
  der: TBytes;
begin
  sl := TStringList.Create;
  try
    sl.LoadFromFile(APath);
    content := sl.Text;
  finally
    sl.Free;
  end;

  start := Pos(PEM_HDR, content);
  if start = 0 then
    raise EASN1Error.CreateFmt('LoadPEM: BEGIN CERTIFICATE not found in %s', [APath]);
  start := start + Length(PEM_HDR);

  finish := Pos(PEM_FTR, content);
  if (finish = 0) or (finish < start) then
    raise EASN1Error.CreateFmt('LoadPEM: END CERTIFICATE not found in %s', [APath]);

  b64 := Copy(content, start, finish - start);
  der := Base64Decode(b64);
  Result := ParseCertificate(der);
end;

{--- LoadBundle ---}

function LoadBundle(const APath: string): TCertStore;
const
  PEM_HDR = '-----BEGIN CERTIFICATE-----';
  PEM_FTR = '-----END CERTIFICATE-----';
var
  sl: TStringList;
  content: string;
  curPos, start, finish: LongInt;
  b64: string;
  der: TBytes;
  cert: TX509Cert;
begin
  Result := TCertStore.Create;
  sl := TStringList.Create;
  try
    sl.LoadFromFile(APath);
    content := sl.Text;
  finally
    sl.Free;
  end;

  curPos := 1;
  while curPos <= Length(content) do
  begin
    start := Pos(PEM_HDR, Copy(content, curPos, Length(content) - curPos + 1));
    if start = 0 then Break;
    start := start + curPos - 1 + Length(PEM_HDR);

    finish := Pos(PEM_FTR, Copy(content, start, Length(content) - start + 1));
    if finish = 0 then Break;
    finish := finish + start - 1;

    b64 := Copy(content, start, finish - start);
    der := Base64Decode(b64);
    cert := ParseCertificate(der);
    Result.Add(cert);

    curPos := finish + Length(PEM_FTR);
  end;
end;


end.
