{ SPDX-License-Identifier: Apache-2.0 }
unit tls.certstore;

{' Certificate store and chain verification (RFC 5280 §6).
  Layer 3 (verification), depends on tls.x509 (TX509Cert), tls.asn1 (DER),
  tls.bn (TBN), tls.ec (ECDSA), tls.rsa (RSA), tls.sha2 (SHA-256/384).

  TCertStore — collection of certificates with lookup by Subject name and
    SubjectKeyIdentifier. Both lookups use a key index that is built as
    certificates are added (the keys are stored per certificate and sorted
    once), so a lookup is a binary search instead of a scan over the whole
    store, which matters for a bundle of ~120 roots and for every hop of
    VerifyChain. Subject names are compared after CanonicalSubjectName
    (RFC 5280 §7.1: lower-case, blanks collapsed).

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
  {' Typed error raised when the Windows system certificate store cannot be
    opened or enumerated (LoadWindowsSystemStore). '}
  TWinCertStoreError = class(Exception);

  {' Order of certificate indexes into a TCertStore certificate list, sorted by
    a lookup key (insertion order among equal keys). Used by the store's
    Subject and SubjectKeyIdentifier indexes. '}
  TCertIndexOrder = array of LongInt;

  {' Certificate store. '}
  TCertStore = class
  private
    FCerts: array of TX509Cert;
    {' Certificates the store created itself (parsed from DER) and must
      free in Destroy. '}
    FOwnedCerts: array of TX509Cert;
    {' Lookup index, kept in step with FCerts by Add and dropped by Clear.
      FSubjectKeys[i] is the canonical subject name of FCerts[i] (see
      CanonicalSubjectName), FSKIKeys[i] its SubjectKeyIdentifier as
      lower-case hex, '' when the certificate carries none. FSubjectOrder and
      FSKIOrder list certificate indexes sorted by the matching key with the
      insertion order kept among equal keys, so a lookup is a binary search
      and still yields the certificate added first.

      The keys are computed once, in Add, while the store is being built:
      lookups never write, so a store that is shared between threads (the
      embedded roots, for example) can be searched concurrently. '}
    FSubjectKeys: array of string;
    FSKIKeys: array of string;
    FSubjectOrder: TCertIndexOrder;
    FSKIOrder: TCertIndexOrder;
    function GetCount: LongInt;
    {' Record the lookup keys of ACert, now at index AIndex of FCerts, and
      insert that index into the sorted order arrays. '}
    procedure AddToIndex(const ACert: TX509Cert; AIndex: LongInt);
    {' Drop the whole lookup index (called by Clear). '}
    procedure ResetIndex;
  public
    constructor Create;
    destructor Destroy; override;
    property Count: LongInt read GetCount;
    {' Add a certificate (the store keeps a reference, does not copy). '}
    procedure Add(const Cert: TX509Cert);
    {' Add a certificate the store now owns: it is appended to the store
      and recorded in the owned list, so Destroy will free it. '}
    procedure AddOwnedCert(const Cert: TX509Cert);
    {' Get certificate by index. '}
    function At(i: LongInt): TX509Cert;
    {' Find a certificate whose Subject matches the name AName, compared after
      CanonicalSubjectName. Returns the first matching certificate in
      insertion order, nil when nothing matches. '}
    function FindBySubject(const AName: string): TX509Cert;
    {' Find a certificate by SubjectKeyIdentifier (bytes, compared by value).
      Returns the first matching certificate in insertion order, nil for an
      empty ASKI or when nothing matches. '}
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

{' Canonical form of a distinguished name, the basis for comparing the Subject
  of a stored certificate with the name asked for by FindBySubject (and the
  Issuer of a certificate with the Subject of its candidate issuer while a
  chain is built): ASCII letters lower-cased and every run of blanks (space,
  tab, CR, LF) collapsed to one space, with the ends trimmed — RFC 5280 §7.1
  compares DirectoryString values case- and blank-insensitively. '}
function CanonicalSubjectName(const AName: string): string;

{' Build and verify the chain: ALeaf → (intermediates) → CA.
  The store AStore contains the CA and, optionally, intermediate certificates.
  AHops — maximum chain length (default 8).
  ANow — current time (0 = Now).
  Returns TVerifyResult. '}
function VerifyChain(const AStore: TCertStore; const ALeaf: TX509Cert;
  AHops: LongInt = 8; ANow: TDateTime = 0): TVerifyResult;
{' Parse the first -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----
  block of in-memory PEM text and return the certificate (owns memory;
  the caller must Free). No file or resource access happens here.
  Errors — EASN1Error (no block, bad base64, malformed DER). '}
function LoadPEMFromMemory(const APEM: RawByteString): TX509Cert;
{' Load a single PEM certificate from a file: read the file into memory and
  hand the text to LoadPEMFromMemory.
  The file must contain a -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE----- block.
  Returns TX509Cert (owns memory; caller must Free).
  Errors — EASN1Error. '}
function LoadPEM(const APath: string): TX509Cert;
{' Load a bundle of PEM certificates from a stream into a new TCertStore:
  the stream is read to the end and every
  -----BEGIN CERTIFICATE----- ... -----END CERTIFICATE----- block is parsed.
  The store owns the parsed certificates. No file or resource access happens
  here.
  Returns TCertStore (owns memory; caller must Free).
  Errors — EASN1Error (nil stream, no block, unterminated block, bad base64,
  malformed DER). '}
function LoadBundleFromStream(AStream: TStream): TCertStore;


{' Load a bundle of PEM certificates (e.g. /etc/ssl/certs/ca-certificates.crt)
  from a file into a new TCertStore: the file is opened as a stream and
  handed to LoadBundleFromStream.
  Returns TCertStore (owns memory; caller must Free).
  Errors — EASN1Error (read error, no block, unterminated block, bad base64,
  malformed DER). '}
function LoadBundle(const APath: string): TCertStore;
{$ifdef windows}
{' Load the Windows system certificate store (the Root and CA stores of
  the current user and the local machine) into a new TCertStore.
  Returns TCertStore (owns memory; caller must Free).
  Errors — TWinCertStoreError (a store cannot be opened), EASN1Error
  (a certificate in the store is malformed). '}
function LoadWindowsSystemStore: TCertStore;
{$endif windows}

implementation

{--- Lookup index helpers ---}

function CanonicalSubjectName(const AName: string): string;
var
  i, Len: LongInt;
  PendingBlank: Boolean;
begin
  { Built in place: the canonical form is never longer than the input. }
  SetLength(Result, Length(AName));
  Len := 0;
  PendingBlank := False;
  for i := 1 to Length(AName) do
  begin
    if AName[i] in [' ', #9, #10, #13] then
    begin
      { A blank survives only if something preceded it, so leading and
        trailing blanks drop out. }
      if Len > 0 then
        PendingBlank := True;
      Continue;
    end;
    if PendingBlank then
    begin
      Inc(Len);
      Result[Len] := ' ';
      PendingBlank := False;
    end;
    Inc(Len);
    Result[Len] := LowerCase(AName[i]);
  end;
  SetLength(Result, Len);
end;

{' Lower-case hex of the bytes: the SubjectKeyIdentifier index key. Two keys
  are equal exactly when the identifiers are equal byte for byte. '}
function SKIKeyOf(const ASKI: TBytes): string;
const
  HexDigit: array[0..15] of Char = '0123456789abcdef';
var
  i: LongInt;
begin
  SetLength(Result, Length(ASKI) * 2);
  for i := 0 to Length(ASKI) - 1 do
  begin
    Result[i * 2 + 1] := HexDigit[ASKI[i] shr 4];
    Result[i * 2 + 2] := HexDigit[ASKI[i] and $0F];
  end;
end;

{ First position in AOrder whose key is not less than AKey. }
function OrderLowerBound(const AOrder: TCertIndexOrder;
  const AKeys: array of string; const AKey: string): LongInt;
var
  Lo, Hi, Mid: LongInt;
begin
  Lo := 0;
  Hi := Length(AOrder);
  while Lo < Hi do
  begin
    Mid := (Lo + Hi) div 2;
    if AKeys[AOrder[Mid]] < AKey then
      Lo := Mid + 1
    else
      Hi := Mid;
  end;
  Result := Lo;
end;

{ First position in AOrder whose key is greater than AKey. }
function OrderUpperBound(const AOrder: TCertIndexOrder;
  const AKeys: array of string; const AKey: string): LongInt;
var
  Lo, Hi, Mid: LongInt;
begin
  Lo := 0;
  Hi := Length(AOrder);
  while Lo < Hi do
  begin
    Mid := (Lo + Hi) div 2;
    if AKeys[AOrder[Mid]] <= AKey then
      Lo := Mid + 1
    else
      Hi := Mid;
  end;
  Result := Lo;
end;

{ Insert the certificate index AIndex into AOrder, keeping it sorted by key
  and equal keys in insertion order (see OrderUpperBound). }
procedure InsertOrder(var AOrder: TCertIndexOrder;
  const AKeys: array of string; AIndex: LongInt);
var
  Pos, Tail: LongInt;
begin
  Pos := OrderUpperBound(AOrder, AKeys, AKeys[AIndex]);
  Tail := Length(AOrder) - Pos;
  SetLength(AOrder, Length(AOrder) + 1);
  if Tail > 0 then
    Move(AOrder[Pos], AOrder[Pos + 1], Tail * SizeOf(LongInt));
  AOrder[Pos] := AIndex;
end;

{--- TCertStore ---}

constructor TCertStore.Create;
begin
  inherited Create;
  FCerts := nil;
  FOwnedCerts := nil;
  ResetIndex;
end;

destructor TCertStore.Destroy;
var
  i: LongInt;
begin
  {' Free the certificates the store created itself (see AddOwnedCert);
    the rest are only referenced — freeing them is the owner's
    responsibility (see Add). '}
  for i := 0 to Length(FOwnedCerts) - 1 do
    FOwnedCerts[i].Free;
  FOwnedCerts := nil;
  FCerts := nil;
  ResetIndex;
  inherited Destroy;
end;

function TCertStore.GetCount: LongInt;
begin
  Result := Length(FCerts);
end;

procedure TCertStore.ResetIndex;
begin
  FSubjectKeys := nil;
  FSKIKeys := nil;
  FSubjectOrder := nil;
  FSKIOrder := nil;
end;

procedure TCertStore.AddToIndex(const ACert: TX509Cert; AIndex: LongInt);
begin
  SetLength(FSubjectKeys, AIndex + 1);
  SetLength(FSKIKeys, AIndex + 1);
  FSubjectKeys[AIndex] := '';
  FSKIKeys[AIndex] := '';
  if ACert <> nil then
  begin
    FSubjectKeys[AIndex] := CanonicalSubjectName(ACert.Subject.ToNameString);
    FSKIKeys[AIndex] := SKIKeyOf(ACert.GetSubjectKeyIdentifier);
  end;
  InsertOrder(FSubjectOrder, FSubjectKeys, AIndex);
  InsertOrder(FSKIOrder, FSKIKeys, AIndex);
end;

procedure TCertStore.Add(const Cert: TX509Cert);
var
  Index: LongInt;
begin
  Index := Length(FCerts);
  SetLength(FCerts, Index + 1);
  FCerts[Index] := Cert;
  AddToIndex(Cert, Index);
end;

procedure TCertStore.AddOwnedCert(const Cert: TX509Cert);
begin
  Add(Cert);
  SetLength(FOwnedCerts, Length(FOwnedCerts) + 1);
  FOwnedCerts[Length(FOwnedCerts) - 1] := Cert;
end;

function TCertStore.At(i: LongInt): TX509Cert;
begin
  if (i < 0) or (i >= Length(FCerts)) then
    raise EASN1Error.CreateFmt('TCertStore.At: index %d out of range', [i]);
  Result := FCerts[i];
end;

function TCertStore.FindBySubject(const AName: string): TX509Cert;
var
  Key: string;
  Pos: LongInt;
begin
  Result := nil;
  if Length(FSubjectOrder) = 0 then Exit;
  Key := CanonicalSubjectName(AName);
  Pos := OrderLowerBound(FSubjectOrder, FSubjectKeys, Key);
  if (Pos < Length(FSubjectOrder)) and
     (FSubjectKeys[FSubjectOrder[Pos]] = Key) then
    Result := FCerts[FSubjectOrder[Pos]];
end;

function TCertStore.FindBySKI(const ASKI: TBytes): TX509Cert;
var
  Key: string;
  Pos: LongInt;
begin
  Result := nil;
  if Length(ASKI) = 0 then Exit;
  if Length(FSKIOrder) = 0 then Exit;
  Key := SKIKeyOf(ASKI);
  Pos := OrderLowerBound(FSKIOrder, FSKIKeys, Key);
  if (Pos < Length(FSKIOrder)) and (FSKIKeys[FSKIOrder[Pos]] = Key) then
    Result := FCerts[FSKIOrder[Pos]];
end;

procedure TCertStore.Clear;
var
  i: LongInt;
begin
  { Certificates the store owns are released here; the others are only
    referenced and stay with their owners (see Add). }
  for i := 0 to Length(FOwnedCerts) - 1 do
    FOwnedCerts[i].Free;
  FOwnedCerts := nil;
  FCerts := nil;
  ResetIndex;
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

{--- LoadPEMFromMemory ---}

function LoadPEMFromMemory(const APEM: RawByteString): TX509Cert;
const
  PEM_HDR = '-----BEGIN CERTIFICATE-----';
  PEM_FTR = '-----END CERTIFICATE-----';
var
  content: string;
  start, finish: LongInt;
  b64: string;
  der: TBytes;
begin
  {' The text is treated as raw bytes: PEM is ASCII, so no encoding
    assumption is needed and a ByteString round-trip stays lossless. '}
  content := APEM;

  start := Pos(PEM_HDR, content);
  if start = 0 then
    raise EASN1Error.Create('LoadPEMFromMemory: BEGIN CERTIFICATE not found');
  start := start + Length(PEM_HDR);

  finish := Pos(PEM_FTR, content);
  if (finish = 0) or (finish < start) then
    raise EASN1Error.Create('LoadPEMFromMemory: END CERTIFICATE not found');

  b64 := Copy(content, start, finish - start);
  der := Base64Decode(b64);
  Result := ParseCertificate(der);
end;

{--- LoadPEM ---}

function LoadPEM(const APath: string): TX509Cert;
var
  sl: TStringList;
  content: string;
begin
  {' Reading the file stays here; parsing lives in LoadPEMFromMemory so the
    same code path serves in-memory PEM (embedded roots). The read error is
    re-raised as EASN1Error to keep the documented contract. '}
  sl := TStringList.Create;
  try
    try
      sl.LoadFromFile(APath);
    except
      on E: Exception do
        raise EASN1Error.CreateFmt('LoadPEM: cannot read %s: %s',
          [APath, E.Message]);
    end;
    content := sl.Text;
  finally
    sl.Free;
  end;

  try
    Result := LoadPEMFromMemory(content);
  except
    on E: EASN1Error do
      raise EASN1Error.CreateFmt('LoadPEM: %s in %s', [E.Message, APath]);
  end;
end;

{--- LoadBundle ---}

function LoadBundle(const APath: string): TCertStore;
var
  fs: TFileStream;
begin
  {' Only the file access lives here; the bundle is parsed by
    LoadBundleFromStream, so the file, the stream and (later) in-memory
    bundles share one code path. The read error is re-raised as EASN1Error to
    keep the documented contract. '}
  try
    fs := TFileStream.Create(APath, fmOpenRead or fmShareDenyNone);
  except
    on E: Exception do
      raise EASN1Error.CreateFmt('LoadBundle: cannot read %s: %s',
        [APath, E.Message]);
  end;
  try
    try
      Result := LoadBundleFromStream(fs);
    except
      on E: EASN1Error do
        raise EASN1Error.CreateFmt('LoadBundle: %s in %s', [E.Message, APath]);
    end;
  finally
    fs.Free;
  end;
end;

{--- PEM bundle reading (shared by the stream and memory entry points) ---}

const
  PEMBundleHeader = '-----BEGIN CERTIFICATE-----';
  PEMBundleFooter = '-----END CERTIFICATE-----';

{' Position of ANeedle in AHaystack at or after AFrom (1-based) or 0 if it
  does not occur. A local replacement for PosEx, which is not available
  everywhere, and cheaper than Copy-ing the rest of the text per block. '}
function FindFrom(const AHaystack, ANeedle: string; AFrom: LongInt): LongInt;
var
  i, j, lastStart: LongInt;
  matched: Boolean;
begin
  Result := 0;
  if (ANeedle = '') or (AFrom < 1) then Exit;

  lastStart := Length(AHaystack) - Length(ANeedle) + 1;
  i := AFrom;
  while i <= lastStart do
  begin
    if AHaystack[i] = ANeedle[1] then
    begin
      matched := True;
      for j := 2 to Length(ANeedle) do
        if AHaystack[i + j - 1] <> ANeedle[j] then
        begin
          matched := False;
          Break;
        end;
      if matched then
        Exit(i);
    end;
    Inc(i);
  end;
end;

{' Parse every PEM certificate block of ABundle and add the certificates to
  AStore, which takes ownership of them. A bundle that yields no certificate
  is reported as malformed — an empty trust store is a mistake, not a result,
  and it must not stay silent. '}
procedure LoadPEMBundleInto(const ABundle: RawByteString; const AStore: TCertStore);
var
  content: string;
  curPos, start, finish, blocks: LongInt;
  der: TBytes;
begin
  {' The text is treated as raw bytes: PEM is ASCII, so no encoding assumption
    is needed and a ByteString round-trip stays lossless. '}
  content := ABundle;
  curPos := 1;
  blocks := 0;
  while True do
  begin
    start := FindFrom(content, PEMBundleHeader, curPos);
    if start = 0 then Break;
    start := start + Length(PEMBundleHeader);

    finish := FindFrom(content, PEMBundleFooter, start);
    if finish = 0 then
      raise EASN1Error.Create('PEM bundle: unterminated CERTIFICATE block');

    der := Base64Decode(Copy(content, start, finish - start));
    { The store parses this certificate itself, so it owns it and frees it in
      Destroy (or in Clear). ParseCertificate failing before this line leaves
      nothing behind to leak. }
    AStore.AddOwnedCert(ParseCertificate(der));
    Inc(blocks);
    curPos := finish + Length(PEMBundleFooter);
  end;

  if blocks = 0 then
    raise EASN1Error.Create('PEM bundle: no CERTIFICATE block found');
end;

{--- LoadBundleFromStream ---}

function LoadBundleFromStream(AStream: TStream): TCertStore;
var
  buf: array[0..4095] of Byte;
  text: RawByteString;
  n, used: LongInt;
begin
  if AStream = nil then
    raise EASN1Error.Create('LoadBundleFromStream: stream is nil');

  {' Read the whole stream as raw bytes, byte by byte in chunks: PEM has no
    binary framing, and the reader needs the text as a whole to notice an
    unterminated block at the end. '}
  text := '';
  repeat
    n := AStream.Read(buf, SizeOf(buf));
    if n > 0 then
    begin
      used := Length(text);
      SetLength(text, used + n);
      Move(buf, text[used + 1], n);
    end;
  until n <= 0;

  Result := TCertStore.Create;
  { Both the store and every certificate parsed into it belong to the caller
    only on success; on a malformed bundle they are released here, so a failed
    load leaks neither. }
  try
    LoadPEMBundleInto(text, Result);
  except
    Result.Free;
    raise;
  end;
end;

{$ifdef windows}
{--- Windows system store (crypt32.dll) ---}

type
  {' Opaque handle to a certificate store (HCERTSTORE). '}
  PCertStore = Pointer;
  {' Certificate context (CERT_CONTEXT). The encoded (DER) certificate is
    referenced by pbCertEncoded / cbCertEncoded. '}
  TCertContext = record
    dwCertEncodingType: LongWord;
    pbCertEncoded: Pointer;
    cbCertEncoded: LongWord;
    pCertContext: Pointer;
  end;
  PCertContext = ^TCertContext;

const
  CERT_SYSTEM_STORE_CURRENT_USER  = $00000001;
  CERT_SYSTEM_STORE_LOCAL_MACHINE = $00000002;
  {' Open both the current-user and the local-machine system stores. '}
  WinSystemStoreFlags = CERT_SYSTEM_STORE_CURRENT_USER or
    CERT_SYSTEM_STORE_LOCAL_MACHINE;

function CertOpenStore(lpszStoreName: PAnsiChar;
  lpszCertEncodingName: PAnsiChar; dwFlags: LongWord; dwReserved: LongWord;
  pvPara: Pointer): PCertStore;
  external 'crypt32.dll' name 'CertOpenStore';
{' Open a system store by name. Used as a fallback when CertOpenStore does
  not support the CERT_SYSTEM_STORE flags (some builds return
  ERROR_FILE_NOT_FOUND for them). '}
function CertOpenSystemStoreW(dwFlags: LongWord;
  pwszStoreName: PWideChar): PCertStore;
  external 'crypt32.dll' name 'CertOpenSystemStoreW';
function CertCloseStore(hCertStore: PCertStore; dwFlags: LongWord): Boolean;
  external 'crypt32.dll' name 'CertCloseStore';
function CertEnumCertificatesInStore(hCertStore: PCertStore;
  pPreviousContext: PCertContext): PCertContext;
  external 'crypt32.dll' name 'CertEnumCertificatesInStore';
{' Declared for completeness; the DER bytes are read directly from the
  CERT_CONTEXT (pbCertEncoded/cbCertEncoded) instead of calling this, so it
  is never invoked. '}
function CertGetCertificateContextData(pCertContext: PCertContext;
  dwCopy: LongWord; pvData: Pointer; pcbData: PLongInt): Boolean;
  external 'crypt32.dll' name 'CertGetCertificateContextData';
function CertFreeCertificateContext(pCertContext: PCertContext): Boolean;
  external 'crypt32.dll' name 'CertFreeCertificateContext';

{' Open a system store (Root/CA) by name, trying the documented
  CertOpenStore first and falling back to CertOpenSystemStoreW.
  Returns nil if the store cannot be opened. '}
function OpenWinSystemStore(const AName: WideString): PCertStore;
var
  h: PCertStore;
begin
  h := CertOpenStore(nil, nil, WinSystemStoreFlags, 0, PWideChar(AName));
  if h = nil then
    h := CertOpenSystemStoreW(WinSystemStoreFlags, PWideChar(AName));
  Result := h;
end;

{' Enumerate every certificate in an open system store (hStore), parse each
  one into a TX509Cert and hand ownership to AStore (AddOwnedCert).
  Runs in two phases: first every certificate''s DER bytes are copied out of
  its CERT_CONTEXT and the context is released; only then are the DER bytes
  parsed. The system stores can be refreshed by crypt32 in the background
  (for example when a new root CA is installed), so a context must not be
  held longer than necessary — in particular not across the slow parse.
  CertEnumCertificatesInStore FREES the context it is given as
  pPrevCertContext (see its documentation), so the DER bytes are copied
  before the next context is requested and the loop never calls
  CertFreeCertificateContext on a context the enumerator already released:
  doing otherwise corrupts the heap. Only a context still held when the loop
  is left through an exception is freed here.
  Raises EASN1Error (from ParseCertificate) on a malformed certificate. '}
procedure EnumWinStore(hStore: PCertStore; AStore: TCertStore);
var
  ctx: PCertContext;
  p: PByte;
  der: TBytes;
  ders: array of TBytes;
  cert: TX509Cert;
  i: LongInt;
begin
  { Phase 1: copy every certificate''s DER bytes out of its context. }
  ders := nil;
  ctx := nil;
  try
    ctx := CertEnumCertificatesInStore(hStore, nil);
    while ctx <> nil do
    begin
      SetLength(der, ctx^.cbCertEncoded);
      if ctx^.cbCertEncoded > 0 then
      begin
        p := PByte(ctx^.pbCertEncoded);
        Move(p^, der[0], ctx^.cbCertEncoded);
      end;
      SetLength(ders, Length(ders) + 1);
      ders[Length(ders) - 1] := der;
      { The enumerator frees the context passed in and returns the next one,
        or nil at the end of the store. }
      ctx := CertEnumCertificatesInStore(hStore, ctx);
    end;
  except
    { Leave the store through an error: release the context that is still
      held (it has not been handed back to the enumerator yet). }
    if ctx <> nil then
      CertFreeCertificateContext(ctx);
    raise;
  end;

  { Phase 2: parse the DER bytes (no certificate contexts are involved). }
  for i := 0 to Length(ders) - 1 do
  begin
    cert := ParseCertificate(ders[i]);
    AStore.AddOwnedCert(cert);
  end;
end;

function LoadWindowsSystemStore: TCertStore;
var
  rootStore, caStore: PCertStore;
begin
  Result := TCertStore.Create;
  caStore := nil;

  { Open the system Root store (current user + local machine). }
  rootStore := OpenWinSystemStore('Root');
  if rootStore = nil then
  begin
    Result.Free;
    raise TWinCertStoreError.Create(
      'LoadWindowsSystemStore: cannot open the Root store');
  end;

  { The inner try/except drops the partially filled store and re-raises;
    the outer finally closes both system stores on every path. The nesting
    works around an FPC 3.2.2 parser bug: a "raise;" statement directly in
    an except block followed by "finally" is not parsed. }
  try
    try
      { Open the system CA store (current user + local machine). }
      caStore := OpenWinSystemStore('CA');
      if caStore = nil then
        raise TWinCertStoreError.Create(
          'LoadWindowsSystemStore: cannot open the CA store');

      { Enumerate both stores; EnumWinStore copies every certificate out of
        its context, frees the context, and parses the DER bytes. }
      EnumWinStore(rootStore, Result);
      EnumWinStore(caStore, Result);
    except
      { A store could not be opened, or a certificate is malformed: drop
        the partially filled store, then re-raise. }
      Result.Free;
      raise;
    end;
  finally
    { Close both system stores on every path (success or error). }
    if caStore <> nil then
      CertCloseStore(caStore, 0);
    CertCloseStore(rootStore, 0);
  end;
end;
{$endif windows}
end.
