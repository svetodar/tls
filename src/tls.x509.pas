{ SPDX-License-Identifier: Apache-2.0 }
unit tls.x509;

{ X.509 (RFC 5280) — parsing of a v3 certificate into a structured object.
  Layer 2 (certificates), depends on tls.asn1 (DER), tls.bn (TBN),
  tls.ec (curves/points for EC keys). Implementation for
  task 10 (docs/tasks/10-x509.md).

  TX509Cert — parsing: version, serial number, issuer/subject (RDN names),
  validity, signature algorithm and value, raw DER bytes of TBS (for signature
  verification in task 11), SubjectPublicKeyInfo (key type + DER of public
  key + parsed N/E for RSA and curve/point for EC), extensions
  (SAN, BasicConstraints, KeyUsage, EKU, SKI, AKI).

  Structure (RFC 5280): Certificate = SEQUENCE of TBSCertificate,
  signature AlgorithmIdentifier and BIT STRING signature value.
  TBSCertificate = SEQUENCE: version (context [0], optional, default v1),
  serialNumber (INTEGER), signature (AlgorithmIdentifier), issuer (Name),
  validity (SEQUENCE of notBefore/notAfter), subject (Name),
  subjectPublicKeyInfo, issuerUniqueID [1] / subjectUniqueID [2] (opt.),
  extensions [3] (EXPLICIT SEQUENCE OF Extension, opt.). }

{$mode objfpc}{$H+}

interface

uses
  SysUtils,
  tls.asn1,
  tls.bn,
  tls.ec;

type
  { Public key type (by algorithm OID in SPKI). }
  TPublicKeyType = (pkUnknown, pkRSA, pkEC, pkDH);

  { SubjectAltName element type (GeneralName). }
  TSANType = (sanDNS, sanIP, sanEmail, sanURI, sanOther);

  { Name attribute (AttributeTypeAndValue): OID + value. }
  TX509Attribute = class
  public
    OID: string;
    Value: string;
  end;

  { Single RDN (RelativeDistinguishedName): set of attributes (usually one). }
  TRDN = class
  private
    FAttrs: array of TX509Attribute;
    function GetCount: LongInt;
  public
    constructor Create;
    destructor Destroy; override;
    function Add(const AOID, AValue: string): TX509Attribute;
    property Count: LongInt read GetCount;
    function At(i: LongInt): TX509Attribute;
    { String of the form "CN=localhost" (multiple attributes — separated by "+"). }
    function ToNameString: string;
  end;

  { Name (Name / RDNSequence): sequence of RDN in certificate order. }
  TX509Name = class
  private
    FRDNs: array of TRDN;
    function GetCount: LongInt;
  public
    constructor Create;
    destructor Destroy; override;
    procedure AddRDN(const ARDN: TRDN);
    { Add a single-attribute RDN. }
    function Add(const AOID, AValue: string): TRDN;
    property Count: LongInt read GetCount;
    function At(i: LongInt): TRDN;
    { Value of the first attribute with the given OID (across all RDN), '' if none. }
    function GetByOID(const AOID: string): string;
    { Human-readable string "C=US, ST=Test, CN=localhost". }
    function ToNameString: string;
  end;

  { X.509 extension: OID + critical + raw value (contents of OCTET STRING). }
  TX509Extension = class
  public
    OID: string;
    Critical: Boolean;
    Value: TBytes;
  end;

  { SubjectPublicKeyInfo: algorithm OID, key type, DER of public key
    and parsed fields (RSA: N/E; EC: curve + point). }
  TSPKI = class
  private
    FAlgorithmOID: string;
    FCurveOID: string;
    FKeyBytes: TBytes;
    FKeyType: TPublicKeyType;
    FRSAN, FRSANE: TBN;
    FCurve: TECCurve;
    FPoint: TECPoint;
  public
    constructor Create;
    destructor Destroy; override;
    property AlgorithmOID: string read FAlgorithmOID;
    property KeyType: TPublicKeyType read FKeyType;
    { Raw DER bytes of the public key (contents of BIT STRING without unused byte). }
    property KeyBytes: TBytes read FKeyBytes;
    { Curve OID (for EC), '' for non-EC. }
    property CurveOID: string read FCurveOID;
    { RSA: modulus and exponent (nil for non-RSA). }
    property RSAModulus: TBN read FRSAN;
    property RSAExponent: TBN read FRSANE;
    { EC: curve and point (nil for non-EC or unknown curve). }
    property Curve: TECCurve read FCurve;
    property Point: TECPoint read FPoint;
  end;

  { BasicConstraints (unpacked value of extension 2.5.29.19). }
  TBasicConstraints = record
    IsCA: Boolean;
    PathLen: LongInt;  { -1 if pathlenConstraint is absent }
  end;

  { SubjectAltName element. }
  TX509AltName = class
  public
    Kind: TSANType;
    Value: string;  { DNS/email/URI; for IP — dotted-decimal string }
  end;
  { List of OIDs (for ExtendedKeyUsage). }
  TOIDList = class
  private
    FOIDs: array of string;
    function GetCount: LongInt;
  public
    constructor Create;
    destructor Destroy; override;
    property Count: LongInt read GetCount;
    procedure Add(const AOID: string);
    function At(i: LongInt): string;
  end;

  { List of SubjectAltName elements. }
  TSANList = class
  private
    FItems: array of TX509AltName;
    function GetCount: LongInt;
  public
    constructor Create;
    destructor Destroy; override;
    property Count: LongInt read GetCount;
    procedure Add(const AItem: TX509AltName);
    function At(i: LongInt): TX509AltName;
  end;


  { X.509 certificate. }
  TX509Cert = class
  private
    FVersion: LongInt;
    FSerialNumber: TBN;
    FIssuer: TX509Name;
    FSubject: TX509Name;
    FNotBefore, FNotAfter: TDateTime;
    FSignatureAlgorithm: string;
    FSignature: TBytes;
    FTBS: TBytes;
    FSPKI: TSPKI;
    FExtensions: array of TX509Extension;
  public
    constructor Create;
    destructor Destroy; override;
    property Version: LongInt read FVersion;
    property SerialNumber: TBN read FSerialNumber;
    property Issuer: TX509Name read FIssuer;
    property Subject: TX509Name read FSubject;
    property NotBefore: TDateTime read FNotBefore;
    property NotAfter: TDateTime read FNotAfter;
    { Signature algorithm OID (from TBS). }
    property SignatureAlgorithm: string read FSignatureAlgorithm;
    { Signature bytes (contents of BIT STRING signatureValue without unused byte). }
    property Signature: TBytes read FSignature;
    { Raw DER bytes of TBSCertificate (for signature verification). }
    property TBSCertificate: TBytes read FTBS;
    property SPKI: TSPKI read FSPKI;
    function ExtensionCount: LongInt;
    function ExtensionAt(i: LongInt): TX509Extension;
    function FindExtension(const AOID: string): TX509Extension;
    { --- Extensions (unpacked) --- }
    function GetBasicConstraints: TBasicConstraints;
    { KeyUsage bytes (without unused byte). }
    function GetKeyUsage: TBytes;
    function HasKeyUsageBit(pos: LongInt): Boolean;
    { List of OIDs from ExtendedKeyUsage. }
    function GetExtendedKeyUsage: TOIDList;
    function GetSubjectAltNames: TSANList;
    function GetSubjectKeyIdentifier: TBytes;
    function GetAuthorityKeyIdentifier: TBytes;
    { Debug string. }
    function ToDebugString: string;
  end;

{ Parse DER X.509 certificate into TX509Cert. Errors — EASN1Error. }
function ParseCertificate(const der: TBytes): TX509Cert;
{ Short name of name attribute OID (CN, C, ST, L, O, OU, ...); OID as is,
  if no known name exists. }
function AttributeName(const OID: string): string;
{ Human-readable signature algorithm name (sha256WithRSAEncryption, ...). }
function SignatureAlgorithmName(const OID: string): string;

implementation

{--- Helper functions ---}

{ TBytes → string (byte copy; for UTF8String bytes remain UTF-8). }
function BytesToString(const B: TBytes): string;
begin
  SetLength(Result, Length(B));
  if Length(B) > 0 then
    Move(B[0], PChar(Result)^, Length(B));
end;

{ Contents of primitive node → string. }
function NodeToString(const Node: TASN1Node): string;
begin
  if (Node = nil) or Node.IsConstructor then
    raise EASN1Error.Create('NodeToString: node is not primitive');
  Result := BytesToString(Node.Data);
end;

{ TBN → LongInt (for small values: version, pathlen). }
function BNToLongInt(const B: TBN): LongInt;
begin
  if B = nil then
    Result := 0
  else
    Result := StrToIntDef(B.ToString, 0);
end;

{ IP bytes → dotted-decimal string (IPv4/IPv6). }
function IPToString(const B: TBytes): string;
var
  i: LongInt;
  g: array[0..7] of string;
begin
  if Length(B) = 4 then
  begin
    Result := IntToStr(B[0]) + '.' + IntToStr(B[1]) + '.' +
      IntToStr(B[2]) + '.' + IntToStr(B[3]);
    Exit;
  end;
  if Length(B) = 16 then
  begin
    for i := 0 to 7 do
      g[i] := IntToHex(B[i * 2] * 256 + B[i * 2 + 1], 4);
    Result := g[0] + ':' + g[1] + ':' + g[2] + ':' + g[3] +
      ':' + g[4] + ':' + g[5] + ':' + g[6] + ':' + g[7];
    Exit;
  end;
  Result := '';
end;

{ Curve OID → TECCurve (only supported P-256/P-384). }
function CurveFromOID(const OID: string): TECCurve;
begin
  Result := nil;
  case OID of
    '1.2.840.10045.3.1.7': Result := CurveP256;  { prime256v1 }
    '1.3.132.0.34':        Result := CurveP384;  { secp384r1 }
  end;
end;

{ Key type name (debug). }
function KeyTypeName(const T: TPublicKeyType): string;
begin
  case T of
    pkRSA:     Result := 'RSA';
    pkEC:      Result := 'EC';
    pkDH:      Result := 'DH';
  else
    Result := 'unknown';
  end;
end;

{--- Name trace ---}

{ Parse Name: SEQUENCE OF SET OF (OID, value). }
function ParseName(const Node: TASN1Node): TX509Name;
var
  i, j: LongInt;
  rdnNode, atavNode: TASN1Node;
  rdn: TRDN;
begin
  Result := TX509Name.Create;
  if (Node = nil) or (Node.TagClass <> tcUniversal) or
     (Node.TagNumber <> Ord(atSequence)) then
    raise EASN1Error.Create('ParseName: node is not SEQUENCE (Name)');
  for i := 0 to Node.ChildCount - 1 do
  begin
    rdnNode := Node.ChildAt(i);  { SET OF AttributeTypeAndValue }
    if (rdnNode.TagClass <> tcUniversal) or (rdnNode.TagNumber <> Ord(atSet)) then
      raise EASN1Error.Create('ParseName: RDN is not SET');
    rdn := TRDN.Create;
    for j := 0 to rdnNode.ChildCount - 1 do
    begin
      atavNode := rdnNode.ChildAt(j);  { SEQUENCE (OID, value) }
      if (atavNode.TagNumber <> Ord(atSequence)) or (atavNode.ChildCount < 2) then
        raise EASN1Error.Create('ParseName: AttributeTypeAndValue < 2 fields');
      rdn.Add(ReadOID(atavNode.ChildAt(0)), NodeToString(atavNode.ChildAt(1)));
    end;
    Result.AddRDN(rdn);
  end;
end;

{--- SPKI trace ---}

{ Parse SubjectPublicKeyInfo: SEQUENCE (AlgorithmIdentifier, BIT STRING). }
function ParseSPKI(const Node: TASN1Node): TSPKI;
var
  algNode, paramNode, keyNode, rsaNode: TASN1Node;
  keyBytes: TBytes;
begin
  Result := TSPKI.Create;
  if (Node = nil) or (Node.TagNumber <> Ord(atSequence)) or (Node.ChildCount < 2) then
    raise EASN1Error.Create('ParseSPKI: invalid SPKI structure');
  algNode := Node.ChildAt(0);  { SEQUENCE (OID, params) }
  if (algNode.TagNumber <> Ord(atSequence)) or (algNode.ChildCount < 1) then
    raise EASN1Error.Create('ParseSPKI: AlgorithmIdentifier is incorrect');
  Result.FAlgorithmOID := ReadOID(algNode.ChildAt(0));
  if algNode.ChildCount >= 2 then
  begin
    paramNode := algNode.ChildAt(1);
    if (paramNode.TagClass = tcUniversal) and
       (paramNode.TagNumber = Ord(atObjectIdentifier)) then
      Result.FCurveOID := ReadOID(paramNode);
  end;

  keyNode := Node.ChildAt(1);  { BIT STRING }
  if (keyNode.TagClass <> tcUniversal) or (keyNode.TagNumber <> Ord(atBitString)) then
    raise EASN1Error.Create('ParseSPKI: subjectPublicKey is not BIT STRING');
  { BIT STRING: [unused_bits][key_bytes] }
  SetLength(keyBytes, Length(keyNode.Data) - 1);
  if Length(keyBytes) > 0 then
    Move(keyNode.Data[1], keyBytes[0], Length(keyBytes));
  Result.FKeyBytes := keyBytes;

  case Result.FAlgorithmOID of
    '1.2.840.113549.1.1.1': Result.FKeyType := pkRSA;
    '1.2.840.10045.2.1':    Result.FKeyType := pkEC;
    '1.2.840.113549.1.3.1': Result.FKeyType := pkDH;
  else
    Result.FKeyType := pkUnknown;
  end;

  if Result.FKeyType = pkRSA then
  begin
    { RSAPublicKey ::= SEQUENCE (modulus INTEGER, publicExponent INTEGER) }
    rsaNode := ParseDER(Result.FKeyBytes);
    try
      if (rsaNode.TagNumber <> Ord(atSequence)) or (rsaNode.ChildCount < 2) then
        raise EASN1Error.Create('ParseSPKI: RSAPublicKey is incorrect');
      Result.FRSAN := ReadInteger(rsaNode.ChildAt(0));
      Result.FRSANE := ReadInteger(rsaNode.ChildAt(1));
    finally
      rsaNode.Free;
    end;
  end
  else if Result.FKeyType = pkEC then
  begin
    Result.FCurve := CurveFromOID(Result.FCurveOID);
    if Result.FCurve <> nil then
      Result.FPoint := DecodePoint(Result.FCurve, Result.FKeyBytes);
  end;
end;

{--- TOIDList / TSANList ---}

constructor TOIDList.Create;
begin
  inherited Create;
  FOIDs := nil;
end;

destructor TOIDList.Destroy;
begin
  FOIDs := nil;
  inherited Destroy;
end;

function TOIDList.GetCount: LongInt;
begin
  Result := Length(FOIDs);
end;

procedure TOIDList.Add(const AOID: string);
begin
  SetLength(FOIDs, Length(FOIDs) + 1);
  FOIDs[Length(FOIDs) - 1] := AOID;
end;

function TOIDList.At(i: LongInt): string;
begin
  if (i < 0) or (i >= Length(FOIDs)) then
    raise EASN1Error.CreateFmt('TOIDList.At: index %d out of range', [i]);
  Result := FOIDs[i];
end;

constructor TSANList.Create;
begin
  inherited Create;
  FItems := nil;
end;

destructor TSANList.Destroy;
var
  i: LongInt;
begin
  for i := 0 to Length(FItems) - 1 do
    FItems[i].Free;
  inherited Destroy;
end;

function TSANList.GetCount: LongInt;
begin
  Result := Length(FItems);
end;

procedure TSANList.Add(const AItem: TX509AltName);
begin
  SetLength(FItems, Length(FItems) + 1);
  FItems[Length(FItems) - 1] := AItem;
end;

function TSANList.At(i: LongInt): TX509AltName;
begin
  if (i < 0) or (i >= Length(FItems)) then
    raise EASN1Error.CreateFmt('TSANList.At: index %d out of range', [i]);
  Result := FItems[i];
end;

{--- TX509Attribute / TRDN / TX509Name ---}

constructor TRDN.Create;
begin
  inherited Create;
  FAttrs := nil;
end;

destructor TRDN.Destroy;
var
  i: LongInt;
begin
  for i := 0 to Length(FAttrs) - 1 do
    FAttrs[i].Free;
  inherited Destroy;
end;

function TRDN.GetCount: LongInt;
begin
  Result := Length(FAttrs);
end;

function TRDN.Add(const AOID, AValue: string): TX509Attribute;
begin
  Result := TX509Attribute.Create;
  Result.OID := AOID;
  Result.Value := AValue;
  SetLength(FAttrs, Length(FAttrs) + 1);
  FAttrs[Length(FAttrs) - 1] := Result;
end;

function TRDN.At(i: LongInt): TX509Attribute;
begin
  if (i < 0) or (i >= Length(FAttrs)) then
    raise EASN1Error.CreateFmt('TRDN.At: index %d out of range', [i]);
  Result := FAttrs[i];
end;

function TRDN.ToNameString: string;
var
  i: LongInt;
begin
  Result := '';
  for i := 0 to Length(FAttrs) - 1 do
  begin
    if i > 0 then
      Result := Result + '+';
    Result := Result + AttributeName(FAttrs[i].OID) + '=' + FAttrs[i].Value;
  end;
end;

constructor TX509Name.Create;
begin
  inherited Create;
  FRDNs := nil;
end;

destructor TX509Name.Destroy;
var
  i: LongInt;
begin
  for i := 0 to Length(FRDNs) - 1 do
    FRDNs[i].Free;
  inherited Destroy;
end;

function TX509Name.GetCount: LongInt;
begin
  Result := Length(FRDNs);
end;

procedure TX509Name.AddRDN(const ARDN: TRDN);
begin
  SetLength(FRDNs, Length(FRDNs) + 1);
  FRDNs[Length(FRDNs) - 1] := ARDN;
end;

function TX509Name.Add(const AOID, AValue: string): TRDN;
begin
  Result := TRDN.Create;
  Result.Add(AOID, AValue);
  AddRDN(Result);
end;

function TX509Name.At(i: LongInt): TRDN;
begin
  if (i < 0) or (i >= Length(FRDNs)) then
    raise EASN1Error.CreateFmt('TX509Name.At: index %d out of range', [i]);
  Result := FRDNs[i];
end;

function TX509Name.GetByOID(const AOID: string): string;
var
  i, j: LongInt;
begin
  Result := '';
  for i := 0 to Length(FRDNs) - 1 do
    for j := 0 to FRDNs[i].Count - 1 do
      if FRDNs[i].At(j).OID = AOID then
      begin
        Result := FRDNs[i].At(j).Value;
        Exit;
      end;
end;

function TX509Name.ToNameString: string;
var
  i: LongInt;
begin
  Result := '';
  for i := 0 to Length(FRDNs) - 1 do
  begin
    if i > 0 then
      Result := Result + ', ';
    Result := Result + FRDNs[i].ToNameString;
  end;
end;

{--- TSPKI ---}

constructor TSPKI.Create;
begin
  inherited Create;
  FAlgorithmOID := '';
  FCurveOID := '';
  FKeyBytes := nil;
  FKeyType := pkUnknown;
  FRSAN := nil;
  FRSANE := nil;
  FCurve := nil;
  FPoint := nil;
end;

destructor TSPKI.Destroy;
begin
  if FRSAN <> nil then FRSAN.Free;
  if FRSANE <> nil then FRSANE.Free;
  if FCurve <> nil then FCurve.Free;
  if FPoint <> nil then FPoint.Free;
  inherited Destroy;
end;

{--- TX509Cert ---}

constructor TX509Cert.Create;
begin
  inherited Create;
  FVersion := 0;
  FSerialNumber := nil;
  FIssuer := nil;
  FSubject := nil;
  FNotBefore := 0;
  FNotAfter := 0;
  FSignatureAlgorithm := '';
  FSignature := nil;
  FTBS := nil;
  FSPKI := nil;
  FExtensions := nil;
end;

destructor TX509Cert.Destroy;
var
  i: LongInt;
begin
  if FSerialNumber <> nil then FSerialNumber.Free;
  if FIssuer <> nil then FIssuer.Free;
  if FSubject <> nil then FSubject.Free;
  if FSPKI <> nil then FSPKI.Free;
  for i := 0 to Length(FExtensions) - 1 do
    FExtensions[i].Free;
  inherited Destroy;
end;

function TX509Cert.ExtensionCount: LongInt;
begin
  Result := Length(FExtensions);
end;

function TX509Cert.ExtensionAt(i: LongInt): TX509Extension;
begin
  if (i < 0) or (i >= Length(FExtensions)) then
    raise EASN1Error.CreateFmt('TX509Cert.ExtensionAt: index %d out of range', [i]);
  Result := FExtensions[i];
end;

function TX509Cert.FindExtension(const AOID: string): TX509Extension;
var
  i: LongInt;
begin
  Result := nil;
  for i := 0 to Length(FExtensions) - 1 do
    if FExtensions[i].OID = AOID then
    begin
      Result := FExtensions[i];
      Break;
    end;
end;

{ BasicConstraints (2.5.29.19): SEQUENCE (cA BOOLEAN DEFAULT FALSE,
  pathLenConstraint INTEGER OPTIONAL). }
function TX509Cert.GetBasicConstraints: TBasicConstraints;
var
  ext: TX509Extension;
  node: TASN1Node;
begin
  Result.IsCA := False;
  Result.PathLen := -1;
  ext := FindExtension('2.5.29.19');
  if ext = nil then
    Exit;
  node := ParseDER(ext.Value);
  try
    if node.TagNumber <> Ord(atSequence) then
      raise EASN1Error.Create('BasicConstraints: not SEQUENCE');
    if node.ChildCount > 0 then
    begin
      if node.ChildAt(0).TagNumber = Ord(atBoolean) then
        Result.IsCA := node.ChildAt(0).Data[0] <> 0;
    end;
    if node.ChildCount > 1 then
      Result.PathLen := BNToLongInt(ReadInteger(node.ChildAt(1)));
  finally
    node.Free;
  end;
end;

{ KeyUsage (2.5.29.15): BIT STRING. }
function TX509Cert.GetKeyUsage: TBytes;
var
  ext: TX509Extension;
  node: TASN1Node;
begin
  Result := nil;
  ext := FindExtension('2.5.29.15');
  if ext = nil then
    Exit;
  node := ParseDER(ext.Value);
  try
    if node.TagNumber <> Ord(atBitString) then
      raise EASN1Error.Create('KeyUsage: not BIT STRING');
    SetLength(Result, Length(node.Data) - 1);
    if Length(Result) > 0 then
      Move(node.Data[1], Result[0], Length(Result));
  finally
    node.Free;
  end;
end;

function TX509Cert.HasKeyUsageBit(pos: LongInt): Boolean;
var
  ku: TBytes;
begin
  ku := GetKeyUsage;
  Result := False;
  { ASN.1 BIT STRING: bits are numbered from the most significant (MSB) of the first byte. }
  if (pos >= 0) and (pos div 8 < Length(ku)) then
    Result := (ku[pos div 8] and (1 shl (7 - (pos mod 8)))) <> 0;
end;
function TX509Cert.GetExtendedKeyUsage: TOIDList;
var
  ext: TX509Extension;
  node: TASN1Node;
  i: LongInt;
begin
  Result := TOIDList.Create;
  ext := FindExtension('2.5.29.37');
  if ext = nil then
    Exit;
  node := ParseDER(ext.Value);
  try
    if node.TagNumber <> Ord(atSequence) then
      raise EASN1Error.Create('EKU: not SEQUENCE');
    for i := 0 to node.ChildCount - 1 do
      Result.Add(ReadOID(node.ChildAt(i)));
  finally
    node.Free;
  end;
end;

{ SubjectAltName (2.5.29.17): SEQUENCE OF GeneralName.
  GeneralName: dNSName [2], emailAddress [4], URI [6], iPAddress [7]. }
function TX509Cert.GetSubjectAltNames: TSANList;
var
  ext: TX509Extension;
  node: TASN1Node;
  i: LongInt;
  name: TX509AltName;
  cn: TASN1Node;
begin
  Result := TSANList.Create;
  ext := FindExtension('2.5.29.17');
  if ext = nil then
    Exit;
  node := ParseDER(ext.Value);
  try
    if node.TagNumber <> Ord(atSequence) then
      raise EASN1Error.Create('SAN: not SEQUENCE');
    for i := 0 to node.ChildCount - 1 do
    begin
      cn := node.ChildAt(i);
      name := TX509AltName.Create;
      case cn.TagNumber of
        2: begin name.Kind := sanDNS;   name.Value := NodeToString(cn); end;
        4: begin name.Kind := sanEmail; name.Value := NodeToString(cn); end;
        6: begin name.Kind := sanURI;   name.Value := NodeToString(cn); end;
        7: begin name.Kind := sanIP;    name.Value := IPToString(cn.Data); end;
      else
        begin name.Kind := sanOther; name.Value := ''; end;
      end;
      Result.Add(name);
    end;
  finally
    node.Free;
  end;
end;

{ SubjectKeyIdentifier (2.5.29.14): OCTET STRING. extnValue contains DER
 encoding of the value (inner OCTET STRING with the identifier). }
function TX509Cert.GetSubjectKeyIdentifier: TBytes;
var
  ext: TX509Extension;
  node: TASN1Node;
begin
  Result := nil;
  ext := FindExtension('2.5.29.14');
  if ext = nil then
    Exit;
  node := ParseDER(ext.Value);
  try
    if (node.TagClass <> tcUniversal) or (node.TagNumber <> Ord(atOctetString)) then
      raise EASN1Error.Create('SKI: value is not OCTET STRING');
    Result := node.Data;
  finally
    node.Free;
  end;
end;

{ AuthorityKeyIdentifier (2.5.29.35): SEQUENCE, [0] keyIdentifier OPTIONAL, ... . }
function TX509Cert.GetAuthorityKeyIdentifier: TBytes;
var
  ext: TX509Extension;
  node, kid: TASN1Node;
begin
  Result := nil;
  ext := FindExtension('2.5.29.35');
  if ext = nil then
    Exit;
  node := ParseDER(ext.Value);
  try
    if node.TagNumber <> Ord(atSequence) then
      raise EASN1Error.Create('AKI: not SEQUENCE');
    kid := node.FindByTag(tcContextSpecific, 0);
    if kid <> nil then
      Result := kid.Data;
  finally
    node.Free;
  end;
end;

function TX509Cert.ToDebugString: string;
begin
  Result := 'X509Cert v' + IntToStr(FVersion) +
    #13#10 + '  Serial: ' + FSerialNumber.ToHex +
    #13#10 + '  Issuer: ' + FIssuer.ToNameString +
    #13#10 + '  Subject: ' + FSubject.ToNameString +
    #13#10 + '  NotBefore: ' + FloatToStr(FNotBefore) +
    #13#10 + '  NotAfter: ' + FloatToStr(FNotAfter) +
    #13#10 + '  SigAlg: ' + FSignatureAlgorithm + ' (' +
      SignatureAlgorithmName(FSignatureAlgorithm) + ')' +
    #13#10 + '  SPKI: ' + FSPKI.AlgorithmOID + ' (' +
      KeyTypeName(FSPKI.KeyType) + ')' +
    #13#10 + '  Extensions: ' + IntToStr(Length(FExtensions));
end;

{--- ParseCertificate ---}

function ParseCertificate(const der: TBytes): TX509Cert;
var
  tree, certNode, tbsNode, sigNode: TASN1Node;
  verNode, serialNode, sigAlgTBSNode, issuerNode, validityNode: TASN1Node;
  subjectNode, spkiNode, extNode, extSeq, extItem, child: TASN1Node;
  i, seqCount: LongInt;
  ext: TX509Extension;
begin
  Result := TX509Cert.Create;
  tree := ParseDER(der);
  try
    certNode := tree;  { SEQUENCE (tbs, sigAlg, sig) }
    if (certNode.TagClass <> tcUniversal) or
       (certNode.TagNumber <> Ord(atSequence)) or (certNode.ChildCount < 3) then
      raise EASN1Error.Create('ParseCertificate: root is not Certificate SEQUENCE');
    tbsNode := certNode.ChildAt(0);
    sigNode := certNode.ChildAt(2);

    { TBS bytes (for signature verification) — canonical re-encoded DER. }
    Result.FTBS := EncodeDER(tbsNode);

    { Identification of TBS fields in order (version and uniqueID are optional). }
    verNode := nil;
    serialNode := nil;
    sigAlgTBSNode := nil;
    issuerNode := nil;
    validityNode := nil;
    subjectNode := nil;
    spkiNode := nil;
    extNode := nil;
    seqCount := 0;
    for i := 0 to tbsNode.ChildCount - 1 do
    begin
      child := tbsNode.ChildAt(i);
      if child.TagClass = tcContextSpecific then
      begin
        case child.TagNumber of
          0: verNode := child;
          3: extNode := child;
        end;
      end
      else
      begin
        if child.TagNumber = Ord(atInteger) then
        begin
          if serialNode = nil then
            serialNode := child;
        end
        else if child.TagNumber = Ord(atSequence) then
        begin
          case seqCount of
            0: sigAlgTBSNode := child;
            1: issuerNode := child;
            2: validityNode := child;
            3: subjectNode := child;
            4: spkiNode := child;
          end;
          Inc(seqCount);
        end;
      end;
    end;

    if serialNode = nil then
      raise EASN1Error.Create('ParseCertificate: no serialNumber');
    if sigAlgTBSNode = nil then
      raise EASN1Error.Create('ParseCertificate: no signature (TBS)');
    if issuerNode = nil then
      raise EASN1Error.Create('ParseCertificate: no issuer');
    if validityNode = nil then
      raise EASN1Error.Create('ParseCertificate: no validity');
    if subjectNode = nil then
      raise EASN1Error.Create('ParseCertificate: no subject');
    if spkiNode = nil then
      raise EASN1Error.Create('ParseCertificate: no subjectPublicKeyInfo');

    { Version: [0] EXPLICIT Version DEFAULT v1. }
    Result.FVersion := 0;
    if verNode <> nil then
      Result.FVersion := BNToLongInt(ReadInteger(verNode.FirstChild));

    Result.FSerialNumber := ReadInteger(serialNode);
    Result.FSignatureAlgorithm := ReadOID(sigAlgTBSNode.ChildAt(0));

    { Validity: SEQUENCE (notBefore Time, notAfter Time). }
    if validityNode.ChildCount < 2 then
      raise EASN1Error.Create('ParseCertificate: validity < 2 fields');
    Result.FNotBefore := ReadTime(validityNode.ChildAt(0));
    Result.FNotAfter := ReadTime(validityNode.ChildAt(1));

    Result.FIssuer := ParseName(issuerNode);
    Result.FSubject := ParseName(subjectNode);
    Result.FSPKI := ParseSPKI(spkiNode);

    { Extensions: [3] EXPLICIT SEQUENCE OF Extension. }
    if extNode <> nil then
    begin
      extSeq := extNode.FirstChild;
      if (extSeq = nil) or (extSeq.TagNumber <> Ord(atSequence)) then
        raise EASN1Error.Create('ParseCertificate: extensions not SEQUENCE');
      for i := 0 to extSeq.ChildCount - 1 do
      begin
        extItem := extSeq.ChildAt(i);  { SEQUENCE (OID, [BOOLEAN], OCTET STRING) }
        if (extItem.TagNumber <> Ord(atSequence)) or (extItem.ChildCount < 2) then
          raise EASN1Error.Create('ParseCertificate: Extension invalid');
        ext := TX509Extension.Create;
        ext.OID := ReadOID(extItem.ChildAt(0));
        ext.Critical := False;
        if extItem.ChildCount = 2 then
          ext.Value := extItem.ChildAt(1).Data
        else if extItem.ChildCount = 3 then
        begin
          ext.Critical := (extItem.ChildAt(1).TagNumber = Ord(atBoolean)) and
            (extItem.ChildAt(1).Data[0] <> 0);
          ext.Value := extItem.ChildAt(2).Data;
        end
        else
          raise EASN1Error.Create('ParseCertificate: Extension: > 3 fields');
        SetLength(Result.FExtensions, Length(Result.FExtensions) + 1);
        Result.FExtensions[Length(Result.FExtensions) - 1] := ext;
      end;
    end;

    { Signature value: BIT STRING. }
    if (sigNode.TagClass <> tcUniversal) or (sigNode.TagNumber <> Ord(atBitString)) then
      raise EASN1Error.Create('ParseCertificate: signatureValue not BIT STRING');
    SetLength(Result.FSignature, Length(sigNode.Data) - 1);
    if Length(Result.FSignature) > 0 then
      Move(sigNode.Data[1], Result.FSignature[0], Length(Result.FSignature));
  finally
    tree.Free;
  end;
end;

{--- OID Names ---}

function AttributeName(const OID: string): string;
begin
  case OID of
    '2.5.4.3':              Result := 'CN';
    '2.5.4.6':              Result := 'C';
    '2.5.4.7':              Result := 'L';
    '2.5.4.8':              Result := 'ST';
    '2.5.4.10':             Result := 'O';
    '2.5.4.11':             Result := 'OU';
    '1.2.840.113549.1.9.1': Result := 'emailAddress';
  else
    Result := OID;
  end;
end;

function SignatureAlgorithmName(const OID: string): string;
begin
  case OID of
    '1.2.840.113549.1.1.4':  Result := 'md5WithRSAEncryption';
    '1.2.840.113549.1.1.5':  Result := 'sha1WithRSAEncryption';
    '1.2.840.113549.1.1.11': Result := 'sha256WithRSAEncryption';
    '1.2.840.113549.1.1.12': Result := 'sha384WithRSAEncryption';
    '1.2.840.113549.1.1.13': Result := 'sha512WithRSAEncryption';
    '1.2.840.10045.4.1':     Result := 'ecdsa-with-SHA1';
    '1.2.840.10045.4.3.2':   Result := 'ecdsa-with-SHA256';
    '1.2.840.10045.4.3.3':   Result := 'ecdsa-with-SHA384';
    '1.2.840.10045.4.3.4':   Result := 'ecdsa-with-SHA512';
  else
    Result := OID;
  end;
end;

end.
