unit test_x509;

{ Tests for X.509 parser (tls.x509): ParseCertificate, certificate fields,
  SPKI (RSA/EC), extensions (BasicConstraints, KeyUsage, EKU, SAN, SKI, AKI),
  expired/non-CA/mismatch certificates, OpenSSL samples, errors. }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TX509Tests = class(TTestCase)
  published
    { --- RSA CA / Leaf --- }
    procedure TestRSACABasic;
    procedure TestRSACASPKI;
    procedure TestRSACAAuthorityKeyIdentifier;
    procedure TestRSACABasicConstraints;
    procedure TestRSACASubjectKeyIdentifier;
    procedure TestRSACASignature;
    procedure TestRSALeafBasic;
    procedure TestRSALeafSubject;
    procedure TestRSALeafSAN;
    procedure TestRSALeafBasicConstraints;
    procedure TestRSALeafKeyUsage;
    procedure TestRSALeafEKU;
    procedure TestRSALeafSKI;
    procedure TestRSALeafAKI;
    procedure TestRSALeafSPKI;
    procedure TestRSALeafSignature;
    { --- EC CA / Leaf --- }
    procedure TestECCABasic;
    procedure TestECLeafSPKI;
    procedure TestECLeafSAN;
    procedure TestECLeafSignature;
    { --- Special certificates --- }
    procedure TestExpiredCert;
    procedure TestMismatchCert;
    procedure TestNonCACert;
    { --- OpenSSL test/certs --- }
    procedure TestOpenSSLLeaf;
    procedure TestOpenSSLCertV1;
    procedure TestOpenSSLECCert;
    procedure TestOpenSSLExpired;
    procedure TestOpenSSLNonCA;
    procedure TestOpenSSLMD5;
    procedure TestOpenSSLPSS;
    { --- Errors --- }
    procedure TestParseEmpty;
    procedure TestParseNotCert;
    procedure TestParseTruncated;
    { --- Helpers --- }
    procedure TestAttributeName;
    procedure TestSignatureAlgorithmName;
    procedure TestToDebugString;
    procedure TestTBSCertificate;
  end;

implementation

uses
  SysUtils, Classes, DateUtils,
  tls.asn1, tls.bn, tls.ec, tls.x509;

{--- Helper functions ---}

function LoadFixture(const Name: string): TBytes;
var
  fs: TFileStream;
  path: string;
begin
  path := ExtractFilePath(ParamStr(0)) + '..' + PathDelim + 'tests' + PathDelim + 'fixtures' + PathDelim + Name;
  if not FileExists(path) then
    path := 'tests' + PathDelim + 'fixtures' + PathDelim + Name;
  fs := TFileStream.Create(path, fmOpenRead);
  try
    fs.Position := 0;
    Result := nil;
    SetLength(Result, fs.Size);
    if fs.Size > 0 then
      fs.ReadBuffer(Result[0], fs.Size);
  finally
    fs.Free;
  end;
end;

function ParseFixture(const Name: string): TX509Cert;
begin
  Result := ParseCertificate(LoadFixture(Name));
end;

function BytesEqual(A, B: TBytes): Boolean;
var
  i: LongInt;
begin
  if Length(A) <> Length(B) then Exit(False);
  for i := 0 to High(A) do
    if A[i] <> B[i] then Exit(False);
  Result := True;
end;

{--- RSA CA ---}

procedure TX509Tests.TestRSACABasic;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('ca_rsa.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertNotNull('serial', cert.SerialNumber);
    AssertTrue('serial > 0', not cert.SerialNumber.IsZero);
    AssertNotNull('issuer', cert.Issuer);
    AssertNotNull('subject', cert.Subject);
    AssertTrue('notBefore > 0', cert.NotBefore > 0);
    AssertTrue('notAfter > notBefore', cert.NotAfter > cert.NotBefore);
    AssertEquals('sigAlg OID', '1.2.840.113549.1.1.11', cert.SignatureAlgorithm);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSACASPKI;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('ca_rsa.der');
  try
    AssertNotNull('spki', cert.SPKI);
    AssertEquals('keyType', Integer(pkRSA), Integer(cert.SPKI.KeyType));
    AssertEquals('algOID', '1.2.840.113549.1.1.1', cert.SPKI.AlgorithmOID);
    AssertNotNull('modulus', cert.SPKI.RSAModulus);
    AssertNotNull('exponent', cert.SPKI.RSAExponent);
    AssertEquals('exponent value', '65537', cert.SPKI.RSAExponent.ToString);
    AssertTrue('modulus > 2048 bits', cert.SPKI.RSAModulus.BitLength >= 2048);
    AssertTrue('keyBytes > 0', Length(cert.SPKI.KeyBytes) > 0);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSACAAuthorityKeyIdentifier;
var
  cert: TX509Cert;
  aki: TBytes;
begin
  cert := ParseFixture('ca_rsa.der');
  try
    aki := cert.GetAuthorityKeyIdentifier;
    AssertTrue('aki exists', Length(aki) > 0);
    AssertEquals('aki length', 20, Length(aki));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSACABasicConstraints;
var
  cert: TX509Cert;
  bc: TBasicConstraints;
begin
  cert := ParseFixture('ca_rsa.der');
  try
    bc := cert.GetBasicConstraints;
    AssertTrue('isCA', bc.IsCA);
    AssertEquals('pathLen', -1, bc.PathLen);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSACASubjectKeyIdentifier;
var
  cert: TX509Cert;
  ski: TBytes;
begin
  cert := ParseFixture('ca_rsa.der');
  try
    ski := cert.GetSubjectKeyIdentifier;
    AssertTrue('ski exists', Length(ski) > 0);
    AssertEquals('ski length', 20, Length(ski));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSACASignature;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('ca_rsa.der');
  try
    AssertTrue('signature exists', Length(cert.Signature) > 0);
    AssertTrue('signature length > 0', Length(cert.Signature) > 0);
    { RSA-2048 + SHA-256 → 256 bytes }
    AssertEquals('signature length', 256, Length(cert.Signature));
  finally
    cert.Free;
  end;
end;

{--- RSA Leaf ---}

procedure TX509Tests.TestRSALeafBasic;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertNotNull('serial', cert.SerialNumber);
    AssertEquals('sigAlg OID', '1.2.840.113549.1.1.11', cert.SignatureAlgorithm);
    AssertTrue('notBefore > 0', cert.NotBefore > 0);
    AssertTrue('notAfter > notBefore', cert.NotAfter > cert.NotBefore);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafSubject;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertEquals('CN', 'localhost', cert.Subject.GetByOID('2.5.4.3'));
    AssertEquals('C', 'US', cert.Subject.GetByOID('2.5.4.6'));
    AssertEquals('ST', 'Test', cert.Subject.GetByOID('2.5.4.8'));
    AssertEquals('L', 'Test', cert.Subject.GetByOID('2.5.4.7'));
    AssertEquals('O', 'TLS Test', cert.Subject.GetByOID('2.5.4.10'));
    AssertEquals('issuer CN', 'TLS Test RSA CA', cert.Issuer.GetByOID('2.5.4.3'));
    AssertEquals('issuer O', 'TLS Test CA', cert.Issuer.GetByOID('2.5.4.10'));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafSAN;
var
  cert: TX509Cert;
  san: TSANList;
  i: LongInt;
  found: Boolean;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    san := cert.GetSubjectAltNames;
    try
      AssertEquals('SAN count', 3, san.Count);
      for i := 0 to san.Count - 1 do
        AssertEquals('SAN kind', Integer(sanDNS), Integer(san.At(i).Kind));
      { Verify that all three DNS names are present }
      found := False;
      for i := 0 to san.Count - 1 do
        if san.At(i).Value = 'localhost' then found := True;
      AssertTrue('SAN has localhost', found);

      found := False;
      for i := 0 to san.Count - 1 do
        if san.At(i).Value = 'example.com' then found := True;
      AssertTrue('SAN has example.com', found);

      found := False;
      for i := 0 to san.Count - 1 do
        if san.At(i).Value = '*.example.com' then found := True;
      AssertTrue('SAN has *.example.com', found);
    finally
      san.Free;
    end;
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafBasicConstraints;
var
  cert: TX509Cert;
  bc: TBasicConstraints;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    bc := cert.GetBasicConstraints;
    AssertFalse('not CA', bc.IsCA);
    AssertEquals('pathLen', -1, bc.PathLen);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafKeyUsage;
var
  cert: TX509Cert;
  ku: TBytes;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    ku := cert.GetKeyUsage;
    AssertTrue('keyUsage exists', Length(ku) > 0);
    { digitalSignature = bit 0 (MSB-first), keyEncipherment = bit 2 }
    AssertTrue('digitalSignature bit', cert.HasKeyUsageBit(0));
    AssertFalse('contentCommitment bit', cert.HasKeyUsageBit(1));
    AssertTrue('keyEncipherment bit', cert.HasKeyUsageBit(2));
    AssertFalse('dataEncipherment bit', cert.HasKeyUsageBit(3));
  finally
    cert.Free;
  end;
end;
procedure TX509Tests.TestRSALeafEKU;
var
  cert: TX509Cert;
  eku: TOIDList;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    eku := cert.GetExtendedKeyUsage;
    try
      AssertEquals('EKU count', 1, eku.Count);
      { serverAuth = 1.3.6.1.5.5.7.3.1 }
      AssertEquals('serverAuth OID', '1.3.6.1.5.5.7.3.1', eku.At(0));
    finally
      eku.Free;
    end;
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafSKI;
var
  cert: TX509Cert;
  ski: TBytes;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    ski := cert.GetSubjectKeyIdentifier;
    AssertTrue('SKI exists', Length(ski) > 0);
    AssertEquals('SKI length', 20, Length(ski));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafAKI;
var
  cert: TX509Cert;
  aki: TBytes;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    aki := cert.GetAuthorityKeyIdentifier;
    AssertTrue('AKI exists', Length(aki) > 0);
    AssertEquals('AKI length', 20, Length(aki));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafSPKI;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertNotNull('spki', cert.SPKI);
    AssertEquals('keyType', Integer(pkRSA), Integer(cert.SPKI.KeyType));
    AssertNotNull('modulus', cert.SPKI.RSAModulus);
    AssertNotNull('exponent', cert.SPKI.RSAExponent);
    AssertEquals('exponent', '65537', cert.SPKI.RSAExponent.ToString);
    AssertTrue('modulus >= 2048 bits', cert.SPKI.RSAModulus.BitLength >= 2048);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestRSALeafSignature;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertTrue('signature exists', Length(cert.Signature) > 0);
    AssertEquals('signature length (RSA-2048/SHA-256)', 256, Length(cert.Signature));
  finally
    cert.Free;
  end;
end;

{--- EC CA / Leaf ---}

procedure TX509Tests.TestECCABasic;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('ca_ec.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertEquals('sigAlg', '1.2.840.10045.4.3.2', cert.SignatureAlgorithm);
    AssertEquals('CN', 'TLS Test EC CA', cert.Subject.GetByOID('2.5.4.3'));
    AssertEquals('O', 'TLS Test CA', cert.Subject.GetByOID('2.5.4.10'));
    AssertNotNull('spki', cert.SPKI);
    AssertEquals('keyType', Integer(pkEC), Integer(cert.SPKI.KeyType));
    AssertEquals('algOID', '1.2.840.10045.2.1', cert.SPKI.AlgorithmOID);
    AssertEquals('curveOID', '1.2.840.10045.3.1.7', cert.SPKI.CurveOID);
    AssertNotNull('curve', cert.SPKI.Curve);
    AssertNotNull('point', cert.SPKI.Point);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestECLeafSPKI;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_ec.der');
  try
    AssertNotNull('spki', cert.SPKI);
    AssertEquals('keyType', Integer(pkEC), Integer(cert.SPKI.KeyType));
    AssertEquals('algOID', '1.2.840.10045.2.1', cert.SPKI.AlgorithmOID);
    AssertEquals('curveOID', '1.2.840.10045.3.1.7', cert.SPKI.CurveOID);
    AssertNotNull('curve', cert.SPKI.Curve);
    AssertNotNull('point', cert.SPKI.Point);
    { P-256: uncompressed point = 65 bytes (0x04 + 32 + 32) }
    AssertEquals('point bytes', 65, Length(cert.SPKI.KeyBytes));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestECLeafSAN;
var
  cert: TX509Cert;
  san: TSANList;
  i: LongInt;
  found: Boolean;
begin
  cert := ParseFixture('leaf_ec.der');
  try
    san := cert.GetSubjectAltNames;
    try
      AssertEquals('SAN count', 3, san.Count);
      found := False;
      for i := 0 to san.Count - 1 do
        if san.At(i).Value = 'localhost' then found := True;
      AssertTrue('SAN has localhost', found);
    finally
      san.Free;
    end;
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestECLeafSignature;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_ec.der');
  try
    AssertTrue('signature exists', Length(cert.Signature) > 0);
    AssertTrue('signature length > 0', Length(cert.Signature) > 0);
    { ECDSA-256/SHA-256: DER SEQUENCE (r INTEGER, s INTEGER), ~70-80 bytes }
    AssertTrue('signature length reasonable', Length(cert.Signature) >= 60);
  finally
    cert.Free;
  end;
end;

{--- Special certificates ---}

procedure TX509Tests.TestExpiredCert;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('expired_rsa.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertEquals('CN', 'localhost', cert.Subject.GetByOID('2.5.4.3'));
    { Must not be valid now (2026) }
    AssertTrue('expired: notAfter < now', cert.NotAfter < Now);
    AssertTrue('notBefore < notAfter', cert.NotBefore < cert.NotAfter);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestMismatchCert;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('mismatch_rsa.der');
  try
    AssertEquals('version', 2, cert.Version);
    { CN does not match expected localhost }
    AssertEquals('CN', 'wrong.example.com', cert.Subject.GetByOID('2.5.4.3'));
    AssertTrue('CN != localhost', cert.Subject.GetByOID('2.5.4.3') <> 'localhost');
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestNonCACert;
var
  cert: TX509Cert;
  bc: TBasicConstraints;
begin
  cert := ParseFixture('nonca_rsa.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertEquals('CN', 'nonca.example.com', cert.Subject.GetByOID('2.5.4.3'));
    bc := cert.GetBasicConstraints;
    AssertFalse('not CA', bc.IsCA);
  finally
    cert.Free;
  end;
end;

{--- OpenSSL test/certs ---}

procedure TX509Tests.TestOpenSSLLeaf;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('openssl_leaf.der');
  try
    { This is a v1 certificate (no version field) }
    AssertEquals('version', 0, cert.Version);
    AssertEquals('CN', 'cert.example', cert.Subject.GetByOID('2.5.4.3'));
    AssertEquals('sigAlg', '1.2.840.113549.1.1.11', cert.SignatureAlgorithm);
    AssertNotNull('serial', cert.SerialNumber);
    AssertNotNull('spki', cert.SPKI);
    AssertEquals('keyType', Integer(pkRSA), Integer(cert.SPKI.KeyType));
    AssertTrue('notBefore > 0', cert.NotBefore > 0);
    AssertTrue('notAfter > notBefore', cert.NotAfter > cert.NotBefore);
    { v1 certificate has no extensions }
    AssertEquals('ext count', 0, cert.ExtensionCount);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestOpenSSLCertV1;
var
  cert: TX509Cert;
begin
  { openssl_leaf.der — v1 certificate with long fields }
  cert := ParseFixture('openssl_leaf.der');
  try
    AssertEquals('version v1', 0, cert.Version);
    { Long RDN fields }
    AssertEquals('ST', 'The Great State of Long-Winded Certificate Field Names Whereby to Increase the Output Size',
      cert.Subject.GetByOID('2.5.4.8'));
    AssertEquals('L', 'Toomanycharactersville', cert.Subject.GetByOID('2.5.4.7'));
    AssertEquals('O', 'The Benevolent Society of Loquacious and Pleonastic Periphrasis',
      cert.Subject.GetByOID('2.5.4.10'));
    AssertEquals('OU', 'Endorsement of Vouchsafe''d Evidentiary Certification',
      cert.Subject.GetByOID('2.5.4.11'));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestOpenSSLECCert;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('openssl_ca_ec.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertEquals('CN', 'CA', cert.Subject.GetByOID('2.5.4.3'));
    AssertEquals('issuer CN', 'Root CA', cert.Issuer.GetByOID('2.5.4.3'));
    AssertNotNull('spki', cert.SPKI);
    AssertEquals('keyType', Integer(pkEC), Integer(cert.SPKI.KeyType));
    AssertEquals('algOID', '1.2.840.10045.2.1', cert.SPKI.AlgorithmOID);
    AssertNotNull('curve', cert.SPKI.Curve);
    AssertNotNull('point', cert.SPKI.Point);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestOpenSSLExpired;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('openssl_expired.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertEquals('CN', 'CA', cert.Subject.GetByOID('2.5.4.3'));
    { Must not be valid now }
    AssertTrue('expired: notAfter < now', cert.NotAfter < Now);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestOpenSSLNonCA;
var
  cert: TX509Cert;
  bc: TBasicConstraints;
begin
  cert := ParseFixture('openssl_nonca.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertEquals('CN', 'CA', cert.Subject.GetByOID('2.5.4.3'));
    bc := cert.GetBasicConstraints;
    AssertFalse('not CA', bc.IsCA);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestOpenSSLMD5;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('openssl_ca_md5.der');
  try
    AssertEquals('version', 2, cert.Version);
    { md5WithRSAEncryption = 1.2.840.113549.1.1.4 }
    AssertEquals('sigAlg md5', '1.2.840.113549.1.1.4', cert.SignatureAlgorithm);
    AssertEquals('CN', 'CA', cert.Subject.GetByOID('2.5.4.3'));
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestOpenSSLPSS;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('openssl_ca_pss.der');
  try
    AssertEquals('version', 2, cert.Version);
    AssertEquals('CN', 'CA-PSS', cert.Subject.GetByOID('2.5.4.3'));
    { rsassaPss = 1.2.840.113549.1.1.10 }
    AssertEquals('sigAlg pss', '1.2.840.113549.1.1.10', cert.SignatureAlgorithm);
  finally
    cert.Free;
  end;
end;

{--- Errors ---}
procedure TX509Tests.TestParseEmpty;
var
  buf: TBytes;
  raised: Boolean;
begin
  SetLength(buf, 0);
  raised := False;
  try
    ParseCertificate(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('empty buffer raises', raised);
end;

procedure TX509Tests.TestParseNotCert;
var
  buf: TBytes;
  node: TASN1Node;
  raised: Boolean;
begin
  { Empty SEQUENCE — not a Certificate }
  node := ParseDER(LoadFixture('der_seq_empty.der'));
  try
    buf := EncodeDER(node);
    raised := False;
    try
      ParseCertificate(buf).Free;
    except
      on E: EASN1Error do raised := True;
    end;
    AssertTrue('empty SEQUENCE raises', raised);
  finally
    node.Free;
  end;
end;

procedure TX509Tests.TestParseTruncated;
var
  buf: TBytes;
  full: TBytes;
  raised: Boolean;
begin
  full := LoadFixture('ca_rsa.der');
  {Trim the last 10 bytes}
  SetLength(buf, Length(full) - 10);
  System.Move(full[0], buf[0], Length(buf));
  raised := False;
  try
    ParseCertificate(buf).Free;
  except
    on E: EASN1Error do raised := True;
  end;
  AssertTrue('truncated cert raises', raised);
end;

{--- Helpers ---}

procedure TX509Tests.TestAttributeName;
begin
  AssertEquals('CN', 'CN', AttributeName('2.5.4.3'));
  AssertEquals('C', 'C', AttributeName('2.5.4.6'));
  AssertEquals('L', 'L', AttributeName('2.5.4.7'));
  AssertEquals('ST', 'ST', AttributeName('2.5.4.8'));
  AssertEquals('O', 'O', AttributeName('2.5.4.10'));
  AssertEquals('OU', 'OU', AttributeName('2.5.4.11'));
  AssertEquals('email', 'emailAddress', AttributeName('1.2.840.113549.1.9.1'));
  AssertEquals('unknown OID passthrough', '1.2.3.4.5', AttributeName('1.2.3.4.5'));
end;

procedure TX509Tests.TestSignatureAlgorithmName;
begin
  AssertEquals('sha256rsa', 'sha256WithRSAEncryption',
    SignatureAlgorithmName('1.2.840.113549.1.1.11'));
  AssertEquals('sha1rsa', 'sha1WithRSAEncryption',
    SignatureAlgorithmName('1.2.840.113549.1.1.5'));
  AssertEquals('md5rsa', 'md5WithRSAEncryption',
    SignatureAlgorithmName('1.2.840.113549.1.1.4'));
  AssertEquals('ecdsa-sha256', 'ecdsa-with-SHA256',
    SignatureAlgorithmName('1.2.840.10045.4.3.2'));
  AssertEquals('unknown passthrough', '1.2.3.4.5',
    SignatureAlgorithmName('1.2.3.4.5'));
end;

procedure TX509Tests.TestToDebugString;
var
  cert: TX509Cert;
  s: string;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    s := cert.ToDebugString;
    AssertTrue('has version', Pos('v2', s) > 0);
    AssertTrue('has Issuer', Pos('Issuer:', s) > 0);
    AssertTrue('has Subject', Pos('Subject:', s) > 0);
    AssertTrue('has localhost', Pos('localhost', s) > 0);
    AssertTrue('has RSA', Pos('RSA', s) > 0);
    AssertTrue('has Extensions', Pos('Extensions:', s) > 0);
  finally
    cert.Free;
  end;
end;

procedure TX509Tests.TestTBSCertificate;
var
  cert: TX509Cert;
  tbs: TBytes;
  node: TASN1Node;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    tbs := cert.TBSCertificate;
    AssertTrue('TBS exists', Length(tbs) > 0);
    AssertTrue('TBS length > 0', Length(tbs) > 0);
    {TBS must be a valid DER SEQUENCE}
    node := ParseDER(tbs);
    try
      AssertEquals('TBS is SEQUENCE', Integer(atSequence), Integer(node.Tag));
      AssertTrue('TBS has children', node.ChildCount >= 6);
    finally
      node.Free;
    end;
  finally
    cert.Free;
  end;
end;

initialization
  RegisterTest(TX509Tests);

end.
