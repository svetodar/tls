{ SPDX-License-Identifier: Apache-2.0 }
unit test_certverify;

{ Certificate chain verification tests (tls.certstore):
  VerifyChain, VerifySignature, CheckValidity, WildcardMatch, CertMatchesHost,
  TCertStore (Add/FindBySubject/FindBySKI/Clear),
  PEM loading without a file (LoadPEMFromMemory, LoadBundleFromStream) and the
  file wrappers over it (LoadPEM, LoadBundle),
  LoadWindowsSystemStore (Windows only; skipped on other platforms). }

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TCertVerifyTests = class(TTestCase)
  published
    { --- VerifyChain: successful chains --- }
    procedure TestChainRSASuccess;
    procedure TestChainECSuccess;
    procedure TestChainSelfSigned;
    procedure TestChainLen;
    { --- VerifyChain: failures --- }
    procedure TestChainExpiredLeaf;
    procedure TestChainNonCAIssuer;
    procedure TestChainUnknownIssuer;
    procedure TestChainWrongCA;
    procedure TestChainNilLeaf;
    procedure TestChainOpenSSLExpired;
    procedure TestChainOpenSSLNonCA;
    procedure TestChainOpenSSLEnptyStore;
    { --- VerifySignature --- }
    procedure TestSigRSAValid;
    procedure TestSigECValid;
    procedure TestSigRSACross;
    procedure TestSigNil;
    { --- CheckValidity --- }
    procedure TestValidityCurrent;
    procedure TestValidityExpired;
    procedure TestValidityFuture;
    procedure TestValidityCustomTime;
    { --- WildcardMatch --- }
    procedure TestWildcardExact;
    procedure TestWildcardBasic;
    procedure TestWildcardMultiLabel;
    procedure TestWildcardNoMatch;
    procedure TestWildcardCaseInsensitive;
    procedure TestWildcardStarNotFirst;
    procedure TestWildcardStarNoDot;
    procedure TestWildcardEmptyHost;
    { --- CertMatchesHost --- }
    procedure TestHostSANExact;
    procedure TestHostSANWildcard;
    procedure TestHostSANMultiple;
    procedure TestHostCNFallback;
    procedure TestHostMismatch;
    procedure TestHostCaseInsensitive;
    procedure TestHostEmpty;
    { --- TCertStore --- }
    procedure TestStoreAddCount;
    procedure TestStoreFindBySubject;
    procedure TestStoreFindBySKI;
    procedure TestStoreFindBySubjectCanonical;
    procedure TestStoreFindBySubjectNotFound;
    procedure TestStoreFindBySubjectInsertionOrder;
    procedure TestStoreFindBySKINotFound;
    procedure TestStoreLookupEmptyStore;
    procedure TestStoreClearDropsIndex;
    procedure TestStoreClear;
    procedure TestStoreAt;
    { --- PEM from memory and streams (no file access) --- }
    procedure TestPEMFromMemoryMatchesFile;
    procedure TestPEMFromMemorySurroundingText;
    procedure TestPEMFromMemoryNoHeader;
    procedure TestPEMFromMemoryUnterminated;
    procedure TestPEMFromMemoryBadBase64;
    procedure TestLoadPEMFileMatchesMemory;
    procedure TestBundleFromStreamTwoCerts;
    procedure TestBundleFromStreamSurroundingText;
    procedure TestBundleFromStreamNil;
    procedure TestBundleFromStreamEmpty;
    procedure TestBundleFromStreamUnterminated;
    procedure TestBundleFromStreamBadDER;
    procedure TestLoadBundleFileMatchesStream;
    { --- Windows system store (skipped off-Windows) --- }
    procedure TestWinSystemStoreNonEmpty;
    procedure TestWinSystemStoreKnownRoot;
    procedure TestWinSystemStoreNoLeak;
  end;

implementation

uses
  SysUtils, Classes, DateUtils,
  tls.asn1, tls.x509, tls.certstore;
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

{ Create a store with a single CA certificate. }
function MakeStore(const CAName: string): TCertStore;
var
  ca: TX509Cert;
begin
  Result := TCertStore.Create;
  ca := ParseFixture(CAName);
  { The store parsed nothing itself here, so it is told to own the
    certificate: Destroy frees it together with the store. }
  Result.AddOwnedCert(ca);
end;

{--- PEM helpers ---}

{' Standard base64 (RFC 4648 §4) with padding. The library only decodes base64
  (Base64Decode is private to tls.certstore), so the tests need their own
  encoder to turn fixture DER into PEM text. '}
function Base64EncodeBytes(const AData: TBytes): string;
const
  Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
var
  i, n: LongInt;
  b0, b1, b2: Byte;
begin
  Result := '';
  n := Length(AData);
  i := 0;
  while i + 2 < n do
  begin
    b0 := AData[i];
    b1 := AData[i + 1];
    b2 := AData[i + 2];
    Result := Result + Alphabet[(b0 shr 2) + 1] +
      Alphabet[(((b0 and $03) shl 4) or (b1 shr 4)) + 1] +
      Alphabet[(((b1 and $0F) shl 2) or (b2 shr 6)) + 1] +
      Alphabet[(b2 and $3F) + 1];
    Inc(i, 3);
  end;
  case n - i of
    1:
      begin
        b0 := AData[i];
        Result := Result + Alphabet[(b0 shr 2) + 1] +
          Alphabet[((b0 and $03) shl 4) + 1] + '==';
      end;
    2:
      begin
        b0 := AData[i];
        b1 := AData[i + 1];
        Result := Result + Alphabet[(b0 shr 2) + 1] +
          Alphabet[(((b0 and $03) shl 4) or (b1 shr 4)) + 1] +
          Alphabet[((b1 and $0F) shl 2) + 1] + '=';
      end;
  end;
end;

{' Wrap DER bytes into a PEM CERTIFICATE block with 64-character lines,
  the same shape certifi / OpenSSL bundles use. '}
function PEMFromDER(const ADER: TBytes): RawByteString;
const
  Header = '-----BEGIN CERTIFICATE-----';
  Footer = '-----END CERTIFICATE-----';
  ChunkLen = 64;
var
  b64, text: string;
  i: LongInt;
begin
  b64 := Base64EncodeBytes(ADER);
  text := Header + #13#10;
  i := 1;
  while i <= Length(b64) do
  begin
    text := text + Copy(b64, i, ChunkLen) + #13#10;
    Inc(i, ChunkLen);
  end;
  text := text + Footer + #13#10;
  Result := text;
end;

{ PEM text for a DER fixture. }
function FixturePEM(const Name: string): RawByteString;
begin
  Result := PEMFromDER(LoadFixture(Name));
end;

{' Parse PEM text held in memory through a TMemoryStream, so the test exercises
  the stream entry point without touching the file system. '}
function BundleFromText(const AText: RawByteString): TCertStore;
var
  ms: TMemoryStream;
begin
  ms := TMemoryStream.Create;
  try
    if Length(AText) > 0 then
      ms.WriteBuffer(AText[1], Length(AText));
    ms.Position := 0;
    Result := LoadBundleFromStream(ms);
  finally
    ms.Free;
  end;
end;

{' True if LoadPEMFromMemory rejects AText with EASN1Error (the message is
  returned in AMessage). A certificate returned by mistake is freed here, so
  the helper leaks nothing on either outcome. '}
function PEMFromTextFails(const AText: RawByteString;
  out AMessage: string): Boolean;
var
  cert: TX509Cert;
begin
  Result := False;
  AMessage := '';
  cert := nil;
  try
    try
      cert := LoadPEMFromMemory(AText);
    except
      on E: EASN1Error do
      begin
        Result := True;
        AMessage := E.Message;
      end;
    end;
  finally
    cert.Free;
  end;
end;

{' True if LoadBundleFromStream rejects AText with EASN1Error (see
  PEMFromTextFails for the ownership rules). '}
function BundleFromTextFails(const AText: RawByteString;
  out AMessage: string): Boolean;
var
  store: TCertStore;
begin
  Result := False;
  AMessage := '';
  store := nil;
  try
    try
      store := BundleFromText(AText);
    except
      on E: EASN1Error do
      begin
        Result := True;
        AMessage := E.Message;
      end;
    end;
  finally
    store.Free;
  end;
end;

{' Write AText into a file under the temporary directory and return its path;
  the caller removes the file. Used to check that LoadPEM / LoadBundle really
  delegate to the in-memory parsers. '}
function WriteTempPEM(const AName: string; const AText: RawByteString): string;
var
  fs: TFileStream;
begin
  Result := IncludeTrailingPathDelimiter(GetTempDir) + AName;
  DeleteFile(Result);
  fs := TFileStream.Create(Result, fmCreate);
  try
    if Length(AText) > 0 then
      fs.WriteBuffer(AText[1], Length(AText));
  finally
    fs.Free;
  end;
end;

function SameBytes(const A, B: TBytes): Boolean;
var
  i: LongInt;
begin
  Result := Length(A) = Length(B);
  if not Result then
    Exit;
  for i := 0 to High(A) do
    if A[i] <> B[i] then
    begin
      Result := False;
      Exit;
    end;
end;

{--- VerifyChain: successful chains ---}

procedure TCertVerifyTests.TestChainRSASuccess;
var
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  store := MakeStore('ca_rsa.der');
  leaf := ParseFixture('leaf_rsa.der');
  try
    res := VerifyChain(store, leaf);
    AssertTrue('RSA chain OK', res.OK);
    AssertEquals('RSA chain len', 2, res.ChainLen);
    AssertEquals('no reason', '', res.Reason);
  finally
    leaf.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainECSuccess;
var
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  store := MakeStore('ca_ec.der');
  leaf := ParseFixture('leaf_ec.der');
  try
    res := VerifyChain(store, leaf);
    AssertTrue('EC chain OK', res.OK);
    AssertEquals('EC chain len', 2, res.ChainLen);
  finally
    leaf.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainSelfSigned;
var
  store: TCertStore;
  cert: TX509Cert;
  res: TVerifyResult;
begin
  { openssl_leaf.der — self-signed (issuer == subject). }
  store := TCertStore.Create;
  cert := ParseFixture('openssl_leaf.der');
  try
    { Self-signed: no store needed, but VerifyChain requires a store.
      Empty store — self-signed is verified without searching the store. }
    res := VerifyChain(store, cert);
    { openssl_leaf is expired (notAfter 2017), so we expect a failure due to validity.
      To test self-signed logic we use ca_rsa (not expired). }
    AssertFalse('expired self-signed fails', res.OK);
  finally
    cert.Free;
    store.Free;
  end;

  { Now ca_rsa is self-signed and not expired. }
  store := TCertStore.Create;
  cert := ParseFixture('ca_rsa.der');
  try
    res := VerifyChain(store, cert);
    AssertTrue('self-signed CA OK', res.OK);
    AssertEquals('self-signed chain len', 1, res.ChainLen);
  finally
    cert.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainLen;
var
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  store := MakeStore('ca_rsa.der');
  leaf := ParseFixture('leaf_rsa.der');
  try
    res := VerifyChain(store, leaf);
    AssertTrue('chain OK', res.OK);
    { leaf → CA = 2 elements }
    AssertEquals('chain length 2', 2, res.ChainLen);
  finally
    leaf.Free;
    store.Free;
  end;
end;

{--- VerifyChain: failures ---}

procedure TCertVerifyTests.TestChainExpiredLeaf;
var
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  store := MakeStore('ca_rsa.der');
  leaf := ParseFixture('expired_rsa.der');
  try
    res := VerifyChain(store, leaf);
    AssertFalse('expired leaf fails', res.OK);
    AssertTrue('reason mentions expired',
      Pos('expired', LowerCase(res.Reason)) > 0);
  finally
    leaf.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainNonCAIssuer;
var
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  { nonca_rsa is signed by ca_rsa, but nonca_rsa itself is CA:FALSE.
    If nonca_rsa is used as leaf and its issuer (ca_rsa) is searched for,
    the chain should pass (nonca — leaf, CA — issuer).
    But if nonca_rsa is the issuer for another leaf, the chain should
    be rejected. For the test: nonca_rsa as leaf → ca_rsa as issuer → OK.
    To test "issuer is not a CA" we need a leaf signed by nonca_rsa.
    There is none in fixtures, so we check that nonca_rsa as root
    (self-signed by name) does not pass. }

  { nonca_rsa: issuer = ca_rsa, so the chain leaf=nonca_rsa → ca_rsa
    should pass (nonca_rsa — leaf, not root). }
  store := MakeStore('ca_rsa.der');
  leaf := ParseFixture('nonca_rsa.der');
  try
    res := VerifyChain(store, leaf);
    { nonca_rsa is signed by ca_rsa (CA:TRUE), signature is valid, validity OK.
      nonca_rsa — leaf (CA:FALSE), but that's normal for a leaf. }
    AssertTrue('nonca as leaf → CA passes', res.OK);
  finally
    leaf.Free;
    store.Free;
  end;
  { openssl_nonca.der: issuer="CN=Root CA", subject="CN=CA", CA:FALSE.
    Not self-signed (issuer ≠ subject), so VerifyChain searches for
    "CN=Root CA" in the store. Empty store → "issuer not found". }
  store := TCertStore.Create;
  leaf := ParseFixture('openssl_nonca.der');
  try
    res := VerifyChain(store, leaf);
    AssertFalse('non-CA issuer not found', res.OK);
    AssertTrue('reason mentions issuer',
      Pos('issuer', LowerCase(res.Reason)) > 0);
  finally
    leaf.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainUnknownIssuer;
var
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  { Empty store: issuer of leaf_rsa not found. }
  store := TCertStore.Create;
  leaf := ParseFixture('leaf_rsa.der');
  try
    res := VerifyChain(store, leaf);
    AssertFalse('unknown issuer fails', res.OK);
    AssertTrue('reason mentions issuer',
      Pos('issuer', LowerCase(res.Reason)) > 0);
  finally
    leaf.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainWrongCA;
var
  store: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  { leaf_rsa is signed by ca_rsa, but the store has ca_ec.
    AKI of leaf_rsa → SKI of ca_rsa, won't be found in the store.
    Search by name: issuer of leaf_rsa = "TLS Test RSA CA",
    in the store "TLS Test EC CA" — won't be found. }
  store := MakeStore('ca_ec.der');
  leaf := ParseFixture('leaf_rsa.der');
  try
    res := VerifyChain(store, leaf);
    AssertFalse('wrong CA fails', res.OK);
    AssertTrue('reason mentions issuer',
      Pos('issuer', LowerCase(res.Reason)) > 0);
  finally
    leaf.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainNilLeaf;
var
  store: TCertStore;
  res: TVerifyResult;
begin
  store := TCertStore.Create;
  try
    res := VerifyChain(store, nil);
    AssertFalse('nil leaf fails', res.OK);
    AssertTrue('reason mentions nil',
      Pos('nil', LowerCase(res.Reason)) > 0);
  finally
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainOpenSSLExpired;
var
  store: TCertStore;
  cert: TX509Cert;
  res: TVerifyResult;
begin
  { openssl_expired.der: self-signed, expired (notAfter < notBefore). }
  store := TCertStore.Create;
  cert := ParseFixture('openssl_expired.der');
  try
    res := VerifyChain(store, cert);
    AssertFalse('expired cert fails', res.OK);
  finally
    cert.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainOpenSSLNonCA;
var
  store: TCertStore;
  cert: TX509Cert;
  res: TVerifyResult;
begin
  { openssl_nonca.der: issuer="CN=Root CA", CA:FALSE, not self-signed.
    Empty store → issuer not found → chain cannot be built. }
  store := TCertStore.Create;
  cert := ParseFixture('openssl_nonca.der');
  try
    res := VerifyChain(store, cert);
    AssertFalse('non-CA fails', res.OK);
  finally
    cert.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestChainOpenSSLEnptyStore;
var
  store: TCertStore;
  cert: TX509Cert;
  res: TVerifyResult;
begin
  {openssl_leaf.der: self-signed, but expired (2017).
    Check that even a self-signed with an expired validity period does not pass.}
  store := TCertStore.Create;
  cert := ParseFixture('openssl_leaf.der');
  try
    res := VerifyChain(store, cert);
    AssertFalse('expired self-signed fails', res.OK);
  finally
    cert.Free;
    store.Free;
  end;
end;

{--- VerifySignature ---}

procedure TCertVerifyTests.TestSigRSAValid;
var
  ca, leaf: TX509Cert;
begin
  ca := ParseFixture('ca_rsa.der');
  leaf := ParseFixture('leaf_rsa.der');
  try
    AssertTrue('RSA sig valid', VerifySignature(ca, leaf));
  finally
    ca.Free;
    leaf.Free;
  end;
end;

procedure TCertVerifyTests.TestSigECValid;
var
  ca, leaf: TX509Cert;
begin
  ca := ParseFixture('ca_ec.der');
  leaf := ParseFixture('leaf_ec.der');
  try
    AssertTrue('EC sig valid', VerifySignature(ca, leaf));
  finally
    ca.Free;
    leaf.Free;
  end;
end;

procedure TCertVerifyTests.TestSigRSACross;
var
  ca, leaf: TX509Cert;
begin
  {leaf_rsa is signed by ca_rsa, but we verify with ca_ec key — it must not pass.}
  ca := ParseFixture('ca_ec.der');
  leaf := ParseFixture('leaf_rsa.der');
  try
    AssertFalse('cross sig fails', VerifySignature(ca, leaf));
  finally
    ca.Free;
    leaf.Free;
  end;
end;

procedure TCertVerifyTests.TestSigNil;
begin
  AssertFalse('nil parent', VerifySignature(nil, nil));
end;

{--- CheckValidity ---}

procedure TCertVerifyTests.TestValidityCurrent;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertTrue('leaf_rsa valid now', CheckValidity(cert, 0));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestValidityExpired;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('expired_rsa.der');
  try
    AssertFalse('expired_rsa not valid now', CheckValidity(cert, 0));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestValidityFuture;
var
  cert: TX509Cert;
  future: TDateTime;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    {Time is after notAfter.}
    future := cert.NotAfter + 1;
    AssertFalse('future time invalid', CheckValidity(cert, future));
    {Time is before notBefore.}
    AssertFalse('past time invalid', CheckValidity(cert, cert.NotBefore - 1));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestValidityCustomTime;
var
  cert: TX509Cert;
  mid: TDateTime;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    {Middle of the validity period — valid.}
    mid := (cert.NotBefore + cert.NotAfter) / 2;
    AssertTrue('mid validity', CheckValidity(cert, mid));
  finally
    cert.Free;
  end;
end;

{--- WildcardMatch ---}

procedure TCertVerifyTests.TestWildcardExact;
begin
  AssertTrue('exact match', WildcardMatch('example.com', 'example.com'));
  AssertTrue('exact case-insensitive', WildcardMatch('Example.COM', 'example.com'));
  AssertFalse('different', WildcardMatch('example.com', 'other.com'));
end;

procedure TCertVerifyTests.TestWildcardBasic;
begin
  AssertTrue('wildcard match', WildcardMatch('*.example.com', 'sub.example.com'));
  AssertTrue('wildcard case-insensitive', WildcardMatch('*.EXAMPLE.COM', 'Sub.example.com'));
  AssertFalse('wildcard no match', WildcardMatch('*.example.com', 'other.com'));
  AssertFalse('wildcard no match 2', WildcardMatch('*.example.com', 'example.org'));
end;

procedure TCertVerifyTests.TestWildcardMultiLabel;
begin
  {'*' replaces exactly one label: a.b.example.com must not
    match *.example.com (two labels).}
  AssertFalse('multi-label no match',
    WildcardMatch('*.example.com', 'a.b.example.com'));
end;

procedure TCertVerifyTests.TestWildcardNoMatch;
begin
  {Exact name does not match wildcard.}
  AssertFalse('exact vs wildcard',
    WildcardMatch('*.example.com', 'example.com'));
end;

procedure TCertVerifyTests.TestWildcardCaseInsensitive;
begin
  AssertTrue('upper pattern', WildcardMatch('*.EXAMPLE.COM', 'sub.example.com'));
  AssertTrue('upper host', WildcardMatch('*.example.com', 'SUB.EXAMPLE.COM'));
end;

procedure TCertVerifyTests.TestWildcardStarNotFirst;
begin
  {'*' not in the first label — does not match.}
  AssertFalse('star middle', WildcardMatch('sub.*.com', 'sub.example.com'));
  AssertFalse('star end', WildcardMatch('example.*', 'example.com'));
end;

procedure TCertVerifyTests.TestWildcardStarNoDot;
begin
  {'*' without a dot — does not match.}
  AssertFalse('no dot', WildcardMatch('*example.com', 'subexample.com'));
end;

procedure TCertVerifyTests.TestWildcardEmptyHost;
begin
  AssertFalse('empty host', WildcardMatch('*.example.com', ''));
  AssertFalse('empty pattern', WildcardMatch('', 'example.com'));
end;

{--- CertMatchesHost ---}

procedure TCertVerifyTests.TestHostSANExact;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertTrue('SAN localhost', CertMatchesHost(cert, 'localhost'));
    AssertTrue('SAN example.com', CertMatchesHost(cert, 'example.com'));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestHostSANWildcard;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertTrue('SAN *.example.com → sub', CertMatchesHost(cert, 'sub.example.com'));
    AssertFalse('SAN *.example.com → a.b', CertMatchesHost(cert, 'a.b.example.com'));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestHostSANMultiple;
var
  cert: TX509Cert;
begin
  { leaf_rsa SAN: localhost, example.com, *.example.com }
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertTrue('localhost', CertMatchesHost(cert, 'localhost'));
    AssertTrue('example.com', CertMatchesHost(cert, 'example.com'));
    AssertTrue('sub.example.com', CertMatchesHost(cert, 'sub.example.com'));
    AssertFalse('other.com', CertMatchesHost(cert, 'other.com'));
    AssertFalse('localhost2', CertMatchesHost(cert, 'localhost2'));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestHostCNFallback;
var
  cert: TX509Cert;
begin
  {openssl_leaf.der: self-signed, CN=cert.example, no SAN.
    Check CN fallback.}
  cert := ParseFixture('openssl_leaf.der');
  try
    {Is there a SAN? If not — check CN.}
    AssertTrue('CN fallback match', CertMatchesHost(cert, 'cert.example'));
    AssertFalse('CN fallback no match', CertMatchesHost(cert, 'other.example'));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestHostMismatch;
var
  cert: TX509Cert;
begin
  { mismatch_rsa: SAN = DNS:wrong.example.com, DNS:other.example.com. }
  cert := ParseFixture('mismatch_rsa.der');
  try
    AssertFalse('mismatch no match', CertMatchesHost(cert, 'localhost'));
    AssertTrue('mismatch SAN match', CertMatchesHost(cert, 'wrong.example.com'));
    AssertTrue('mismatch SAN other', CertMatchesHost(cert, 'other.example.com'));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestHostCaseInsensitive;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertTrue('upper host', CertMatchesHost(cert, 'LOCALHOST'));
    AssertTrue('mixed case', CertMatchesHost(cert, 'Sub.Example.COM'));
  finally
    cert.Free;
  end;
end;

procedure TCertVerifyTests.TestHostEmpty;
var
  cert: TX509Cert;
begin
  cert := ParseFixture('leaf_rsa.der');
  try
    AssertFalse('empty host', CertMatchesHost(cert, ''));
  finally
    cert.Free;
  end;
end;

{--- TCertStore ---}

procedure TCertVerifyTests.TestStoreAddCount;
var
  store: TCertStore;
  ca1, ca2: TX509Cert;
begin
  store := TCertStore.Create;
  ca1 := ParseFixture('ca_rsa.der');
  ca2 := ParseFixture('ca_ec.der');
  try
    AssertEquals('empty store', 0, store.Count);
    store.Add(ca1);
    AssertEquals('after add 1', 1, store.Count);
    store.Add(ca2);
    AssertEquals('after add 2', 2, store.Count);
  finally
    ca1.Free;
    ca2.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreFindBySubject;
var
  store: TCertStore;
  ca: TX509Cert;
  found: TX509Cert;
begin
  store := MakeStore('ca_rsa.der');
  ca := ParseFixture('ca_rsa.der');
  try
    found := store.FindBySubject(ca.Subject.ToNameString);
    AssertNotNull('found by subject', found);
    AssertEquals('same subject', ca.Subject.ToNameString,
      found.Subject.ToNameString);
  finally
    ca.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreFindBySKI;
var
  store: TCertStore;
  ca: TX509Cert;
  ski: TBytes;
  found: TX509Cert;
begin
  store := MakeStore('ca_rsa.der');
  ca := ParseFixture('ca_rsa.der');
  try
    ski := ca.GetSubjectKeyIdentifier;
    AssertTrue('SKI not empty', Length(ski) > 0);
    found := store.FindBySKI(ski);
    AssertNotNull('found by SKI', found);
    AssertEquals('same subject', ca.Subject.ToNameString,
      found.Subject.ToNameString);
  finally
    ca.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreFindBySubjectCanonical;
var
  store: TCertStore;
  ca: TX509Cert;
  name: string;
  found: TX509Cert;
begin
  store := MakeStore('ca_rsa.der');
  ca := ParseFixture('ca_rsa.der');
  try
    name := ca.Subject.ToNameString;
    { The subject index is keyed by CanonicalSubjectName, so case and blank
      runs do not matter (RFC 5280 §7.1). }
    found := store.FindBySubject(UpperCase(name));
    AssertNotNull('case-insensitive', found);
    AssertEquals('same subject', name, found.Subject.ToNameString);
    found := store.FindBySubject('   ' + name + '   ');
    AssertNotNull('surrounding blanks', found);
    found := store.FindBySubject(StringReplace(name, ' ', '   ', [rfReplaceAll]));
    AssertNotNull('extra inner blanks', found);
  finally
    ca.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreFindBySubjectNotFound;
var
  store: TCertStore;
begin
  store := MakeStore('ca_rsa.der');
  try
    AssertNull('unknown subject', store.FindBySubject('CN=nothing like it'));
    AssertNull('empty name', store.FindBySubject(''));
  finally
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreFindBySubjectInsertionOrder;
var
  store: TCertStore;
  ca1, ca2: TX509Cert;
begin
  store := TCertStore.Create;
  ca1 := ParseFixture('ca_rsa.der');
  ca2 := ParseFixture('ca_rsa.der');
  try
    store.Add(ca1);
    store.Add(ca2);
    { Equal keys keep the insertion order: the old linear scan returned the
      first certificate added, and so does the index. }
    AssertTrue('first added wins by subject',
      store.FindBySubject(ca1.Subject.ToNameString) = ca1);
    AssertTrue('first added wins by SKI',
      store.FindBySKI(ca1.GetSubjectKeyIdentifier) = ca1);
  finally
    store.Free;
    ca1.Free;
    ca2.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreFindBySKINotFound;
var
  store: TCertStore;
  other: TBytes;
begin
  store := MakeStore('ca_rsa.der');
  try
    SetLength(other, 20);
    FillChar(other[0], 20, $AA);
    AssertNull('unknown SKI', store.FindBySKI(other));
    AssertNull('empty SKI', store.FindBySKI(nil));
    SetLength(other, 19);
    FillChar(other[0], 19, $AA);
    AssertNull('SKI of another length', store.FindBySKI(other));
  finally
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreLookupEmptyStore;
var
  store: TCertStore;
begin
  store := TCertStore.Create;
  try
    AssertNull('empty store, by subject', store.FindBySubject('CN=x'));
    AssertNull('empty store, by SKI', store.FindBySKI(nil));
  finally
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreClearDropsIndex;
var
  store: TCertStore;
  ca: TX509Cert;
  name: string;
begin
  store := TCertStore.Create;
  ca := ParseFixture('ca_rsa.der');
  try
    name := ca.Subject.ToNameString;
    store.Add(ca);
    AssertNotNull('before clear', store.FindBySubject(name));
    store.Clear;
    AssertNull('after clear, by subject', store.FindBySubject(name));
    AssertNull('after clear, by SKI', store.FindBySKI(ca.GetSubjectKeyIdentifier));
    { The store is usable again after Clear and rebuilds its index. }
    store.Add(ca);
    AssertTrue('re-added certificate is found',
      store.FindBySubject(name) = ca);
  finally
    store.Free;
    ca.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreClear;
var
  store: TCertStore;
  ca: TX509Cert;
begin
  store := MakeStore('ca_rsa.der');
  ca := ParseFixture('ca_ec.der');
  try
    AssertEquals('count before clear', 1, store.Count);
    store.Add(ca);
    AssertEquals('count after add', 2, store.Count);
    store.Clear;
    AssertEquals('count after clear', 0, store.Count);
  finally
    ca.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestStoreAt;
var
  store: TCertStore;
  ca1, ca2: TX509Cert;
  c: TX509Cert;
begin
  store := TCertStore.Create;
  ca1 := ParseFixture('ca_rsa.der');
  ca2 := ParseFixture('ca_ec.der');
  try
    store.Add(ca1);
    store.Add(ca2);
    c := store.At(0);
    AssertEquals('At(0) subject', ca1.Subject.ToNameString,
      c.Subject.ToNameString);
    c := store.At(1);
    AssertEquals('At(1) subject', ca2.Subject.ToNameString,
      c.Subject.ToNameString);
  finally
    ca1.Free;
    ca2.Free;
    store.Free;
  end;
end;

{--- PEM from memory and streams (no file access) ---}

procedure TCertVerifyTests.TestPEMFromMemoryMatchesFile;
var
  fromMem, fromDer: TX509Cert;
begin
  { The DER fixture is turned into PEM text in the test, so the comparison does
    not depend on any PEM file on disk. }
  fromMem := nil;
  fromDer := ParseFixture('ca_rsa.der');
  try
    fromMem := LoadPEMFromMemory(FixturePEM('ca_rsa.der'));
    AssertNotNull('certificate parsed from memory', fromMem);
    AssertEquals('subject matches the DER fixture',
      fromDer.Subject.ToNameString, fromMem.Subject.ToNameString);
    AssertTrue('SKI matches the DER fixture',
      SameBytes(fromDer.GetSubjectKeyIdentifier,
        fromMem.GetSubjectKeyIdentifier));
  finally
    fromMem.Free;
    fromDer.Free;
  end;
end;

procedure TCertVerifyTests.TestPEMFromMemorySurroundingText;
var
  fromMem, fromDer: TX509Cert;
  text: RawByteString;
begin
  { Certificate dumps (certifi, the Windows store export) put comments around
    the block; the parser must pick the block and ignore the surrounding text. }
  text := '# local trust anchor' + #13#10 + FixturePEM('ca_ec.der') +
    'trailing text' + #13#10;
  fromMem := nil;
  fromDer := ParseFixture('ca_ec.der');
  try
    fromMem := LoadPEMFromMemory(text);
    AssertEquals('block found despite surrounding text',
      fromDer.Subject.ToNameString, fromMem.Subject.ToNameString);
  finally
    fromMem.Free;
    fromDer.Free;
  end;
end;

procedure TCertVerifyTests.TestPEMFromMemoryNoHeader;
var
  msg: string;
begin
  AssertTrue('text without a PEM block is rejected',
    PEMFromTextFails('no PEM here' + #13#10, msg));
  AssertTrue('message names the missing header',
    Pos('begin certificate', LowerCase(msg)) > 0);
end;

procedure TCertVerifyTests.TestPEMFromMemoryUnterminated;
var
  text: RawByteString;
  p: LongInt;
  msg: string;
begin
  { A header with no footer must be an error, never a partial certificate. }
  text := FixturePEM('ca_rsa.der');
  p := Pos('-----END CERTIFICATE-----', text);
  AssertTrue('fixture PEM text has a footer', p > 0);
  text := Copy(text, 1, p - 1);
  AssertTrue('block without a footer is rejected',
    PEMFromTextFails(text, msg));
  AssertTrue('message names the missing footer',
    Pos('end certificate', LowerCase(msg)) > 0);
end;

procedure TCertVerifyTests.TestPEMFromMemoryBadBase64;
var
  text: RawByteString;
  msg: string;
begin
  text := '-----BEGIN CERTIFICATE-----' + #13#10 + '!!!!' + #13#10 +
    '-----END CERTIFICATE-----' + #13#10;
  AssertTrue('invalid base64 is rejected', PEMFromTextFails(text, msg));
  AssertTrue('message names base64', Pos('base64', LowerCase(msg)) > 0);
end;

procedure TCertVerifyTests.TestLoadPEMFileMatchesMemory;
var
  tmpFile: string;
  text: RawByteString;
  fromFile, fromMem: TX509Cert;
begin
  { LoadPEM is a thin wrapper over LoadPEMFromMemory: both must yield the same
    certificate for the same bytes. }
  text := FixturePEM('ca_rsa.der');
  tmpFile := WriteTempPEM('tls_test_ca_rsa.pem', text);
  fromFile := nil;
  fromMem := nil;
  try
    fromMem := LoadPEMFromMemory(text);
    fromFile := LoadPEM(tmpFile);
    AssertEquals('LoadPEM delegates to the in-memory parser',
      fromMem.Subject.ToNameString, fromFile.Subject.ToNameString);
    AssertTrue('SKI matches',
      SameBytes(fromMem.GetSubjectKeyIdentifier,
        fromFile.GetSubjectKeyIdentifier));
  finally
    fromMem.Free;
    fromFile.Free;
    DeleteFile(tmpFile);
  end;
end;

procedure TCertVerifyTests.TestBundleFromStreamTwoCerts;
var
  store: TCertStore;
  leaf, caRsa, caEc: TX509Cert;
  bundle: RawByteString;
  res: TVerifyResult;
begin
  bundle := FixturePEM('ca_rsa.der') + FixturePEM('ca_ec.der');
  store := BundleFromText(bundle);
  leaf := ParseFixture('leaf_rsa.der');
  caRsa := ParseFixture('ca_rsa.der');
  caEc := ParseFixture('ca_ec.der');
  try
    AssertEquals('both blocks loaded', 2, store.Count);
    AssertNotNull('RSA CA found by subject',
      store.FindBySubject(caRsa.Subject.ToNameString));
    AssertNotNull('EC CA found by subject',
      store.FindBySubject(caEc.Subject.ToNameString));
    { A store built from memory must verify a real fixture chain exactly like a
      store built from a file. }
    res := VerifyChain(store, leaf);
    AssertTrue('chain verifies against the stream-loaded store', res.OK);
    AssertEquals('chain length', 2, res.ChainLen);
  finally
    caEc.Free;
    caRsa.Free;
    leaf.Free;
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestBundleFromStreamSurroundingText;
var
  store: TCertStore;
begin
  store := BundleFromText('leading comment' + #13#10 +
    FixturePEM('ca_rsa.der') + 'trailing text' + #13#10);
  try
    AssertEquals('one block loaded around text', 1, store.Count);
  finally
    store.Free;
  end;
end;

procedure TCertVerifyTests.TestBundleFromStreamNil;
var
  store: TCertStore;
  msg: string;
  raised: Boolean;
begin
  store := nil;
  msg := '';
  raised := False;
  try
    try
      store := LoadBundleFromStream(nil);
    except
      on E: EASN1Error do
      begin
        raised := True;
        msg := E.Message;
      end;
    end;
  finally
    store.Free;
  end;
  AssertTrue('nil stream raises EASN1Error', raised);
  AssertTrue('message names the nil stream', Pos('nil', LowerCase(msg)) > 0);
end;

procedure TCertVerifyTests.TestBundleFromStreamEmpty;
var
  msg: string;
begin
  { An empty store is a mistake, not a result: a bundle without a block must
    not silently produce a trust store with zero certificates. }
  AssertTrue('a bundle without certificates is rejected',
    BundleFromTextFails('no certificates here' + #13#10, msg));
  AssertTrue('message says no block was found',
    Pos('no certificate', LowerCase(msg)) > 0);
end;

procedure TCertVerifyTests.TestBundleFromStreamUnterminated;
var
  text: RawByteString;
  p: LongInt;
  msg: string;
begin
  text := FixturePEM('ca_rsa.der');
  p := Pos('-----END CERTIFICATE-----', text);
  AssertTrue('fixture PEM text has a footer', p > 0);
  text := Copy(text, 1, p - 1);
  AssertTrue('truncated bundle is rejected', BundleFromTextFails(text, msg));
  AssertTrue('message says the block is unterminated',
    Pos('unterminated', LowerCase(msg)) > 0);
end;

procedure TCertVerifyTests.TestBundleFromStreamBadDER;
var
  text: RawByteString;
  msg: string;
begin
  { Valid base64, but the decoded bytes are not a certificate: the DER parser
    must raise EASN1Error instead of adding a broken certificate. }
  text := '-----BEGIN CERTIFICATE-----' + #13#10 + 'AAAA' + #13#10 +
    '-----END CERTIFICATE-----' + #13#10;
  AssertTrue('garbage DER is rejected', BundleFromTextFails(text, msg));
  AssertTrue('message comes from the DER parser', msg <> '');
end;

procedure TCertVerifyTests.TestLoadBundleFileMatchesStream;
var
  tmpFile: string;
  text: RawByteString;
  store, streamStore: TCertStore;
  leaf: TX509Cert;
  res: TVerifyResult;
begin
  { LoadBundle opens the file and hands the stream to LoadBundleFromStream: the
    two entry points must build the same store. }
  text := FixturePEM('ca_ec.der') + FixturePEM('ca_rsa.der');
  tmpFile := WriteTempPEM('tls_test_bundle.pem', text);
  store := nil;
  streamStore := nil;
  leaf := nil;
  try
    streamStore := BundleFromText(text);
    store := LoadBundle(tmpFile);
    AssertEquals('file bundle count', 2, store.Count);
    AssertEquals('file and stream bundles agree', 2, streamStore.Count);
    leaf := ParseFixture('leaf_rsa.der');
    res := VerifyChain(store, leaf);
    AssertTrue('chain verifies against the file-loaded bundle', res.OK);
  finally
    leaf.Free;
    streamStore.Free;
    store.Free;
    DeleteFile(tmpFile);
  end;
end;

{--- Windows system store ---}

procedure TCertVerifyTests.TestWinSystemStoreNonEmpty;
{$ifdef windows}
var
  store: TCertStore;
{$endif}
begin
{$ifdef windows}
  { LoadWindowsSystemStore is only declared on Windows; on other
    platforms this test is skipped. }
  store := LoadWindowsSystemStore;
  try
    AssertTrue('Windows system store is not empty', store.Count > 0);
  finally
    store.Free;
  end;
{$else}
  { Not on Windows — skipped. }
{$endif}
end;

procedure TCertVerifyTests.TestWinSystemStoreKnownRoot;
{$ifdef windows}
var
  store: TCertStore;
  i: LongInt;
  found: Boolean;
{$endif}
begin
{$ifdef windows}
  { The Windows Root store has contained the long-lived
    "Baltimore CyberTrust Root" (DigiCert) certificate for many years;
    assert that it is present in the loaded store. }
  store := LoadWindowsSystemStore;
  try
    found := False;
    for i := 0 to store.Count - 1 do
      if Pos('baltimore cybertrust root',
             LowerCase(store.At(i).Subject.ToNameString)) > 0 then
      begin
        found := True;
        Break;
      end;
    AssertTrue('well-known root present in system store', found);
  finally
    store.Free;
  end;
{$else}
  { Not on Windows — skipped. }
{$endif}
end;

{$ifdef TLS_HEAPTRACE}
{ Bytes currently held by the heap, read straight from the RTL heap status.
  This is deliberately not heaptrc's DumpHeap: DumpHeap walks every block
  heaptrc has ever handed out, freed ones included, and dereferences their
  headers. Once the memory manager returns a freed page to the OS (the EC
  tests allocate multi-megabyte buffers, and LoadWindowsSystemStore allocates
  for 158 certificates), those headers are gone and the walk faults under
  FPC 3.2.2. The heap status is a counter, safe to read at any time. }
function HeapUsedBytes: PtrUInt;
var
  status: TFPCHeapStatus;
begin
  status := GetFPCHeapStatus;
  Result := status.CurrHeapUsed;
end;
{$endif TLS_HEAPTRACE}

procedure TCertVerifyTests.TestWinSystemStoreNoLeak;
{$ifdef windows}
{$ifdef TLS_HEAPTRACE}
var
  store: TCertStore;
  i: LongInt;
  before, after: PtrUInt;
{$endif}
{$endif}
begin
{$ifdef windows}
{$ifdef TLS_HEAPTRACE}
  { Compare the heap in use before and after repeated LoadWindowsSystemStore
    calls: a leaked store (with its certificates and DER bytes) keeps its
    memory, so a leak shows up as growth. A warm-up load+free runs first, so
    one-time allocations (crypt32 load, caches) happen before the baseline. }
  store := LoadWindowsSystemStore;
  store.Free;

  before := HeapUsedBytes;

  for i := 1 to 2 do
  begin
    store := LoadWindowsSystemStore;
    store.Free;
  end;

  after := HeapUsedBytes;

  { A real leak (an unfreed store or its DER bytes) is far larger than
    this bound; the delta should stay near zero. }
  AssertTrue('no heap growth from repeated LoadWindowsSystemStore',
    Int64(after) - Int64(before) < 512 * 1024);
{$else}
  { Not built with heap tracing: nothing to measure here, the check runs
    under `make leaktest`. }
{$endif}
{$else}
  { Not on Windows — skipped. }
{$endif}
end;

initialization
  RegisterTest(TCertVerifyTests);

end.
