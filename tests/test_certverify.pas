{ SPDX-License-Identifier: Apache-2.0 }
unit test_certverify;

{ Certificate chain verification tests (tls.certstore):
  VerifyChain, VerifySignature, CheckValidity, WildcardMatch, CertMatchesHost,
  TCertStore (Add/FindBySubject/FindBySKI/Clear),
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
    procedure TestStoreClear;
    procedure TestStoreAt;
    { --- Windows system store (skipped off-Windows) --- }
    procedure TestWinSystemStoreNonEmpty;
    procedure TestWinSystemStoreKnownRoot;
    procedure TestWinSystemStoreNoLeak;
  end;

implementation

uses
  SysUtils, Classes, DateUtils,
{$ifdef TLS_HEAPTRACE}
  { Heap tracing is only linked in when the runner is built with
    -dTLS_HEAPTRACE (`make leaktest`): heaptrc slows every allocation down,
    so it stays out of the normal `make test` run. }
  heaptrc,
{$endif}
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
{ Read the "unfreed memory blocks" byte count from a heaptrc DumpHeap
  report file. Returns -1 if the file is missing or the line is absent. }
function ReadUnfreedBytes(const AFile: string): Int64;
var
  sl: TStringList;
  i, start, colon: Integer;
  num: string;
begin
  Result := -1;
  if not FileExists(AFile) then Exit;
  sl := TStringList.Create;
  try
    sl.LoadFromFile(AFile);
    for i := 0 to sl.Count - 1 do
    begin
      start := Pos('unfreed memory blocks : ', sl[i]);
      if start > 0 then
      begin
        Inc(start, Length('unfreed memory blocks : '));
        colon := start;
        while (colon <= Length(sl[i])) and (sl[i][colon] <> ' ') do
          Inc(colon);
        num := Copy(sl[i], start, colon - start);
        TryStrToInt64(num, Result);
        Exit;
      end;
    end;
  finally
    sl.Free;
  end;
end;
{$endif TLS_HEAPTRACE}

procedure TCertVerifyTests.TestWinSystemStoreNoLeak;
{$ifdef windows}
{$ifdef TLS_HEAPTRACE}
var
  store: TCertStore;
  i: LongInt;
  before, after: Int64;
  tmp, beforeFile, afterFile, sinkFile: string;
{$endif}
{$endif}
begin
{$ifdef windows}
{$ifdef TLS_HEAPTRACE}
  { heaptrc (linked in by `make leaktest`) tracks every heap allocation. We
    compare the bytes held in unfreed blocks before and after repeated
    LoadWindowsSystemStore calls: a leak would show up as a growing unfreed
    total. A warm-up load+free runs first so one-time allocations (crypt32
    load, etc.) happen before the baseline. heaptrc keeps its output file
    open, so after each DumpHeap the output is re-pointed to a scratch file,
    which closes the dump before it is read back. }
  tmp := IncludeTrailingPathDelimiter(GetTempDir);
  beforeFile := tmp + 'tls_winstore_leak_before.log';
  afterFile := tmp + 'tls_winstore_leak_after.log';
  sinkFile := tmp + 'tls_winstore_leak_sink.log';
  DeleteFile(sinkFile);
  store := LoadWindowsSystemStore;
  store.Free;

  DeleteFile(beforeFile);
  SetHeapTraceOutput(beforeFile);
  DumpHeap;
  SetHeapTraceOutput(sinkFile);
  before := ReadUnfreedBytes(beforeFile);

  for i := 1 to 2 do
  begin
    store := LoadWindowsSystemStore;
    store.Free;
  end;

  DeleteFile(afterFile);
  SetHeapTraceOutput(afterFile);
  DumpHeap;
  SetHeapTraceOutput(sinkFile);
  after := ReadUnfreedBytes(afterFile);

  AssertTrue('heaptrc baseline captured', before >= 0);
  AssertTrue('heaptrc after captured', after >= 0);
  { A real leak (an unfreed store or its DER bytes) is far larger than
    this bound; the delta should stay near zero. }
  AssertTrue('no heap growth from repeated LoadWindowsSystemStore',
    (after - before) < 512 * 1024);
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
