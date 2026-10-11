unit test_ec;

{EC tests (tls.ec): P-256, P-384, ECDHE, ECDSA.
  Vectors: basic point operations, ECDHE consistency,
  ECDSA sign/verify, forgery rejection.}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TECTests = class(TTestCase)
  published
    procedure TestP256GeneratorOnCurve;
    procedure TestP384GeneratorOnCurve;
    procedure TestPointDoubleVsAdd;
    procedure TestPointNeg;
    procedure TestScalarMulSmall;
    procedure TestScalarMulOrder;
    procedure TestECDHEConsistencyP256;
    procedure TestECDHEConsistencyP384;
    procedure TestECDSASignVerifyP256;
    procedure TestECDSASignVerifyP384;
    procedure TestECDSATampered;
    procedure TestGenerateKeyPair;
    procedure TestIsOnCurveRejectsInvalid;
    procedure TestECDHVectorP256;
    procedure TestECDHVectorP384;
    procedure TestECDSAVerifyVectorP256;
    procedure TestECDSAVerifyVectorP384;
  end;

implementation

uses
  SysUtils, tls.ec, tls.bn;

{Convert string to bytes (AnsiString -> TBytes).
  Direct cast TBytes(UTF8Encode(...)) is incorrect: it reinterprets
  the string descriptor as a dynamic array and corrupts the heap.}
function StrBytes(const S: string): TBytes;
var
  i: LongInt;
begin
  SetLength(Result, Length(S));
  for i := 1 to Length(S) do
    Result[i - 1] := Byte(S[i]);
end;

{Helper function: compare two points.}
function PointsEqual(const A, B: TECPoint): Boolean;
begin
  if A.Infinity <> B.Infinity then
  begin
    Result := False;
    Exit;
  end;
  if A.Infinity then Exit;
  Result := A.X.Equal(B.X) and A.Y.Equal(B.Y);
end;

{--- Curve parameters ---}

procedure TECTests.TestP256GeneratorOnCurve;
var
  curve: TECCurve;
begin
  curve := CurveP256;
  try
    Check(IsOnCurve(curve, curve.G), 'P-256: G is on curve');
    Check(curve.N.BitLength = 256, 'P-256: N is 256 bits');
    Check(curve.P.BitLength = 256, 'P-256: p is 256 bits');
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestP384GeneratorOnCurve;
var
  curve: TECCurve;
begin
  curve := CurveP384;
  try
    Check(IsOnCurve(curve, curve.G), 'P-384: G is on curve');
    Check(curve.N.BitLength = 384, 'P-384: N is 384 bits');
    Check(curve.P.BitLength = 384, 'P-384: p is 384 bits');
  finally
    curve.Free;
  end;
end;

{--- Point operations ---}

procedure TECTests.TestPointDoubleVsAdd;
var
  curve: TECCurve;
  d1, d2: TECPoint;
begin
  curve := CurveP256;
  try
    d1 := PointDouble(curve, curve.G);
    d2 := PointAdd(curve, curve.G, curve.G);
    Check(PointsEqual(d1, d2), 'P-256: 2G == G+G');
    d1.Free;
    d2.Free;
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestPointNeg;
var
  curve: TECCurve;
  negG: TECPoint;
  sum: TECPoint;
begin
  curve := CurveP256;
  try
    negG := PointNeg(curve, curve.G);
    Check(not negG.Infinity, 'P-256: -G is not Infinity');
    Check(negG.X.Equal(curve.G.X), 'P-256: -G has same X');
    { G + (-G) = Infinity }
    sum := PointAdd(curve, curve.G, negG);
    Check(sum.Infinity, 'P-256: G + (-G) = Infinity');
    sum.Free;
    negG.Free;
  finally
    curve.Free;
  end;
end;

{--- Scalar multiplication ---}

procedure TECTests.TestScalarMulSmall;
var
  curve: TECCurve;
  k1, k2, k3: TBN;
  p1, p2, p3: TECPoint;
begin
  curve := CurveP256;
  try
    { 1*G = G }
    k1 := TBN.FromQWord(1);
    p1 := ScalarMul(curve, k1, curve.G);
    Check(PointsEqual(p1, curve.G), 'P-256: 1*G == G');
    p1.Free;
    k1.Free;

    { 2*G = G+G }
    k2 := TBN.FromQWord(2);
    p2 := ScalarMul(curve, k2, curve.G);
    p3 := PointDouble(curve, curve.G);
    Check(PointsEqual(p2, p3), 'P-256: 2*G == PointDouble(G)');
    p2.Free;
    p3.Free;
    k2.Free;

    { 3*G = 2*G + G }
    k3 := TBN.FromQWord(3);
    p2 := ScalarMul(curve, k3, curve.G);
    p3 := PointDouble(curve, curve.G);
    p3 := PointAdd(curve, p3, curve.G);
    Check(PointsEqual(p2, p3), 'P-256: 3*G == 2*G + G');
    p2.Free;
    p3.Free;
    k3.Free;
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestScalarMulOrder;
var
  curve: TECCurve;
  result: TECPoint;
begin
  curve := CurveP256;
  try
    { N*G = Infinity (N is the order of the base point) }
    result := ScalarMul(curve, curve.N, curve.G);
    Check(result.Infinity, 'P-256: N*G = Infinity');
    result.Free;
  finally
    curve.Free;
  end;
end;

{--- ECDHE: consistency ---}

procedure TECTests.TestECDHEConsistencyP256;
var
  curve: TECCurve;
  keyA, keyB: TECKeypair;
  sharedA, sharedB: TECPoint;
begin
  curve := CurveP256;
  try
    keyA := GenerateKeyPair(curve);
    keyB := GenerateKeyPair(curve);

    {Both ends compute the shared secret }
    sharedA := ComputeSharedSecret(curve, keyA.PrivateKey, keyB.PublicKey);
    sharedB := ComputeSharedSecret(curve, keyB.PrivateKey, keyA.PublicKey);

    Check(PointsEqual(sharedA, sharedB), 'P-256: ECDHE shared secrets match');
    Check(not sharedA.Infinity, 'P-256: shared secret is not Infinity');
    Check(IsOnCurve(curve, sharedA), 'P-256: shared secret on curve');

    sharedA.Free;
    sharedB.Free;
    keyA.Free;
    keyB.Free;
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestECDHEConsistencyP384;
var
  curve: TECCurve;
  keyA, keyB: TECKeypair;
  sharedA, sharedB: TECPoint;
begin
  curve := CurveP384;
  try
    keyA := GenerateKeyPair(curve);
    keyB := GenerateKeyPair(curve);

    sharedA := ComputeSharedSecret(curve, keyA.PrivateKey, keyB.PublicKey);
    sharedB := ComputeSharedSecret(curve, keyB.PrivateKey, keyA.PublicKey);

    Check(PointsEqual(sharedA, sharedB), 'P-384: ECDHE shared secrets match');
    Check(not sharedA.Infinity, 'P-384: shared secret is not Infinity');
    Check(IsOnCurve(curve, sharedA), 'P-384: shared secret on curve');

    sharedA.Free;
    sharedB.Free;
    keyA.Free;
    keyB.Free;
  finally
    curve.Free;
  end;
end;

{--- ECDSA: sign and verify ---}

procedure TECTests.TestECDSASignVerifyP256;
var
  curve: TECCurve;
  key: TECKeypair;
  msg: TBytes;
  sig: TECDsaSig;
begin
  curve := CurveP256;
  try
    key := GenerateKeyPair(curve);
    msg := StrBytes('ECDSA P-256 test message');
    sig := ECDSASign(curve, key.PrivateKey, msg);
    Check(sig.R <> nil, 'ECDSA P-256: R generated');
    Check(sig.S <> nil, 'ECDSA P-256: S generated');
    Check(not sig.R.IsZero, 'ECDSA P-256: R != 0');
    Check(not sig.S.IsZero, 'ECDSA P-256: S != 0');
    Check(sig.R.Compare(curve.N) < 0, 'ECDSA P-256: R < N');
    Check(sig.S.Compare(curve.N) < 0, 'ECDSA P-256: S < N');
    Check(ECDSAVerify(curve, key.PublicKey, msg, sig),
      'ECDSA P-256: valid signature verifies');
    sig.Free;
    key.Free;
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestECDSASignVerifyP384;
var
  curve: TECCurve;
  key: TECKeypair;
  msg: TBytes;
  sig: TECDsaSig;
begin
  curve := CurveP384;
  try
    key := GenerateKeyPair(curve);
    msg := StrBytes('ECDSA P-384 test message');
    sig := ECDSASign(curve, key.PrivateKey, msg);
    Check(sig.R <> nil, 'ECDSA P-384: R generated');
    Check(sig.S <> nil, 'ECDSA P-384: S generated');
    Check(not sig.R.IsZero, 'ECDSA P-384: R != 0');
    Check(not sig.S.IsZero, 'ECDSA P-384: S != 0');
    Check(sig.R.Compare(curve.N) < 0, 'ECDSA P-384: R < N');
    Check(sig.S.Compare(curve.N) < 0, 'ECDSA P-384: S < N');
    Check(ECDSAVerify(curve, key.PublicKey, msg, sig),
      'ECDSA P-384: valid signature verifies');
    sig.Free;
    key.Free;
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestECDSATampered;
var
  curve: TECCurve;
  key: TECKeypair;
  msg, badMsg: TBytes;
  sig, tampered: TECDsaSig;
begin
  curve := CurveP256;
  try
    key := GenerateKeyPair(curve);
    msg := StrBytes('original message');
    sig := ECDSASign(curve, key.PrivateKey, msg);

    {Message forgery }
    badMsg := StrBytes('tampered message');
    Check(not ECDSAVerify(curve, key.PublicKey, badMsg, sig),
      'ECDSA: tampered message rejected');

    {Signature forgery: S -> S+1 }
    tampered := TECDsaSig.Create;
    tampered.R := sig.R.Clone;
    tampered.S := sig.S.ModAdd(TBN.FromQWord(1), curve.N);
    Check(not ECDSAVerify(curve, key.PublicKey, msg, tampered),
      'ECDSA: tampered signature rejected');
    tampered.Free;

    sig.Free;
    key.Free;
  finally
    curve.Free;
  end;
end;

{--- Key generation ---}

procedure TECTests.TestGenerateKeyPair;
var
  curve: TECCurve;
  key: TECKeypair;
  pub: TECPoint;
begin
  curve := CurveP256;
  try
    key := GenerateKeyPair(curve);
    Check(key.PrivateKey <> nil, 'KeyPair: private key generated');
    Check(not key.PrivateKey.IsZero, 'KeyPair: private key != 0');
    Check(key.PrivateKey.Compare(curve.N) < 0, 'KeyPair: private key < N');
    Check(IsOnCurve(curve, key.PublicKey), 'KeyPair: public key on curve');

    {Check: pub = priv * G }
    pub := ScalarMul(curve, key.PrivateKey, curve.G);
    Check(PointsEqual(pub, key.PublicKey), 'KeyPair: pub = priv * G');
    pub.Free;
    key.Free;
  finally
    curve.Free;
  end;
end;

{--- IsOnCurve: invalid point rejection ---}

procedure TECTests.TestIsOnCurveRejectsInvalid;
var
  curve: TECCurve;
  badPoint: TECPoint;
begin
  curve := CurveP256;
  try
    {Point (1, 2) does not lie on curve P-256 }
    badPoint := TECPoint.CreateFromXY(
      TBN.FromQWord(1),
      TBN.FromQWord(2));
    Check(not IsOnCurve(curve, badPoint), 'P-256: (1,2) not on curve');
    badPoint.Free;
  finally
    curve.Free;
  end;
end;

{--- Fixed ECDH vectors (RFC 5903) ---}

procedure TECTests.TestECDHVectorP256;
var
  curve: TECCurve;
  i, r: TBN;
  pubA, pubB, sharedA, sharedB: TECPoint;
  expPubA, expPubB, expShared: TECPoint;
begin
  curve := CurveP256;
  try
    { RFC 5903 §8.1: ECDH P-256 }
    i := TBN.CreateFromHex('C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433');
    r := TBN.CreateFromHex('C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53');

    expPubA := TECPoint.CreateFromXY(
      TBN.CreateFromHex('DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180'),
      TBN.CreateFromHex('5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3'));
    expPubB := TECPoint.CreateFromXY(
      TBN.CreateFromHex('D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63'),
      TBN.CreateFromHex('56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB'));
    expShared := TECPoint.CreateFromXY(
      TBN.CreateFromHex('D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE'),
      TBN.CreateFromHex('522BDE0AF0D8585B8DEF9C183B5AE38F50235206A8674ECB5D98EDB20EB153A2'));

    { pubA = i*G, pubB = r*G }
    pubA := ScalarMul(curve, i, curve.G);
    pubB := ScalarMul(curve, r, curve.G);
    Check(PointsEqual(pubA, expPubA), 'ECDH P-256: i*G matches expected');
    Check(PointsEqual(pubB, expPubB), 'ECDH P-256: r*G matches expected');

    { sharedA = i*(r*G), sharedB = r*(i*G) }
    sharedA := ScalarMul(curve, i, pubB);
    sharedB := ScalarMul(curve, r, pubA);
    Check(PointsEqual(sharedA, sharedB), 'ECDH P-256: shared secrets match');
    Check(PointsEqual(sharedA, expShared), 'ECDH P-256: shared secret matches expected');

    pubA.Free; pubB.Free;
    sharedA.Free; sharedB.Free;
    expPubA.Free; expPubB.Free; expShared.Free;
    i.Free; r.Free;
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestECDHVectorP384;
var
  curve: TECCurve;
  i, r: TBN;
  pubA, pubB, sharedA, sharedB: TECPoint;
  expPubA, expPubB, expShared: TECPoint;
begin
  curve := CurveP384;
  try
    { RFC 5903 §8.2: ECDH P-384 }
    i := TBN.CreateFromHex(
      '099F3C7034D4A2C699884D73A375A67F' +
      '7624EF7C6B3C0F160647B67414DCE655' +
      'E35B538041E649EE3FAEF896783AB194');
    r := TBN.CreateFromHex(
      '41CB0779B4BDB85D47846725FBEC3C94' +
      '30FAB46CC8DC5060855CC9BDA0AA2942' +
      'E0308312916B8ED2960E4BD55A7448FC');

    expPubA := TECPoint.CreateFromXY(
      TBN.CreateFromHex(
        '667842D7D180AC2CDE6F74F37551F557' +
        '55C7645C20EF73E31634FE72B4C55EE6' +
        'DE3AC808ACB4BDB4C88732AEE95F41AA'),
      TBN.CreateFromHex(
        '9482ED1FC0EEB9CAFC4984625CCFC23F' +
        '65032149E0E144ADA024181535A0F38E' +
        'EB9FCFF3C2C947DAE69B4C634573A81C'));
    expPubB := TECPoint.CreateFromXY(
      TBN.CreateFromHex(
        'E558DBEF53EECDE3D3FCCFC1AEA08A89' +
        'A987475D12FD950D83CFA41732BC509D' +
        '0D1AC43A0336DEF96FDA41D0774A3571'),
      TBN.CreateFromHex(
        'DCFBEC7AACF3196472169E838430367F' +
        '66EEBE3C6E70C416DD5F0C68759DD1FF' +
        'F83FA40142209DFF5EAAD96DB9E6386C'));
    expShared := TECPoint.CreateFromXY(
      TBN.CreateFromHex(
        '11187331C279962D93D604243FD592CB' +
        '9D0A926F422E47187521287E7156C5C4' +
        'D603135569B9E9D09CF5D4A270F59746'),
      TBN.CreateFromHex(
        'A2A9F38EF5CAFBE2347CF7EC24BDD5E6' +
        '24BC93BFA82771F40D1B65D06256A852' +
        'C983135D4669F8792F2C1D55718AFBB4'));

    { pubA = i*G, pubB = r*G }
    pubA := ScalarMul(curve, i, curve.G);
    pubB := ScalarMul(curve, r, curve.G);
    Check(PointsEqual(pubA, expPubA), 'ECDH P-384: i*G matches expected');
    Check(PointsEqual(pubB, expPubB), 'ECDH P-384: r*G matches expected');

    { sharedA = i*(r*G), sharedB = r*(i*G) }
    sharedA := ScalarMul(curve, i, pubB);
    sharedB := ScalarMul(curve, r, pubA);
    Check(PointsEqual(sharedA, sharedB), 'ECDH P-384: shared secrets match');
    Check(PointsEqual(sharedA, expShared), 'ECDH P-384: shared secret matches expected');

    pubA.Free; pubB.Free;
    sharedA.Free; sharedB.Free;
    expPubA.Free; expPubB.Free; expShared.Free;
    i.Free; r.Free;
  finally
    curve.Free;
  end;
end;

{--- Fixed ECDSA vectors (RFC 4754) ---}

procedure TECTests.TestECDSAVerifyVectorP256;
var
  curve: TECCurve;
  w: TBN;
  pub, expPub: TECPoint;
  sig: TECDsaSig;
  msg: TBytes;
begin
  curve := CurveP256;
  try
    { RFC 4754 §8.1: ECDSA P-256, message "abc" }
    w := TBN.CreateFromHex('DC51D3866A15BACDE33D96F992FCA99DA7E6EF0934E7097559C27F1614C88A7F');
    expPub := TECPoint.CreateFromXY(
      TBN.CreateFromHex('2442A5CC0ECD015FA3CA31DC8E2BBC70BF42D60CBCA20085E0822CB04235E970'),
      TBN.CreateFromHex('6FC98BD7E50211A4A27102FA3549DF79EBCB4BF246B80945CDDFE7D509BBFD7D'));

    { pub = w*G must match the expected }
    pub := ScalarMul(curve, w, curve.G);
    Check(PointsEqual(pub, expPub), 'ECDSA P-256: w*G matches expected public key');

    sig := TECDsaSig.Create;
    sig.R := TBN.CreateFromHex('CB28E0999B9C7715FD0A80D8E47A77079716CBBF917DD72E97566EA1C066957C');
    sig.S := TBN.CreateFromHex('86FA3BB4E26CAD5BF90B7F81899256CE7594BB1EA0C89212748BFF3B3D5B0315');

    msg := StrBytes('abc');
    Check(ECDSAVerify(curve, pub, msg, sig),
      'ECDSA P-256: RFC 4754 vector verifies');

    sig.Free;
    pub.Free;
    expPub.Free;
    w.Free;
  finally
    curve.Free;
  end;
end;

procedure TECTests.TestECDSAVerifyVectorP384;
var
  curve: TECCurve;
  w: TBN;
  pub, expPub: TECPoint;
  sig: TECDsaSig;
  msg: TBytes;
begin
  curve := CurveP384;
  try
    { RFC 4754 §8.2: ECDSA P-384, message "abc" }
    w := TBN.CreateFromHex(
      '0BEB646634BA87735D77AE4809A0EBEA' +
      '865535DE4C1E1DCB692E84708E81A5AF' +
      '62E528C38B2A81B35309668D73524D9F');
    expPub := TECPoint.CreateFromXY(
      TBN.CreateFromHex(
        '96281BF8DD5E0525CA049C048D345D30' +
        '82968D10FEDF5C5ACA0C64E6465A97EA' +
        '5CE10C9DFEC21797415710721F437922'),
      TBN.CreateFromHex(
        '447688BA94708EB6E2E4D59F6AB6D7ED' +
        'FF9301D249FE49C33096655F5D502FAD' +
        '3D383B91C5E7EDAA2B714CC99D5743CA'));

    { pub = w*G must match the expected }
    pub := ScalarMul(curve, w, curve.G);
    Check(PointsEqual(pub, expPub), 'ECDSA P-384: w*G matches expected public key');

    sig := TECDsaSig.Create;
    sig.R := TBN.CreateFromHex(
      'FB017B914E29149432D8BAC29A514640' +
      'B46F53DDAB2C69948084E2930F1C8F7E' +
      '08E07C9C63F2D21A07DCB56A6AF56EB3');
    sig.S := TBN.CreateFromHex(
      'B263A1305E057F984D38726A1B468741' +
      '09F417BCA112674C528262A40A629AF1' +
      'CBB9F516CE0FA7D2FF630863A00E8B9F');

    msg := StrBytes('abc');
    Check(ECDSAVerify(curve, pub, msg, sig),
      'ECDSA P-384: RFC 4754 vector verifies');

    sig.Free;
    pub.Free;
    expPub.Free;
    w.Free;
  finally
    curve.Free;
  end;
end;

initialization
  RegisterTest(TECTests);

end.
