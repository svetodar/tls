{ SPDX-License-Identifier: Apache-2.0 }
unit test_rsa;

{RSA tests (tls.rsa): key generation, encryption, PKCS#1 v1.5 and PSS signatures.
  Fixed vectors: NIST CAVP RSADP (SP 800-56B) and RSASP1 (FIPS 186-4).}

{$mode objfpc}{$H+}

interface

uses
  fpcunit, testregistry;

type
  TRSATests = class(TTestCase)
  published
    procedure TestIsPrime;
    procedure TestGenerateAndRoundTrip;
    procedure TestPKCS1v15SignVerify;
    procedure TestPKCS1v15Tampered;
    procedure TestPSSSignVerify;
    procedure TestPSSTampered;
    procedure TestOidToDerBytes;
    procedure TestPKCS1v15EncodeDecode;
    procedure TestRSADPVectors;
    procedure TestRSASP1Vectors;
  end;

implementation

uses
  SysUtils, tls.rsa, tls.bn, tls.sha2;

procedure TRSATests.TestIsPrime;
begin
  Check(IsPrime(TBN.FromQWord(2)), '2 is prime');
  Check(IsPrime(TBN.FromQWord(3)), '3 is prime');
  Check(IsPrime(TBN.FromQWord(5)), '5 is prime');
  Check(IsPrime(TBN.FromQWord(17)), '17 is prime');
  Check(IsPrime(TBN.FromQWord(97)), '97 is prime');
  Check(IsPrime(TBN.FromQWord(7919)), '7919 is prime');
  Check(IsPrime(TBN.FromQWord(104729)), '104729 is prime');
  Check(not IsPrime(TBN.FromQWord(4)), '4 is not prime');
  Check(not IsPrime(TBN.FromQWord(9)), '9 is not prime');
  Check(not IsPrime(TBN.FromQWord(15)), '15 is not prime');
  Check(not IsPrime(TBN.FromQWord(100)), '100 is not prime');
  Check(not IsPrime(TBN.FromQWord(561)), '561 (Carmichael) is not prime');
  Check(not IsPrime(TBN.FromQWord(1729)), '1729 is not prime');
end;

procedure TRSATests.TestGenerateAndRoundTrip;
var
  key: TRSAKey;
  msg, enc, dec: TBN;
begin
  key := TRSAKey.Create;
  try
    key.Generate(512);
    Check(key.N <> nil, 'N generated');
    Check(key.E <> nil, 'E generated');
    Check(key.D <> nil, 'D generated');
    Check(key.P <> nil, 'P generated');
    Check(key.Q <> nil, 'Q generated');
    Check(key.N.BitLength >= 510, 'N is ~512 bits');

    msg := TBN.FromHex('DEADBEEF0123456789ABCDEF');
    enc := key.PublicEncrypt(msg);
    dec := key.PrivateDecrypt(enc);
    Check(dec.Equal(msg), 'PublicEncrypt/PrivateDecrypt round-trip');
  finally
    key.Free;
  end;
end;

procedure TRSATests.TestPKCS1v15SignVerify;
var
  key: TRSAKey;
  hash: TBytes;
  sig: TBN;
begin
  key := TRSAKey.Create;
  try
    key.Generate(512);
    hash := SHA256Str('test message');
    sig := key.SignPKCS1v15(hash, '1.2.840.113549.1.1.11');
    Check(key.VerifyPKCS1v15(sig, hash, '1.2.840.113549.1.1.11'),
      'PKCS1v15: valid signature verifies');
  finally
    key.Free;
  end;
end;

procedure TRSATests.TestPKCS1v15Tampered;
var
  key: TRSAKey;
  hash, badHash: TBytes;
  sig: TBN;
begin
  key := TRSAKey.Create;
  try
    key.Generate(512);
    hash := SHA256Str('test message');
    sig := key.SignPKCS1v15(hash, '1.2.840.113549.1.1.11');
    badHash := SHA256Str('different message');
    Check(not key.VerifyPKCS1v15(sig, badHash, '1.2.840.113549.1.1.11'),
      'PKCS1v15: tampered hash rejected');
    Check(not key.VerifyPKCS1v15(sig, hash, '1.2.840.113549.1.1.12'),
      'PKCS1v15: wrong OID rejected');
  finally
    key.Free;
  end;
end;

procedure TRSATests.TestPSSSignVerify;
var
  key: TRSAKey;
  hash: TBytes;
  sig: TBN;
begin
  key := TRSAKey.Create;
  try
    key.Generate(1024);
    hash := SHA256Str('pss test');
    sig := key.SignPSS(hash);
    Check(key.VerifyPSS(sig, hash),
      'PSS: valid signature verifies');
  finally
    key.Free;
  end;
end;

procedure TRSATests.TestPSSTampered;
var
  key: TRSAKey;
  hash, badHash: TBytes;
  sig: TBN;
begin
  key := TRSAKey.Create;
  try
    key.Generate(1024);
    hash := SHA256Str('pss test');
    sig := key.SignPSS(hash);
    badHash := SHA256Str('tampered');
    Check(not key.VerifyPSS(sig, badHash),
      'PSS: tampered hash rejected');
  finally
    key.Free;
  end;
end;

procedure TRSATests.TestOidToDerBytes;
var
  b: TBytes;
begin
  b := OidToDerBytes('1.2.840.113549.1.1.11');
  Check(Length(b) = 9, 'SHA-256 OID length = 9');
  Check(b[0] = $2A, 'SHA-256 OID byte0');
  Check(b[1] = $86, 'SHA-256 OID byte1');
  Check(b[2] = $48, 'SHA-256 OID byte2');
  Check(b[3] = $86, 'SHA-256 OID byte3');
  Check(b[4] = $F7, 'SHA-256 OID byte4');
  Check(b[5] = $0D, 'SHA-256 OID byte5');
  Check(b[6] = $01, 'SHA-256 OID byte6');
  Check(b[7] = $01, 'SHA-256 OID byte7');
  Check(b[8] = $0B, 'SHA-256 OID byte8');

  b := OidToDerBytes('1.2.840.113549.1.1.12');
  Check(Length(b) = 9, 'SHA-384 OID length = 9');
  Check(b[8] = $0C, 'SHA-384 OID last byte');
end;

procedure TRSATests.TestPKCS1v15EncodeDecode;
var
  digest: TBytes;
  em: TBN;
  emBytes: TBytes;
  decoded: TBytes;
  modLen: LongInt;
  i: LongInt;
  match: Boolean;
begin
  digest := SHA256Str('hello world');
  modLen := 64;
  em := PKCS1v15Encode(digest, '1.2.840.113549.1.1.11', modLen);
  emBytes := em.ToBytes(True);
  Check(Length(emBytes) <= modLen, 'EM fits in modulus');
  decoded := PKCS1v15Decode(em, '1.2.840.113549.1.1.11', modLen);
  Check(decoded <> nil, 'Decode returns non-nil');
  Check(Length(decoded) = Length(digest), 'Decoded length matches');
  match := True;
  for i := 0 to Length(digest) - 1 do
    if decoded[i] <> digest[i] then
      match := False;
  Check(match, 'Decoded digest matches');
  Check(PKCS1v15Decode(em, '1.2.840.113549.1.1.12', modLen) = nil,
    'Wrong OID rejected');
end;

{--- NIST CAVP fixed vectors ---}

{ RSADP (SP 800-56B): RSA Decryption Primitive.
  Verify c^d mod n = k for 5 vectors (1024/2048 bits).}
procedure TRSATests.TestRSADPVectors;
var
  n, d, c, k, result: TBN;
begin
  { --- RSADP #0 (1024-bit) --- }
  n := TBN.FromHex('d0b750c8554b64c7a9d34d068e020fb52fea1b39c47971a359f0eec5da0437ea3fc94597d8dbff5444f6ce5a3293ac89b1eebb3f712b3ad6a06386e6401985e19898715b1ea32ac03456fe1796d31ed4af389f4f675c23c421a125491e740fdac4322ec2d46ec945ddc349227b492191c9049145fb2f8c2998c486a840eac4d3');
  d := TBN.FromHex('27b7119a09edb827c13418c820b522a1ee08de0e4bb28106db6bb91498a3b361ab293af83fefcdd8a6bd2134ca4afacf64a0e33c014f48f47530f8847cc9185cbedec0d9238c8f1d5498f71c7c0cff48dc213421742e34350ca94007753cc0e5a783264cf49ff644ffea94253cfe86859acd2a2276ca4e7215f8ebaa2f188f51');
  c := TBN.FromHex('6cf87c6a65925df6719eef5f1262edc6f8a0a0a0d21c535c64580745d9a268a95b50ff3be24ba8b649ca47c3a760b71ddc3903f36aa1d98e87c53b3370be784bffcb5bc180dea2acc15bb12e681c889b89b8f3de78050019dcdbb68c051b04b880f0f8c4e855321ffed89767fc9d4a8a27a5d82ba450b2478c21e11843c2f539');
  k := TBN.FromHex('5c7bce723cf4da053e503147242c60678c67e8c22467f0336b6d5c31f14088cb3d6cefb648db132cb32e95092f3d9bcd1cab51e68bd3a892ab359cdff556785ae06708633d39a0618f9d6d70f6bdeb6b777e7dd9acc41f19560c71a68479c8a07b14fb9a4c765fd292ae56dd2f2143b62649cc70fb604fdc5cc1ade6e29de235');
  result := c.ModPow(d, n);
  Check(result.Equal(k), 'RSADP #0: c^d mod n = k (1024-bit)');

  { --- RSADP #1 (1024-bit) --- }
  n := TBN.FromHex('c8883f0573e9a5f512fb65ed0adf2649b03237edf4faa6b259f89d7ed59d30d6fe052ef8dd68c9d672c9ac4ddb1edcf0102b8214dbd8478c7c87dfca0ad26cf5a9f73701e8525e059d1be2c568b42e39d0549bb772ed43135a39c79071b76e6604a05523be68ffa9b1c28f37f30bdb0bf78ddd85daff7054c9ab471bb483a065');
  d := TBN.FromHex('032ed7f38db0a3f026aa85f35c8835d8add52e62f631d5a99a6b6fe407c3711dc429cb5846b40fe560fd82b18a83bad21209382584e635ec21b38299d1651797246d69cbc0e23e674ce70a905109583a5b2ec87b0de762594c813f89c06d3ee2a19bfa0ffd78c26bb29d426f7647020434341b4735a2972b6aa653c662d710e7');
  c := TBN.FromHex('49099483331a355f9e1e9446231f1f36d9a7cba76b83c06c6ec752dbf112342d5513e8285f4c7afb8b166e69a3e6f72991ce6a8d7247f163eb2d8419c00b1524a2990ba14983f23dc36c71530c337c55de75ca6dca538a64887552c28c4e5837d9a2e4391a4605efef28844e858f168269a3d58f9e2ff138eda6a3207c64632f');
  k := TBN.FromHex('c847d03e2e5fa8ae543e35e47143bc6d0c172889418e2161398171222cd9aeac4c70f4e1e96425fe555fd492b8a5b45ae9a0af6ba22df257b6b354705819c9018c724032d54da56821f945d8fab1eada5107494a4e72d5ce98fccf03a8af05331f2a7121a0a9201494d1ce896a104323fd475d3e33d570d6cc426ea7f2b0646f');
  result := c.ModPow(d, n);
  Check(result.Equal(k), 'RSADP #1: c^d mod n = k (1024-bit)');

  { --- RSADP #2 (2048-bit) --- }
  n := TBN.FromHex('bd74c62141cc4cf8228224d7e2de0d52b51e67e2d43676249470304d30d662ea3d6e5225101317369ae1de6bab944cde823d182cc0177f1905ca843611a2f67b9c32f975feccc8e9422b05d8831f0a013d8f9c68b1b8c25e5925d516414d34d57d84f38311bbebc7f1faf6548de9968e871f8e7e16b1fae5545d3f3cf04121b7');
  d := TBN.FromHex('0217f64f638419c8741b4b98a0678e40cb0e0c703a8c823224d88be40ea4d2bb8183233c9be2760ccff280a51ba714646344885212569ee9aaa80e610f2de30f42ef26a55bbb2bdbf31b9238036cb387be57067116e97386e9aac9cf2695e266873ef2944a4b010804408b039bd543a7f622983efdf56ec4ebb151ad80d5f4cf');
  c := TBN.FromHex('97c4c0f9b86bf131e695932e891fddd63c46e87373bd6d6261fdd10f19dd5e21f362d4f131d82041e2216b2b074e5657f56c8471faa05ada4377029efd77b6a7bbfa3b30183cab7c9db278c7e59dae7dfee078aa130ee6b148c8ed42e646b086b833fd9cb5be1b49deeec3eb6a356caf2149cc04062f9b5038989ae11a71d426');
  k := TBN.FromHex('3ed4d56d770a47b5a90c22d75fdc71b31a1fd54435de4375a06002cf13db50a012c5f5e5d94b7cfc85b5b3d9f5701d5d3aa75b5900ee0b09091c67d8ca33871228e041ae16138b1343bc3003af4aa21ff701d623dc40fcc0bad9848ec41be3a68ef8f9fdfbdbbd6df98f571a9d3fb8fad7c1e00ae3e72501a1182463b9971298');
  result := c.ModPow(d, n);
  Check(result.Equal(k), 'RSADP #2: c^d mod n = k (2048-bit)');

  { --- RSADP #3 (2048-bit) --- }
  n := TBN.FromHex('8ae197e5bb30172ff378eb37f08709aa87b73802a027617fe959439399b3a0ae58ee46ec6e9fc3f29fa03ec08db9d16371dec03e9a6422d539cb4deb2dee52fd4dc1978f72cce77726886ce81c62b880f29623758aa615c65e500101d0980b2fba68e466a2545aeae7a3bfa6a549ce9a62ad7f171385feccbdfa902494d78443');
  d := TBN.FromHex('2cd9eb9d91370fa049e778dc7b2eed16032a396d96d391f58df1c269ca2b354451bd13ffb929df047e356617f6d7394ca30622651d84823e7400805ea20d4eac617146eb8b11d0e53048c74ec02037e8b58946d95f10505dcb9dc468e5ade82fdec0edfafe09dd0bd2d13a07dbe96b741554b4806f4beeaa50562a1040e024af');
  c := TBN.FromHex('3b888227ed25d10630057877e11ee54576a1d645402dbf2cec426ba350f8e59e65f199e98f8cb703255bd8302dd8e4ca675333d88e2ff2e2da4ec903c9caba3f1fe64d172b44ea5b4d588640b51c82b26d05cfeb9a365745fff5984cc25b9218734fe4da4ab532b4b0e2c9ce015386a6919ff4a7edabb4fe631d22a9c41335d0');
  k := TBN.FromHex('19e5d33241cbc43c21d1c3eb21b9a48b2db1930c78b38321487212f82859cc5b989b77ee23c49de771ab9603ccf0631abeecabb90b4c7178b86db5aee994ed427fdabddf89def7643d0903379f1bb69f575d09472648d7050a77e8c06909dcd51b2edc194d7a9d632b210e883d2710a155f15b3cbb156cbdd7135024f671901c');
  result := c.ModPow(d, n);
  Check(result.Equal(k), 'RSADP #3: c^d mod n = k (2048-bit)');

  { --- RSADP #4 (2048-bit) --- }
  n := TBN.FromHex('b101bd9c2458804386e23d1b7a521430569b4f49029e87db288892159834d827bb2083272bb85bd5934e7ef6d458e40a8549ff338a7e6d84789207b15f824e39ebaefd2076f55c69121e9a90aab7c662734b50b4473c3342f7c57fdb6b891c2697eefe0917d20db468defef1d7acbec6f88390ccc6344b48b273a7d51081c4a5');
  d := TBN.FromHex('22107d6ec7bdf09c9f688448bfae94cdf7268bd72afc96e4ad9d7501b04afe69df7b4274fe90b8f35e1cbf03b71a097489c619d2b87ef0024a6f2c2f1bf7f827c891bf7e42bf1f9a3b973ff0305f5de643092da60d9f039b51902e1b07990d5f3e1f360de4084e92f9bbfe95a51105dd58c266384c5ec815d380eea8dfb248af');
  c := TBN.FromHex('400e4f3d5498a2b5d695618f4599a80639e875b049d1af692d3d678c20875d6a888ec6f4d9094cbbb71b571b5b288bb237e69217ddb71bc91d3622666d0f721e8f1569666d8efcf148d1fadc11149529177f1e6ee38510ce607350294049b3909acac1fcd8cfb93fd0e0d53a3105ce5121daa31c24e2975f401d783d5fdd27a8');
  k := TBN.FromHex('53fe9fdbc8de44c4a0c073f4ed9ba8b2769174fa1c29814528221c223e4dcd42435f3ca8db857a8cc056dd8155369c45d5d6339ace54b77ae4ccdd8180ec0a251c5599cdc5187c5a055ba1cd97e2ac6f43d6a85bce3646dcd2e0342a6d3a165febfae367b79c719ede2940345c55ae9d6106d4f94be9b03cb561f3759304792b');
  result := c.ModPow(d, n);
  Check(result.Equal(k), 'RSADP #4: c^d mod n = k (2048-bit)');
end;

{ RSASP1 (FIPS 186-4): RSA Signature Primitive.
  Verify S^e mod n = EM (verification) and EM^d mod n = S (signature)
  for 5 vectors (2048 bits).}
procedure TRSATests.TestRSASP1Vectors;
var
  n, e, d, em, s, result: TBN;
begin
  { --- RSASP1 #0 (2048-bit) --- }
  n := TBN.FromHex('bad47a84c1782e4dbdd913f2a261fc8b65838412c6e45a2068ed6d7f16e9cdf4462b39119563cafb74b9cbf25cfd544bdae23bff0ebe7f6441042b7e109b9a8afaa056821ef8efaab219d21d6763484785622d918d395a2a31f2ece8385a8131e5ff143314a82e21afd713bae817cc0ee3514d4839007ccb55d68409c97a18ab62fa6f9f89b3f94a2777c47d6136775a56a9a0127f682470bef831fbec4bcd7b5095a7823fd70745d37d1bf72b63c4b1b4a3d0581e74bf9ade93cc46148617553931a79d92e9e488ef47223ee6f6c061884b13c9065b591139de13c1ea2927491ed00fb793cd68f463f5f64baa53916b46c818ab99706557a1c2d50d232577d1');
  e := TBN.FromHex('10001');
  d := TBN.FromHex('40d60f24b61d76783d3bb1dc00b55f96a2a686f59b3750fdb15c40251c370c65cada222673811bc6b305ed7c90ffcb3abdddc8336612ff13b42a75cb7c88fb936291b523d80acce5a0842c724ed85a1393faf3d470bda8083fa84dc5f31499844f0c7c1e93fb1f734a5a29fb31a35c8a0822455f1c850a49e8629714ec6a2657efe75ec1ca6e62f9a3756c9b20b4855bdc9a3ab58c43d8af85b837a7fd15aa1149c119cfe960c05a9d4cea69c9fb6a897145674882bf57241d77c054dc4c94e8349d376296137eb421686159cb878d15d171eda8692834afc871988f203fc822c5dcee7f6c48df663ea3dc755e7dc06aebd41d05f1ca2891e2679783244d068f');
  em := TBN.FromHex('70992c9d95a4908d2a94b3ab9fa1cd643f120e326f9d7808af50cac42c4b0b4eeb7f0d4df303a568fbfb82b0f58300d25357645721bb71861caf81b27a56082c80a146499fb4eab5bde4493f5d00f1a437bbc360dfcd8056fe6be10e608adb30b6c2f7652428b8d32d362945982a46585d2102ef7995a8ba6e8ad8fd16bd7ae8f53c3d7fcfba290b57ce7f8f09c828d6f2d3ce56f131bd9461e5667e5b73edac77f504dac4f202a9570eb4515b2bf516407db831518db8a2083ec701e8fd387c430bb1a72deca5b49d429cf9deb09cc4518dc5f57c089aa2d3420e567e732102c2c92b88a07c69d70917140ab3823c63f312d3f11fa87ba29da3c7224b4fb4bc');
  s := TBN.FromHex('7e65b998a05f626b028c75dc3fbf98963dce66d0f4c3ae4237cff304d84d8836cb6bad9ac86f9d1b8a28dd70404788b869d2429f1ec0663e51b753f7451c6b4645d99126e457c1dac49551d86a8a974a3131e9b371d5c214cc9ff240c299bd0e62dbc7a9a2dad9fa5404adb00632d36332d5be6106e9e6ec81cac45cd339cc87abbe7f89430800e16e032a66210b25e926eda243d9f09955496ddbc77ef74f17fee41c4435e78b46965b713d72ce8a31af641538add387fedfd88bb22a42eb3bda40f72ecad941dbffdd47b3e77737da741553a45b630d070bcc5205804bf80ee2d51612875dbc4796960052f1687e0074007e6a33ab8b2085c033f9892b6f74');
  result := s.ModPow(e, n);
  Check(result.Equal(em), 'RSASP1 #0: S^e mod n = EM (verify)');
  result := em.ModPow(d, n);
  Check(result.Equal(s), 'RSASP1 #0: EM^d mod n = S (sign)');

  { --- RSASP1 #1 (2048-bit) --- }
  n := TBN.FromHex('b968e2aaaee6ac4037af9268d0a90ae37b103c4eb302d0ecc23077752f395e6521647a15ab01117808ed7ddd1279090c42f83deb5029b03216e370a21fcdacc6119385d6e7b278862ff7bfc1461fc7d22ccf02a06c9f4eb63785950bad3b2db9279a973e2fc1e2be6c0d8eb124e0ea97e4642bec8ad0cd16f9ba7c3af22f2d1bdbc7e4d7ae1781d63d22c6a285a52d97730ce3746b94dd4fa4fd3dbd0526fcb141b1fdb99603f41425be8298ff8514a83c639f442f03447908f23603196941d666d2e24cb42a0841c0d99bcbd9db2289c5e2d9863670120b1b2f0ffecf4146d21bfffb1a07e00bc2f18e5909f390e9820b977ca7e3a2c67fdf3147c70a4df445');
  e := TBN.FromHex('10001');
  d := TBN.FromHex('5bd8ff0c81b728d6691f931e545ba156be647513a16f403341218453eb5076980f9a38365aaf9d4942d6ef76600bd0752009dc96a0effde65a5b5235261f1bbb4502b91714515f8e4ddde3c2a96bddef9a9df415a7a9a572f3ff3b2dfd23674ba5385a3b06aa7c1a4be9cd69a8b4b8d204e4b0b3adb2b11e7418b328fa476f86d836b989750cdb7cdde5b888db3b747e82d5e878b473607aa8bcce8d80c40bd43149a84f5579c6b4dcb388a6ebb7710805bd1224c962c809ad2583623a3dfd6ddeb7a5d40840c79780a7e7eac4a4e7740a5603c184470118d46ff68ca3587c6e2ed35d1ee6560237c515fbf5bc0047abad25e71962d3885d90bbcf73df0a2c33');
  em := TBN.FromHex('3afbdaec9d872f6619ce373cbf5d9e1d48dbc2d5bf8d71e5d234bb5c7ec319cf9ddbf1b1aa1e82159adb589f7c3929f68a1c6ad323688569bd9aeb447d26e0537e07a79aad5632a5e8c0846e1ec15dd18e97ea5bbfdbb7fff34b80b8d81eb98e6aea4ee416e479f951b61411f2c0a22e005ad30a6481cff7019fa10ac04c0f846762389f7f241797e12f865a883fcff4735d50867082ed6af02a3b6a968a6a052ed85af524e37afb15d29969e3becc8f03895366ff6a5c05f544fe5f67a81999786c9aaabb00ac8b6442d807669a0a295225c11ae3902a228d8c9535acb2892083cd677fd72103073ec760c6e1317d3e81455c0e09689516bc21681c514686bc');
  s := TBN.FromHex('7237bc0432abdf7e9c87bcf9a7e26b19b245445ce40d5b7440e343542402d504b2d0885e1cff33c753af3c69cfa5965c36225adfd262e5a4ce80141be5f8c5f8aac2379dede905efdab52e6b8f3601d160179846d429abef8a7623c52c72f43299838ebf0513d36606718057d22f648e4ecff4d5950907eda7f4de76557620b73d687525f29d1829d2baf104e24eedec19a25fe57276c176af6fea1cd67ad3f5243dbea52205be786fdacb131412e2b29fe173d0d824315893fc603d755826b5bf29d52e230e82e2afcd2708cf81bf0e4a38741473a0f11a5b578e0a5dfd62c0ad83189fd1fefd2bfb53c8fb67c0747ab0591db02d3b997dafcd35139e8f34d3');
  result := s.ModPow(e, n);
  Check(result.Equal(em), 'RSASP1 #1: S^e mod n = EM (verify)');
  result := em.ModPow(d, n);
  Check(result.Equal(s), 'RSASP1 #1: EM^d mod n = S (sign)');

  { --- RSASP1 #2 (2048-bit) --- }
  n := TBN.FromHex('9cc61aadbc7866db61cb03f389782e7369bc9314337efd861e334c7460bac0e6dd9c32e899b88c0e820093a6ef56403b78c459a512538a239c75cb08f3197caeb925a12b7e1685a22632a9022bad2f3e6fb17995292046b8d5bd801474b58797a1d712e902f9c02e61f16d8e72d9880d7fafa40cc7b8d48d1720700e3c310cf0b4336e560776e08ca1ee76e5e735c48d5e3e1cd86bb3ed130719ca778cd1bf2ad5b7126f580417ccd0f1c6709ff7eb238ca9679c6f1717ac523689bbde8e5145fa626ff4853e6bc18c3f8bfc1ef616f3dc98ed3d83329049d3181a050341a7319c6bd0b666a40c56714d0041643980f1824c8c805f2b5273cd6fd729ce67a233');
  e := TBN.FromHex('10001');
  d := TBN.FromHex('12730bd3b350d605ee49c672c414451f26ebdec12b583ffca7143164a6b7839907ae689d4fedd469a6a9ebb663071af304c0d2ade6ecb6de7efcabc2a75d31fb9be54e44c08764fd929236aa7f3a57cb78b8818ee8b298300b534c3ddc083ae740cfff3535b8ef8165dc5420c5ea4ca50e083cfd96096dd616c925f6bee5a4d8857ac345c6023921a3ffcd4266577bda1063a1ac211618050565aef579d842d9e42bc1d89fc4401d437560278286dd34dbc8da58c945a381804782f73d0bc985ca700f28dfdd8723befb6d5cb7c6a583f0552bd37e0d1cf151e5d67b30aced3b44c53fda93b2b7c13f5ce7022c4365eb795792a62a7eb15d1e7b0e94a8e976a1');
  em := TBN.FromHex('03fff4f85fe62f42a8873ec273193b29df5e3dd023cd4fd3a365fec4623be736287c900038599b78e76247b3dfdbabf6dd74212818bada5b1cb02b8e2250cec914b68ca3d45cd361c0ac64347aa55fdda755fac0d2a7e360309b756ed32d1d57966c66d7109e914f1b6fd327ccf07b1c118b5c0ee473f8a00990f2a1f32787f261d8cd9892efa3804863c40ead28933c6baa8983c45029d5a5b1681544b2e42964f6db6d4e29989c8193af366ecb3290f164636abc2588f63d4eb180523b0a0e293c631382b865af1a218edb015f67e5dbd3728f4246fd2c6dc5bab60d541cb3283c2633502bb3b6071a1e5b514db18fc2adca155ac241b859b12ee40903c0bc');
  s := TBN.FromHex('6eb6e140cbc3e3eed591970997da7c55ca67b958320392342ba59c3351a78a48490c69e8d6db22cea59f48669e7b8955c0a6e50457db2cd798179d276c845b90bc2739ebdb9e2fb0cb75ffdade1145b7bd446aa164141c649bbd3bd4cef8b3730436120ac7747fc2bbbeb2991182a11c61105fdbfc4d5e94ede81122932b9898605c3101c4c479b369cf40deab87e60ee0de6e0f6ca964c4b7b9e4e25e981b6e6b985bc231fb29d11b9a169b0a790f9390a76ca4dbe9dfb0fc53314688c0008bdf6027a594de193ef47cc0f4505334910017e9297a194b26384058287f6036c70172ba1e2897044f54bdf148904b2ad406d196dda716d2278e859b8516a86c7e');
  result := s.ModPow(e, n);
  Check(result.Equal(em), 'RSASP1 #2: S^e mod n = EM (verify)');
  result := em.ModPow(d, n);
  Check(result.Equal(s), 'RSASP1 #2: EM^d mod n = S (sign)');

  { --- RSASP1 #3 (2048-bit) --- }
  n := TBN.FromHex('c25b9f2a113e6da122df3784f9ae4da81f2b3383d0ac214945a6cd6c9e0521e1da7bb607ed0c759847c6530e3a3c9bb8260f37dfed7c89b7abf0d9197f4e3bbd8ce61c26b994a47092b4424747c7aef64385f3d793bcc14fa3870fdc4aac72d3cce366ebd3004f0df540fd275ce1d6f845a6d345d050c08ae3800b4c1abf02a084c36ddd0e5a3fd2421c596c6e1499394d0e6344d582c9a5c7e2dd4803c953444f24a61b9993bd4f47a599653499f9f98bb61b38cf2694989ac3e02de3cc4cb2856dc8bd855e25d254297a99c06548d116b3a7e233b10873a6214c70dbcb201f732e2b368cb0a93009b2eac103bb18179dd1dbf4fd02dd361e5a66c384d93387');
  e := TBN.FromHex('10001');
  d := TBN.FromHex('222f494c75e1fc185670da6c0a1a6d503fc3327961cf94bf3580042bb1938785190f9f51bf90ec720f55c3b001f03d1763a2539a9043d2593ae5ced99c399f6a5488f8b49af998feafdf02b554dbbb5b573f0d478295b58e935da31d8508d5dd88f10a5e3a2b98bc04c21c84bae2821402f437bed4c80f459e841bf893cfbadf403849bfc26a28d27a0f49f12c3ad060865643c1ef4e3d25da0ea45fe2ceda4cba7213dc1f91cbaaf0bc4e51c14488f47a4f74d88c5f8172bd83543a0cc15e0b9dca1eae5f6ee9e828d992d3ffedb5b12d47be3f63050f0f1d1d6f279f380ce08bd89256366d258bb56873d96e2740bc506b9ccc27b9cba3b422bcc74af3f341');
  em := TBN.FromHex('0c4e6cd7e0d36d2235d85c78a51649909b26be7145933bf02cff70bb63cc305d3e5d797238d39bf5d60a1b87b8375a60f538fbfe75cd39b81ddb2ae0e36b3afdb831320fbd6a0fe0beea24c7d1c440b9cc3eec4bf6bac487de98d7e251442efa210e78ee2117bc151081641b68c6ef73b31f9f678fb89fe75890b66198cfca799f4f38dcd9a38be304df90e7880b43adcd0742ebf31b1e0ddb6857155809810091ffeada5fba085c4a897db17ce6a9d1a4bc251cb10e767d1cb2e73a0e4211766eb374ce54d9f6533631e8c0e499713616afb2ceb506254915a3ccdde6f1a008abb5133b902ac5c1e7b3a3b047ba5f21b8fde6dfd3c715064546e307b28cd6bc');
  s := TBN.FromHex('8b526331ae640aa70317816868b05a0ef4cdd6b293242fbb96d3afe374f1407102fcbfc8c999e6dc6c93e44418dd9d484a698af9ccde81f87e695a0b48b1be61e6d7ef4c7847b7fcddcd7be9a41b6516a23aec0ef9b6e3eb1a439691300119c4950b9187478cbc7a92867e279b940f86881d896ab1ade4db961908341def9d5486bdb9f2bf8fc996391b8f47576a49cca50cc90744fab3b687d72f0400f96143281bcfde9633d3c4367f5872ed8e2e6e5ac546b9cfa92114ad4c901b0fe1777a7f9a008807f38099c0ca4be29cf5182798aa04b74bb042fe5505cd5a9e766da8b6f81ffb7911f2fb8c8326754ba5b55a8932be5c640dab3b06bba69b7ef0bb85');
  result := s.ModPow(e, n);
  Check(result.Equal(em), 'RSASP1 #3: S^e mod n = EM (verify)');
  result := em.ModPow(d, n);
  Check(result.Equal(s), 'RSASP1 #3: EM^d mod n = S (sign)');

  { --- RSASP1 #4 (2048-bit) --- }
  n := TBN.FromHex('9ae1bda92193873d8b43ac607463544bcd3cc847c9b6b54a8f7772b57e810f7a5cb2593a2a65d2be9cd81bc0c2281df19f45ae70e75aeff6cfda6b76bffcc493c50f7df53c24ed04e27b32ffca5f480c5e6514f4b3426feb0d43f72818eccc6ed0e830a020c055cf9edbf32f734ffd397b16820938bea0dd3197a38dbcc448ee4a31dae3a471ccbbeb77edcb28ea746294ddd1f268651be003b28760a6f32e60dde567fe1a726e2f75d5f9807f120d9bde82f1126a81908579048ac32958d3f1dc33b7931e5bf05ad104f9f68ff4b405f927fd28c98d7b55c5dc2d65b45b900f17425b425bf7f951d1a53c598860bddb95c00a6bccf92c5cb04109992fc25ce7');
  e := TBN.FromHex('10001');
  d := TBN.FromHex('00b331892f51055f2faecf0788de855fcd0b5aad1f5329d6f72e3178e6a098476371855190211356ddcd03ee90efa7d17acac22b07a13fbc025079737b86a4f6001eb6856566b7e33532ad57892ba0032afa3259b59841f391e322f96c966ebe653e1982ea04ca3f1892531d7d8ed48920dfe2f0c08f208615bbef2e8a5a8a1a96962aee10270d4b00a48f34b82bbbc7b0d9861afd2434439eed5e9b4e3abea77675074b7e5195206d5e1edb19817408e3653ffb021fe107bee13604778976cb2a16e534102006a7e39d3b7a8aeaa1ea52531bb3f06f44bfc50de9fc6c4d17b5e2790b2fd54040ce593d5fe050ea1a5c6af29e0892d1dbe75a52a8854074b201');
  em := TBN.FromHex('7b1fe1148b7776a05ce429fe4f05e4db101deec7fb0bae8d822734ee3032396550e65215b4774b07e37f58321ad4fcab32a730414a851dbe2c68befea6a225ceacf643a1aa0a2e077f052ed3db41f65c12f53ccc43329e59abf3b1560c7fc9de1ae762e0bcebd0f27f078c0f0c624a79067950433274a0bd2e9325bcd1dcf63d13ddebda0e2edd8224d94f240c87d93ceea6c4b6cf604eb5b9d904072a4b8bcd3e5e16b0ca8dc8751ae669365595658b8d3a45280a99680ae2be4e2bbb194134f0a6760a28580fffa667d293c13ce562474c2e2235025de878f8f6ce35456b64fcad7a67332b5318f0255340a1454b571d3f824b41f4c5e3e068740048341fbc');
  s := TBN.FromHex('4c0787990473cca7bbcc5c697743ea94ca8803402011e680e889f488989d3cdd324ef1355df407e56b0ca415b2ee896a508dd93379397fe59e805552671f81248f1aaa1220bc5a2917d1f0d13ffc4f0e67f9cd76d81a2b1048c00e6e44b1de76bc2ca1465d07d0713e0c6f55eb065d55f8958616f8f7085e5b3e66579b37917c8f67dea2f8ed63fa7b51c3d571de1d8185778ed53b11521f2f79323aed476eb6c950e5da3519c46787ae32b37211aba1019162f25e3b09b8a8a0d8fad230c00efba623d030dcb9061f1d3fa8712c12b6319406b36f178a364771a6bde2d90f4692a23eec16e61669ddc6d3f7abf743884b5639d175f32e276029d4b85c5353b4');
  result := s.ModPow(e, n);
  Check(result.Equal(em), 'RSASP1 #4: S^e mod n = EM (verify)');
  result := em.ModPow(d, n);
  Check(result.Equal(s), 'RSASP1 #4: EM^d mod n = S (sign)');
end;

initialization
  RegisterTest(TRSATests);

end.
