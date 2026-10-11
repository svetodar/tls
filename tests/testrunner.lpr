{ SPDX-License-Identifier: Apache-2.0 }
program testrunner;
{ Unit tests for the tls library (fpcunit). Run with `make test`. }

{$mode objfpc}{$H+}

uses
  consoletestrunner,
  test_bn,
  test_rand,
  test_sha2,
  test_aes,
  test_chacha,
  test_rsa,
  test_ec,
  test_dh,
  test_asn1,
  test_x509,
  test_certverify,
  test_tls12,
  test_tls12_e2e;

var
  App: TTestRunner;

begin
  App := TTestRunner.Create(nil);
  try
    App.Initialize;
    App.Title := 'tls tests';
    App.Run;
  finally
    App.Free;
  end;
end.
