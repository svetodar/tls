{ SPDX-License-Identifier: Apache-2.0 }
program debug_ec;
{$mode objfpc}{$H+}
uses
  SysUtils, tls.ec, tls.bn;

var
  curve: TECCurve;
  k1: TBN;
  p1: TECPoint;
  inf: TECPoint;
  sum: TECPoint;

begin
  curve := CurveP256;

  { Check TBN basics }
  k1 := TBN.FromQWord(1);
  WriteLn('k1=1: BitLength=', k1.BitLength, ' BitAt(0)=', k1.BitAt(0));

  { Manual ScalarMul for K=1 }
  inf := TECPoint.InfinityPoint;
  WriteLn('inf.Infinity = ', inf.Infinity);
  { Step 1: double(inf) }
  p1 := PointDouble(curve, inf);
  WriteLn('double(inf).Infinity = ', p1.Infinity);
  { Step 2: add(inf, G) }
  sum := PointAdd(curve, p1, curve.G);
  WriteLn('add(inf, G).Infinity = ', sum.Infinity);
  if not sum.Infinity then
    WriteLn('add(inf, G) = (', sum.X.ToHex, ', ', sum.Y.ToHex, ')');
  WriteLn('G = (', curve.G.X.ToHex, ', ', curve.G.Y.ToHex, ')');
  WriteLn('add(inf,G) == G: ', (not sum.Infinity) and sum.X.Equal(curve.G.X) and sum.Y.Equal(curve.G.Y));

  { Now try ScalarMul }
  p1 := ScalarMul(curve, k1, curve.G);
  WriteLn('ScalarMul(1, G).Infinity = ', p1.Infinity);
  if not p1.Infinity then
    WriteLn('ScalarMul(1, G) = (', p1.X.ToHex, ', ', p1.Y.ToHex, ')');

  sum.Free; p1.Free; inf.Free; k1.Free; curve.Free;
end.
