package schnorr

import (
	"go.dedis.ch/kyber/v3"
)

func Solve(sharedList ...*SharedSecret) kyber.Scalar {
	res := curve.Scalar().Zero()
	for _, iS := range sharedList {
		numer := curve.Scalar().SetInt64(1)
		denom := curve.Scalar().SetInt64(1)
		for _, jS := range sharedList {
			if iS.X == jS.X {
				continue
			}
			numer = curve.Scalar().Mul(
				numer,
				curve.Scalar().Mul(
					curve.Scalar().SetInt64(-1),
					curve.Scalar().SetInt64(jS.X),
				))
			denom = curve.Scalar().Mul(
				denom,
				curve.Scalar().Sub(
					curve.Scalar().SetInt64(iS.X),
					curve.Scalar().SetInt64(jS.X),
				))
		}
		res = curve.Scalar().Add(
			res,
			curve.Scalar().Mul(
				curve.Scalar().Div(numer, denom),
				iS.Secret,
			),
		)
	}

	return res
}
