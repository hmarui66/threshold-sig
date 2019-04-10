package schnorr

import "go.dedis.ch/kyber/v3"

type (
	Secret struct {
		Cons []kyber.Scalar
	}
	SharedSecret struct {
		X      int64
		Secret kyber.Scalar
	}
)

func NewRandomSecret(cnt int) *Secret {
	cons := make([]kyber.Scalar, cnt)
	for i := range cons {
		cons[i] = curve.Scalar().Pick(curve.RandomStream())
	}

	return &Secret{
		Cons: cons,
	}
}

func (sec *Secret) GenShare(x int64) *SharedSecret {
	secret := curve.Scalar().Zero()

	xScalar := curve.Scalar().SetInt64(x)
	for exp, c := range sec.Cons {
		s := c
		for i := 1; i <= exp; i++ {
			s = curve.Scalar().Mul(s, xScalar)
		}
		secret = curve.Scalar().Add(secret, s)
	}
	return &SharedSecret{
		X:      x,
		Secret: secret,
	}
}
