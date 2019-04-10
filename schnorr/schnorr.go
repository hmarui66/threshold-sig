package schnorr

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

var (
	curve  = edwards25519.NewBlakeSHA256Ed25519()
	sha256 = curve.Hash()
)

type Signature struct {
	R kyber.Point
	S kyber.Scalar
}

func GenRandom() kyber.Scalar {
	return curve.Scalar().Pick(curve.RandomStream())
}

func GenPublicKey(x kyber.Scalar) kyber.Point {
	return curve.Point().Mul(x, curve.Point().Base())
}

func Hash(s string) kyber.Scalar {
	sha256.Reset()
	sha256.Write([]byte(s))

	return curve.Scalar().SetBytes(sha256.Sum(nil))
}

func Sign(m string, x kyber.Scalar) *Signature {
	g := curve.Point().Base()

	k := curve.Scalar().Pick(curve.RandomStream())

	r := curve.Point().Mul(k, g)

	e := Hash(m + r.String())
	s := curve.Scalar().Sub(k, curve.Scalar().Mul(e, x))

	return &Signature{
		R: r,
		S: s,
	}
}

func Verify(m string, sig *Signature, pubKey kyber.Point) bool {
	g := curve.Point().Base()

	e := Hash(m + sig.R.String())
	sGv := curve.Point().Sub(sig.R, curve.Point().Mul(e, pubKey))
	sG := curve.Point().Mul(sig.S, g)

	return sG.Equal(sGv)
}
