package schnorr

import (
	"fmt"
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestSignAndVerify(t *testing.T) {
	type args struct {
		k kyber.Scalar
		m string
		x kyber.Scalar
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "sign and verify",
			args: args{
				k: GenRandom(),
				m: "hello world",
				x: GenRandom(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sign(tt.args.k, MulToBase(tt.args.k), tt.args.m, tt.args.x)
			pub := MulToBase(tt.args.x)
			if !Verify(tt.args.m, got, pub) {
				t.Errorf("Sign() = %v, failed to verify", got)
			}
		})
	}
}

func TestThresholdSignature(t *testing.T) {
	privKey := NewRandomSecret(2)
	sharedPrivKey1 := privKey.GenShare(1)
	sharedPrivKey2 := privKey.GenShare(2)

	nonce := NewRandomSecret(2)
	sharedNonce1 := nonce.GenShare(1)
	sharedNonce2 := nonce.GenShare(2)

	R := MulToBase(nonce.Cons[0])

	msg := `hello threshold signature`
	sig1 := Sign(sharedNonce1.Secret, R, msg, sharedPrivKey1.Secret)
	sig2 := Sign(sharedNonce2.Secret, R, msg, sharedPrivKey2.Secret)

	validSig := Sign(nonce.Cons[0], R, msg, privKey.Cons[0])
	fmt.Println(Verify(msg, validSig, MulToBase(privKey.Cons[0])))

	interpolatedSig := &Signature{
		R: validSig.R,
		S: Solve(
			&SharedSecret{
				X:      1,
				Secret: sig1.S,
			},
			&SharedSecret{
				X:      2,
				Secret: sig2.S,
			},
		),
	}

	fmt.Println(Verify(msg, interpolatedSig, MulToBase(privKey.Cons[0])))
}
