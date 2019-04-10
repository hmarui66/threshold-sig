package schnorr

import (
	"fmt"
	"reflect"
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestSecret_GenShare(t *testing.T) {
	cons := []kyber.Scalar{
		curve.Scalar().SetInt64(1),
		curve.Scalar().SetInt64(2),
		curve.Scalar().SetInt64(3),
	}

	type args struct {
		x int64
	}
	tests := []struct {
		name string
		args args
		want *SharedSecret
	}{
		{
			name: "share value to 1",
			args: args{
				x: 1,
			},
			want: &SharedSecret{
				X:      1,
				Secret: curve.Scalar().SetInt64(1 + 2 + 3),
			},
		},
		{
			name: "share value to 2",
			args: args{
				x: 2,
			},
			want: &SharedSecret{
				X:      2,
				Secret: curve.Scalar().SetInt64(1 + 2*2 + 3*2*2),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sec := &Secret{
				Cons: cons,
			}
			if got := sec.GenShare(tt.args.x); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Secret.GenShare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRandomSecretAndSolve(t *testing.T) {
	type args struct {
		cnt int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "2 player",
			args: args{
				cnt: 2,
			},
			want: true,
		},
		{
			name: "3 player",
			args: args{
				cnt: 3,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := NewRandomSecret(tt.args.cnt)

			sharedList := make([]*SharedSecret, tt.args.cnt)
			for i := range secret.Cons {
				x := int64(i + 1)
				sharedList[i] = secret.GenShare(x)
			}
			if got := Solve(sharedList...); !got.Equal(secret.Cons[0]) {
				t.Errorf("NewRandomSecret() = %v, want %v", got, secret.Cons[0])
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

	msg := `hello threshold signature`
	sig1 := Sign(sharedNonce1.Secret, msg, sharedPrivKey1.Secret)
	sig2 := Sign(sharedNonce2.Secret, msg, sharedPrivKey2.Secret)

	validSig := Sign(nonce.Cons[0], msg, privKey.Cons[0])
	fmt.Println(Verify(msg, validSig, GenPublicKey(privKey.Cons[0])))

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

	fmt.Println(Verify(msg, interpolatedSig, GenPublicKey(privKey.Cons[0])))
}
