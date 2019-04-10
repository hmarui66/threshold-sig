package schnorr

import (
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestSign(t *testing.T) {
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
			got := Sign(tt.args.k, tt.args.m, tt.args.x)
			pub := GenPublicKey(tt.args.x)
			if !Verify(tt.args.m, got, pub) {
				t.Errorf("Sign() = %v, failed to verify", got)
			}
		})
	}
}
