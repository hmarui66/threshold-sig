package musig

import (
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestSignAndVerify(t *testing.T) {
	secret := GenRandom()
	nonce := GenRandom()
	R := MulToBase(nonce)

	pub := MulToBase(secret)
	type args struct {
		k kyber.Scalar
		r kyber.Point
		m string
		x kyber.Scalar
	}
	tests := []struct {
		name    string
		args    args
		pub     kyber.Point
		invalid bool
	}{
		{
			name: "valid",
			args: args{
				k: nonce,
				r: R,
				m: "hello world",
				x: secret,
			},
			pub: pub,
		},
		{
			name: "invalid secret",
			args: args{
				k: nonce,
				r: R,
				m: "hello world",
				x: GenRandom(),
			},
			pub:     pub,
			invalid: true,
		},
		{
			name: "invalid pub",
			args: args{
				k: nonce,
				r: R,
				m: "hello world",
				x: GenRandom(),
			},
			pub:     curve.Point(),
			invalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sign(tt.args.k, tt.args.r, tt.args.m, tt.args.x)
			if !Verify(tt.args.m, got, tt.pub) != tt.invalid {
				t.Errorf("Sign() = %v, failed to verify", got)
			}
		})
	}
}

func TestThresholdSignature(t *testing.T) {
	secret := NewRandomConstantTerms(3)
	nonce := NewRandomConstantTerms(3)

	pub := MulToBase(secret.GetSecret())

	type args struct {
		secret *ConstantTerms
		nonce  *ConstantTerms
		signer []int
		msg    string
		pub    kyber.Point
	}
	tests := []struct {
		name    string
		args    args
		invalid bool
	}{
		{
			name: "succeeded to verify threshold signature",
			args: args{
				secret: secret,
				nonce:  nonce,
				signer: []int{1, 3, 5},
				msg:    `hello threshold signature`,
				pub:    pub,
			},
		},
		{
			name: "not enough signer",
			args: args{
				secret: secret,
				nonce:  nonce,
				signer: []int{3, 5},
				msg:    `hello threshold signature`,
				pub:    pub,
			},
			invalid: true,
		},
		{
			name: "invalid pub",
			args: args{
				secret: secret,
				nonce:  nonce,
				signer: []int{1, 3, 5},
				msg:    `hello threshold signature`,
				pub:    curve.Point(),
			},
			invalid: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			R := MulToBase(tt.args.nonce.GetSecret())
			sharedSigs := make([]*SharedSecret, len(tt.args.signer))
			for i, s := range tt.args.signer {
				x := int64(s)

				// 秘密鍵のシェアを算出
				sharedSecret := tt.args.secret.CalcShare(x)
				// 署名に利用するランダム値のシェアを算出
				sharedNonce := tt.args.nonce.CalcShare(x)

				// シェアされた情報を使って署名の一部を作成
				sharedSigs[i] = &SharedSecret{
					X:      x,
					Secret: Sign(sharedNonce.Secret, R, tt.args.msg, sharedSecret.Secret).S,
				}
			}

			// ラグランジュの補間公式を利用して署名を算出
			interpolatedSignature := &Signature{
				R: R,
				S: Solve(sharedSigs...),
			}
			if !Verify(tt.args.msg, interpolatedSignature, tt.args.pub) != tt.invalid {
				t.Errorf("Verify() failed to verify threshold signature")
			}
		})
	}
}
