package musig

import (
	"reflect"
	"testing"

	"go.dedis.ch/kyber/v3"
)

func TestConstantTerms_CalcShare(t *testing.T) {
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
			sec := &ConstantTerms{
				Cons: cons,
			}
			if got := sec.CalcShare(tt.args.x); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ConstantTerms.CalcShare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewRandomConstantTermsAndSolve(t *testing.T) {
	type args struct {
		cnt int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "2 players",
			args: args{
				cnt: 2,
			},
			want: true,
		},
		{
			name: "3 players",
			args: args{
				cnt: 3,
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := NewRandomConstantTerms(tt.args.cnt)

			sharedList := make([]*SharedSecret, tt.args.cnt)
			for i := range secret.Cons {
				x := int64(i + 1)
				sharedList[i] = secret.CalcShare(x)
			}
			if got := Solve(sharedList...); !got.Equal(secret.GetSecret()) {
				t.Errorf("NewRandomConstantTerms() = %v, want %v", got, secret.GetSecret())
			}
		})
	}
}

func TestSolve(t *testing.T) {
	type args struct {
		sharedList []*SharedSecret
	}
	tests := []struct {
		name    string
		args    args
		want    kyber.Scalar
		unmatch bool
	}{
		{
			name: "1 + 2x + 3x^2",
			args: args{
				sharedList: []*SharedSecret{
					{
						X:      1,
						Secret: curve.Scalar().SetInt64(6),
					},
					{
						X:      2,
						Secret: curve.Scalar().SetInt64(17),
					},
					{
						X:      3,
						Secret: curve.Scalar().SetInt64(34),
					},
				},
			},
			want: curve.Scalar().SetInt64(1),
		},
		{
			name: "insufficient: 1 + 2x + 3x^2",
			args: args{
				sharedList: []*SharedSecret{
					{
						X:      1,
						Secret: curve.Scalar().SetInt64(6),
					},
					{
						X:      2,
						Secret: curve.Scalar().SetInt64(17),
					},
				},
			},
			want:    curve.Scalar().SetInt64(1),
			unmatch: true,
		},
		{
			name: "2 + 2x + 3x^2",
			args: args{
				sharedList: []*SharedSecret{
					{
						X:      1,
						Secret: curve.Scalar().SetInt64(7),
					},
					{
						X:      2,
						Secret: curve.Scalar().SetInt64(18),
					},
					{
						X:      3,
						Secret: curve.Scalar().SetInt64(35),
					},
				},
			},
			want: curve.Scalar().SetInt64(2),
		},
		{
			name: "1 + 2x + 3x^2 + 4x^3",
			args: args{
				sharedList: []*SharedSecret{
					{
						X:      1,
						Secret: curve.Scalar().SetInt64(10),
					},
					{
						X:      2,
						Secret: curve.Scalar().SetInt64(49),
					},
					{
						X:      3,
						Secret: curve.Scalar().SetInt64(142),
					},
					{
						X:      4,
						Secret: curve.Scalar().SetInt64(313),
					},
				},
			},
			want: curve.Scalar().SetInt64(1),
		},
		{
			name: "invalid: 1 + 2x + 3x^2 + 4x^3",
			args: args{
				sharedList: []*SharedSecret{
					{
						X:      1,
						Secret: curve.Scalar().SetInt64(11),
					},
					{
						X:      2,
						Secret: curve.Scalar().SetInt64(49),
					},
					{
						X:      3,
						Secret: curve.Scalar().SetInt64(142),
					},
					{
						X:      4,
						Secret: curve.Scalar().SetInt64(313),
					},
				},
			},
			want:    curve.Scalar().SetInt64(1),
			unmatch: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Solve(tt.args.sharedList...); !reflect.DeepEqual(got, tt.want) && !tt.unmatch {
				t.Errorf("Solve() = %v, want %v", got, tt.want)
			}
		})
	}
}
