package schnorr

import (
	"reflect"
	"testing"

	"go.dedis.ch/kyber/v3"
)

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
