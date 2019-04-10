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
		name string
		args args
		want kyber.Scalar
	}{
		{
			name: "",
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Solve(tt.args.sharedList...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Solve() = %v, want %v", got, tt.want)
			}
		})
	}
}
