package schnorr

import (
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
				x:      1,
				secret: curve.Scalar().SetInt64(1 + 2 + 3),
			},
		},
		{
			name: "share value to 2",
			args: args{
				x: 2,
			},
			want: &SharedSecret{
				x:      2,
				secret: curve.Scalar().SetInt64(1 + 2*2 + 3*2*2),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sec := &Secret{
				cons: cons,
			}
			if got := sec.GenShare(tt.args.x); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Secret.GenShare() = %v, want %v", got, tt.want)
			}
		})
	}
}
