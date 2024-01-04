package cose

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestKey_SignAndVerify(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	type args struct {
		hash []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"first", args{hash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.PushTester(t)
			defer assert.PopTester()
			k := try.To1(New())
			var (
				sig []byte
				err error
			)
			if tt.wantErr {
				sig, err = k.Sign(tt.args.hash)
				assert.Error(err)
			} else {
				sig = try.To1(k.Sign(tt.args.hash))
			}
			valid := k.Verify(tt.args.hash, sig)
			assert.That(valid)
		})
	}
}

func TestKey_TryMarshalSecretPrivateKey(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()
	k := try.To1(New())

	d := k.TryMarshalSecretPrivateKey()

	k2 := Key{}
	k2.TryParseSecretPrivateKey(d)
}
