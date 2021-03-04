package cose

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKey_SignAndVerify(t *testing.T) {
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
			k, err := New()
			if err != nil {
				t.Errorf("New() error = %v", err)
				return
			}
			sig, err := k.Sign(tt.args.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			valid := k.Verify(tt.args.hash, sig)
			if !valid {
				t.Errorf("cannot verify")
			}
		})
	}
}

func TestKey_TryMarshalSecretPrivateKey(t *testing.T) {
	k, err := New()
	assert.NoError(t, err)

	d := k.TryMarshalSecretPrivateKey()

	k2 := Key{}
	k2.TryParseSecretPrivateKey(d)
}
