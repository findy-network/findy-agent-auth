package enclave

import (
	"crypto/ecdsa"
	"reflect"
	"testing"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/err2/assert"
)

func TestEnclave_NewKeyHandle(t *testing.T) {
	type fields struct {
		key string
	}
	tests := []struct {
		name   string
		fields fields
	}{
		{"simple",
			fields{"15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.PushTester(t)
			defer assert.PopTester()

			e := New(tt.fields.key)
			assert.NotNil(e)

			got, err := e.NewKeyHandle()
			assert.NoError(err)
			assert.INotNil(got)

			id := got.ID()
			assert.SNotNil(id)

			ok, nkh := e.IsKeyHandle(id)
			assert.That(ok)
			assert.INotNil(nkh)
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		hexKey string
	}
	tests := []struct {
		name    string
		args    args
		wantPtr bool
	}{
		{"simple", args{"15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"}, true},

		// next is caught by our common-go package's assert
		//{"empty hex", args{""}, false},

		// next is catched our assert, see the last z
		//{"not hex", args{"15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336z"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.PushTester(t)
			defer assert.PopTester()

			e := New(tt.args.hexKey)

			if tt.wantPtr {
				assert.NotNil(e)
			}
		})
	}
}

func Test_myHandle_Sign(t *testing.T) {
	type fields struct {
		key string
	}
	type args struct {
		d []byte
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{"simple",
			fields{"15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"},
			args{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.PushTester(t)
			defer assert.PopTester()

			e := New(tt.fields.key)
			assert.NotNil(e)

			h, err := e.NewKeyHandle()
			assert.NoError(err)
			assert.INotNil(h)

			sig, err := h.Sign(tt.args.d)
			assert.NoError(err)

			id := h.ID()
			assert.SNotNil(id)
			for i := 0; i < 10; i++ {
				myID := h.ID()
				assert.SLen(myID, len(id))
				assert.DeepEqual(id, myID, "ID as different round %d:%v,%v",
					i, myID, id)
			}

			ok, nkh := e.IsKeyHandle(id)
			assert.That(ok)
			assert.INotNil(nkh)

			assert.That(nkh.Verify(tt.args.d, sig))
		})
	}
}

func Test_myHandle_ID(t *testing.T) {
	type fields struct {
		Enclave          Enclave
		EC2PublicKeyData webauthncose.EC2PublicKeyData
		privKey          *ecdsa.PrivateKey
	}
	tests := []struct {
		name   string
		fields fields
		want   []byte
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.PushTester(t)
			defer assert.PopTester()

			h := &myHandle{
				Enclave:          tt.fields.Enclave,
				EC2PublicKeyData: tt.fields.EC2PublicKeyData,
				privKey:          tt.fields.privKey,
			}
			if got := h.ID(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("myHandle.ID() = %v, want %v", got, tt.want)
			}
		})
	}
}
