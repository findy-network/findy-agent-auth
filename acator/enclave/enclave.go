package enclave

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/findy-network/findy-common-go/crypto"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

type KeyHandle interface {
	ID() []byte
	PublicKey() ([]byte, error)
	Sign(d []byte) ([]byte, error)
}

type myHandle struct {
	//key []byte
	Enclave

	webauthncose.EC2PublicKeyData
	privKey *ecdsa.PrivateKey
}

func (h *myHandle) ID() []byte {
	x509Encoded := try.To1(x509.MarshalECPrivateKey(h.privKey))
	return h.Cipher.TryEncrypt(x509Encoded)
}

func (h *myHandle) IsKeyHandle(id []byte) bool {
	return false
}

func (h *myHandle) PublicKey() (_ []byte, err error) {
	defer err2.Handle(&err)

	return nil, nil
}

func (h *myHandle) Sign(d []byte) (_ []byte, err error) {
	return nil, nil
}

func (e Enclave) NewKeyHandle() (_ KeyHandle, err error) {
	// new random bytes for EC NewPrivateKey()
	defer err2.Handle(&err)

	privateKey := try.To1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	h := newFromPrivateKey(e, privateKey)
	return h, nil
}

func (e Enclave) IsKeyHandle(credID []byte) (ok bool, kh KeyHandle) {
	pk, err := x509.ParseECPrivateKey(e.Cipher.TryDecrypt(credID))
	ok = err == nil
	return ok, newFromPrivateKey(e, pk)
}

type Enclave struct {
	// TODO: maybe we could make this persistent? Let's leave it for now
	// we don't need to save this, it's enough that someone nows this and they
	// can create Enclave again
	// TODO: remove this
	key string

	crypto.Cipher
}

func New(hexKey string) *Enclave {
	k, err := hex.DecodeString(hexKey)
	assert.NoError(err)

	theCipher := crypto.NewCipher(k)

	return &Enclave{key: hexKey, Cipher: *theCipher}
}

// newFromPrivateKey returns instance of our cose.Key where given priKey is in
// ecdsa fmt. This is called from acator!
// TODO: not needed in enclave mode. we use only handle.
func newFromPrivateKey(e Enclave, priKey *ecdsa.PrivateKey) *myHandle {
	return &myHandle{
		Enclave: e,
		EC2PublicKeyData: webauthncose.EC2PublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{
				KeyType:   2,
				Algorithm: -7,
			},
			Curve:  1,
			XCoord: priKey.X.Bytes(),
			YCoord: priKey.Y.Bytes(),
		},
		privKey: priKey}
}
