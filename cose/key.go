package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/lainio/err2"
)

// "github.com/fxamacker/cbor/v2"

type Key struct {
	webauthncose.EC2PublicKeyData
	privKey *ecdsa.PrivateKey
}

func New() (k *Key, err error) {
	defer err2.Annotate("new", &err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err2.Check(err)
	return &Key{
		EC2PublicKeyData: webauthncose.EC2PublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{
				KeyType:   2,
				Algorithm: -7,
			},
			Curve:  1,
			XCoord: nil,
			YCoord: nil,
		},
		privKey: privateKey}, nil

}

func (k *Key) NewPrivateKey() (err error) {
	defer err2.Annotate("new key", &err)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	err2.Check(err)
	k.privKey = privateKey

	return nil
}

func (k *Key) Sign(hash []byte) (s []byte, err error) {
	defer err2.Annotate("sing", &err)

	sig, err := ecdsa.SignASN1(rand.Reader, k.privKey, hash)
	err2.Check(err)

	return sig, nil
}

func (k *Key) Verify(hash, sig []byte) (ok bool) {
	return ecdsa.VerifyASN1(&k.privKey.PublicKey, hash, sig)
}

func Verify(key *ecdsa.PublicKey, data, sig []byte) bool {
	h := crypto.SHA256.New()
	h.Write(data)
	return ecdsa.VerifyASN1(key, h.Sum(nil), sig)
}