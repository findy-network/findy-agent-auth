package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	crpt "github.com/findy-network/findy-grpc/crypto"
	"github.com/fxamacker/cbor"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
)

var (
	// todo: key must be set from production environment, SHA-256, 32 bytes
	hexKey    = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	theCipher *crpt.Cipher
)

func init() {
	k, _ := hex.DecodeString(hexKey)
	theCipher = crpt.NewCipher(k)
}

type Key struct {
	webauthncose.EC2PublicKeyData
	privKey *ecdsa.PrivateKey
}

func NewFromData(data []byte) (k *Key, err error) {
	defer err2.Annotate("new key from data", &err)

	k1, err := New()
	err2.Check(err)
	pkd, err := parsePublicKey(data)
	err2.Check(err)
	k1.EC2PublicKeyData = pkd.(webauthncose.EC2PublicKeyData)
	return k1, nil
}

func parsePublicKey(keyBytes []byte) (_ interface{}, err error) {
	defer err2.Return(&err)

	pk := webauthncose.PublicKeyData{}
	err2.Check(cbor.Unmarshal(keyBytes, &pk))
	switch webauthncose.COSEKeyType(pk.KeyType) {
	case webauthncose.OctetKey:
		assert.NoImplementation()
	case webauthncose.EllipticKey:
		var e webauthncose.EC2PublicKeyData
		err2.Check(cbor.Unmarshal(keyBytes, &e))
		e.PublicKeyData = pk
		return e, nil
	case webauthncose.RSAKey:
		assert.NoImplementation()
	default:
		return nil, webauthncose.ErrUnsupportedKey
	}
	return nil, nil
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
			XCoord: privateKey.X.Bytes(),
			YCoord: privateKey.Y.Bytes(),
		},
		privKey: privateKey}, nil
}

func (k *Key) Marshal() ([]byte, error) {
	return cbor.Marshal(k.EC2PublicKeyData)
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

func (k *Key) Verify(data, sig []byte) (ok bool) {
	hash := crypto.SHA256.New()
	hash.Write(data)

	pubkey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(k.XCoord),
		Y:     big.NewInt(0).SetBytes(k.YCoord),
	}

	return ecdsa.VerifyASN1(pubkey, hash.Sum(nil), sig)
	//return ecdsa.VerifyASN1(&k.privKey.PublicKey, hash, sig)
}

func (k *Key) TryMarshalSecretPrivateKey() []byte {
	x509Encoded, err := x509.MarshalECPrivateKey(k.privKey)
	err2.Check(err)
	return theCipher.TryEncrypt(x509Encoded)
}

func (k *Key) TryParseSecretPrivateKey(data []byte) {
	var err error
	k.privKey, err = x509.ParseECPrivateKey(theCipher.TryDecrypt(data))
	err2.Check(err)
}

func Verify(key *ecdsa.PublicKey, data, sig []byte) bool {
	h := crypto.SHA256.New()
	h.Write(data)
	return ecdsa.VerifyASN1(key, h.Sum(nil), sig)
}
