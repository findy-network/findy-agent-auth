package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"

	crpt "github.com/findy-network/findy-common-go/crypto"
	"github.com/fxamacker/cbor/v2"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var (
	// hexKey is for tests only
	hexKey    = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	theCipher *crpt.Cipher
)

func init() {
	// todo: we start with the default master key, we should drop this in
	//  future and force to use SetMasterKey()
	k, _ := hex.DecodeString(hexKey)
	theCipher = crpt.NewCipher(k)
}

// SetMasterKey set the master secret for this crypter. Need to be called before
// acator can be used. See AuthnCmd for more info.
func SetMasterKey(hexKey string) (err error) {
	defer err2.Handle(&err, "set master key")
	k := try.To1(hex.DecodeString(hexKey))
	theCipher = crpt.NewCipher(k)
	return nil
}

type Key struct {
	webauthncose.EC2PublicKeyData
	privKey *ecdsa.PrivateKey
}

// NewFromData used in testing.
func NewFromData(data []byte) (k *Key, err error) {
	defer err2.Handle(&err, "new key from data")

	k1 := try.To1(New())
	pkd := try.To1(parsePublicKey(data))
	k1.EC2PublicKeyData = pkd.(webauthncose.EC2PublicKeyData)
	return k1, nil
}

func parsePublicKey(keyBytes []byte) (_ interface{}, err error) {
	defer err2.Handle(&err)

	pk := webauthncose.PublicKeyData{}
	try.To(cbor.Unmarshal(keyBytes, &pk))
	switch webauthncose.COSEKeyType(pk.KeyType) { //nolint
	case webauthncose.OctetKey:
		assert.NotImplemented()
	case webauthncose.EllipticKey:
		var e webauthncose.EC2PublicKeyData
		try.To(cbor.Unmarshal(keyBytes, &e))
		e.PublicKeyData = pk
		return e, nil
	case webauthncose.RSAKey:
		assert.NotImplemented()
	default:
		return nil, webauthncose.ErrUnsupportedKey
	}
	return nil, nil
}

// NewFromPrivateKey returns instance of our cose.Key where given priKey is in
// ecdsa fmt.
func NewFromPrivateKey(priKey *ecdsa.PrivateKey) *Key {
	return &Key{
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

// New creates a new key.
func New() (k *Key, err error) {
	defer err2.Handle(&err, "new")

	privateKey := try.To1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	return NewFromPrivateKey(privateKey), nil
}

// Marshal returns CBOR marshaled public key data.
func (k *Key) Marshal() ([]byte, error) {
	return cbor.Marshal(k.EC2PublicKeyData)
}

func (k *Key) NewPrivateKey() (err error) {
	defer err2.Handle(&err, "new key")

	privateKey := try.To1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	k.privKey = privateKey

	return nil
}

// Sign signs the data. Called from acator!
func (k *Key) Sign(data []byte) (s []byte, err error) {
	defer err2.Handle(&err, "sign")

	hash := crypto.SHA256.New()
	try.To1(hash.Write(data))

	h := hash.Sum(nil)
	sig := try.To1(ecdsa.SignASN1(rand.Reader, k.privKey, h))

	return sig, nil
}

func (k *Key) Verify(data, sig []byte) (ok bool) {
	hash := crypto.SHA256.New()
	try.To1(hash.Write(data))

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(k.XCoord),
		Y:     big.NewInt(0).SetBytes(k.YCoord),
	}

	return ecdsa.VerifyASN1(pubKey, hash.Sum(nil), sig)
}

// TryMarshalSecretPrivateKey marhalls our private key and encrypts it with the
// master key.
func (k *Key) TryMarshalSecretPrivateKey() []byte {
	x509Encoded := try.To1(x509.MarshalECPrivateKey(k.privKey))
	return theCipher.TryEncrypt(x509Encoded)
}

// TryParseSecretPrivateKey used from tests
func (k *Key) TryParseSecretPrivateKey(data []byte) {
	try.To(k.ParseSecretPrivateKey(data))
}

// ParseSecretPrivateKey parses ecdsa priv key from encrypted data. Data is
// encrypted with our master key. If it isn't or data is corrupted function
// returns error. Called from acator!
func (k *Key) ParseSecretPrivateKey(data []byte) (err error) {
	defer err2.Handle(&err, "parse secret")

	k.privKey = try.To1(ParseSecretPrivateKey(data))
	return nil
}

// ParseSecretPrivateKey parses ecdsa priv key from encrypted data. Data is
// encrypted with our master key. If it isn't or data is corrupted function
// returns error.
func ParseSecretPrivateKey(data []byte) (pk *ecdsa.PrivateKey, err error) {
	defer err2.Handle(&err, "parse secret private")

	pk = try.To1(x509.ParseECPrivateKey(theCipher.TryDecrypt(data)))
	return pk, nil
}

// VerifyHashSig verifies signature of data's hash with ecdsa public key. The
// function is currently used only for testing our signatures are right.
func VerifyHashSig(key *ecdsa.PublicKey, data, sig []byte) bool {
	h := crypto.SHA256.New()
	try.To1(h.Write(data))
	return ecdsa.VerifyASN1(key, h.Sum(nil), sig)
}
