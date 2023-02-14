package enclave

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	crpt "github.com/findy-network/findy-common-go/crypto"
	"github.com/fxamacker/cbor/v2"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

type KeyHandle interface {
	ID() []byte
	CBORPublicKey() ([]byte, error)
	Sign(d []byte) ([]byte, error)

	Verify(data, sig []byte) (ok bool) // Mainly testing
}

type myHandle struct {
	//key []byte
	Enclave

	webauthncose.EC2PublicKeyData
	privKey *ecdsa.PrivateKey
}

// ID returns ENCRYPTED presentation of X509 encoded byte slice whole key, which
// means that private key. That means that the whole key pair can be restored
// into this same Enclave (master key is used for the encryption).
func (h *myHandle) ID() []byte {
	x509Encoded := try.To1(x509.MarshalECPrivateKey(h.privKey))
	return h.Cipher.TryEncrypt(x509Encoded)
}

// CBORPublicKey returns CBOR marshaled byte slice presentation of the public
// key or error.
func (h *myHandle) CBORPublicKey() (_ []byte, err error) {
	return cbor.Marshal(h.EC2PublicKeyData)
}

// Sign function signs then given byte slice and returns the signature or error.
func (h *myHandle) Sign(d []byte) (_ []byte, err error) {
	defer err2.Handle(&err)

	hash := crypto.SHA256.New()
	try.To1(hash.Write(d))

	hashVal := hash.Sum(nil)
	sig := try.To1(ecdsa.SignASN1(rand.Reader, h.privKey, hashVal))

	return sig, nil
}

// Verify verifies the given data and signature.
func (h *myHandle) Verify(data, sig []byte) (ok bool) {
	hash := crypto.SHA256.New()
	try.To1(hash.Write(data))

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(h.XCoord),
		Y:     big.NewInt(0).SetBytes(h.YCoord),
	}

	return ecdsa.VerifyASN1(pubKey, hash.Sum(nil), sig)
}

// NewKeyHandle creates a new key handle for the Enclave. The Enclave is
// stateless, which means that only the master key is needed. The master key is
// stored to every key handle to maintain statelessness.
func (e Enclave) NewKeyHandle() (_ KeyHandle, err error) {
	// new random bytes for EC NewPrivateKey()
	defer err2.Handle(&err)

	privateKey := try.To1(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	h := newFromPrivateKey(e, privateKey)
	return h, nil
}

// IsKeyHandle tells if given byte slice really is key handle from the current
// Enclave.
func (e Enclave) IsKeyHandle(credID []byte) (ok bool, kh KeyHandle) {
	defer err2.Catch(func(err error) {
		glog.Errorln("is key handle:", err)
		ok, kh = false, nil
	})
	pk, err := x509.ParseECPrivateKey(e.Cipher.TryDecrypt(credID))
	ok = err == nil
	return ok, newFromPrivateKey(e, pk)
}

var (
	Store Secure // Store is the default secure enclave created by pkg init.
)

func init() {
	const hexKey = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	Store = New(hexKey)
}

// Secure is a secure enclave interface.
type Secure interface {
	NewKeyHandle() (kh KeyHandle, err error)
	IsKeyHandle(id []byte) (yes bool, kh KeyHandle)
}

// Enclave is secure enclave.
type Enclave struct {
	crpt.Cipher
}

// New creates a new Enclave.
func New(hexKey string) *Enclave {
	k, err := hex.DecodeString(hexKey)
	assert.NoError(err)

	theCipher := crpt.NewCipher(k)

	return &Enclave{Cipher: *theCipher}
}

// newFromPrivateKey returns instance of our cose.Key where given priKey is in
// ecdsa fmt.
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
