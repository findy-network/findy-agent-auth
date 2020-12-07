/*
Package enclave is a server-side Secure Enclave. It offers a secure and sealed
storage to store indy wallet keys on the Agency server.

Urgent! This version does not implement internal hash(), encrypt, and decrypt()
functions. We must implement these three functions before production. We will
offer implementations of them when the server-side crypto solution and the Key
Storage is selected. Possible candidates are AWS Nitro, etc. We also bring
addon/plugin system for cryptos when first implementation is done.
*/
package enclave

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/findy-network/findy-grpc/crypto"
	"github.com/findy-network/findy-grpc/crypto/db"
	"github.com/golang/glog"
	"github.com/lainio/err2"
)

const user = 0

var (
	buckets           = [][]byte{{01, 01}}
	sealedBoxFilename string

	// todo: key must be set from production environment, SHA-256, 32 bytes
	hexKey    = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	theCipher *crypto.Cipher
)

// InitSealedBox initialize enclave's sealed box. This must be called once
// during the app life cycle.
func InitSealedBox(filename string) (err error) {
	k, _ := hex.DecodeString(hexKey)
	theCipher = crypto.NewCipher(k)
	glog.V(1).Infoln("init enclave", filename)
	sealedBoxFilename = filename
	return db.Open(filename, buckets)
}

// WipeSealedBox closes and destroys the enclave permanently. This version only
// removes the sealed box file. In the future we might add sector wiping
// functionality.
func WipeSealedBox() {
	if db.DB != nil {
		db.Close()
	}

	err := os.RemoveAll(sealedBoxFilename)
	if err != nil {
		println(err.Error())
	}
}

// PutUser saves the user to database.
func PutUser(u *User) (err error) {
	defer err2.Return(&err)

	err2.Check(db.AddKeyValueToBucket(buckets[user],
		&db.Data{
			Data: u.Data(),
			Read: encrypt,
		},
		&db.Data{
			Data: u.Key(),
			Read: hash,
		},
	))

	return nil
}

// GetUser returns user by name if exists in enclave
func GetUser(name string) (u *User, exist bool, err error) {
	defer err2.Return(&err)

	value := &db.Data{Write: decrypt}
	already, err := db.GetKeyValueFromBucket(buckets[user],
		&db.Data{
			Data: []byte(name),
			Read: hash,
		}, value)
	err2.Check(err)
	if !already {
		return nil, already, err
	}

	return NewUserFromData(value.Data), already, err
}

// GetUserMust returns user by name if exists in enclave
func GetExistingUser(name string) (u *User, err error) {
	defer err2.Return(&err)

	value := &db.Data{Write: decrypt}
	already, err := db.GetKeyValueFromBucket(buckets[user],
		&db.Data{
			Data: []byte(name),
			Read: hash,
		}, value)
	err2.Check(err)
	if !already {
		return nil, fmt.Errorf("user (%s) not exist", name)
	}

	return NewUserFromData(value.Data), err
}

// all of the following has same signature. They also panic on error

// hash makes the cryptographic hash of the map key value. This prevents us to
// store key value index (email, DID) to the DB aka sealed box as plain text.
// Please use salt when implementing this.
func hash(key []byte) (k []byte) {
	h := md5.Sum(key)
	return h[:]
}

// encrypt encrypts the actual wallet key value. This is used when data is
// stored do the DB aka sealed box.
func encrypt(value []byte) (k []byte) {
	return theCipher.TryEncrypt(value)
}

// decrypt decrypts the actual wallet key value. This is used when data is
// retrieved from the DB aka sealed box.
func decrypt(value []byte) (k []byte) {
	return theCipher.TryDecrypt(value)
}

// noop function if need e.g. tests
func _(value []byte) (k []byte) {
	println("noop called!")
	return value
}
