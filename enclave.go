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
	"fmt"
	"os"

	"github.com/golang/glog"
	"github.com/lainio/err2"
)

var userBucket = []byte{01, 01}

var sealedBoxFilename string

// InitSealedBox initialize enclave's sealed box. This must be called once
// during the app life cycle.
func InitSealedBox(filename string) (err error) {
	glog.V(1).Infoln("init enclave", filename)
	sealedBoxFilename = filename
	return open(filename)
}

// WipeSealedBox closes and destroys the enclave permanently. This version only
// removes the sealed box file. In the future we might add sector wiping
// functionality.
func WipeSealedBox() {
	if db != nil {
		Close()
	}

	err := os.RemoveAll(sealedBoxFilename)
	if err != nil {
		println(err.Error())
	}
}

// PutUser saves the user to database.
func PutUser(u *User) (err error) {
	defer err2.Return(&err)

	err2.Check(addKeyValueToBucket(userBucket,
		&dbData{
			data: u.Data(),
			read: encrypt,
		},
		&dbData{
			data: u.Key(),
			read: hash,
		},
	))

	return nil
}

// GetUser returns user by name if exists in enclave
func GetUser(name string) (u *User, exist bool, err error) {
	defer err2.Return(&err)

	value := &dbData{write: decrypt}
	already, err := getKeyValueFromBucket(userBucket,
		&dbData{
			data: []byte(name),
			read: hash,
		}, value)
	err2.Check(err)
	if !already {
		return nil, already, err
	}

	return NewUserFromData(value.data), already, err
}

// GetUserMust returns user by name if exists in enclave
func GetExistingUser(name string) (u *User, err error) {
	defer err2.Return(&err)

	value := &dbData{write: decrypt}
	already, err := getKeyValueFromBucket(userBucket,
		&dbData{
			data: []byte(name),
			read: hash,
		}, value)
	err2.Check(err)
	if !already {
		return nil, fmt.Errorf("user (%s) not exist", name)
	}

	return NewUserFromData(value.data), err
}

// Todo: these dummy functions must be implemented before production.

// all of the following has same signature. They also panic on error

// hash makes the cryptographic hash of the map key value. This prevents us to
// store key value index (email, DID) to the DB aka sealed box as plain text.
// Please use salt when implementing this.
func hash(key []byte) (k []byte) {
	return append(key[:0:0], key...)
}

// encrypt encrypts the actual wallet key value. This is used when data is
// stored do the DB aka sealed box.
func encrypt(value []byte) (k []byte) {
	return append(value[:0:0], value...)
}

// decrypt decrypts the actual wallet key value. This is used when data is
// retrieved from the DB aka sealed box.
func decrypt(value []byte) (k []byte) {
	return append(value[:0:0], value...)
}

func _(value []byte) (k []byte) {
	println("noop called!")
	return value
}
