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
	"time"

	"github.com/findy-network/findy-agent-auth/user"
	"github.com/findy-network/findy-common-go/crypto"
	"github.com/findy-network/findy-common-go/crypto/db"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

const userByte = 0

var (
	buckets           = [][]byte{{01, 01}}
	sealedBoxFilename string

	// Key must be set from production environment, SHA-256, 32 bytes
	hexKey    = "15308490f1e4026284594dd08d31291bc8ef2aeac730d0daf6ff87bb92d4336c"
	theCipher *crypto.Cipher
)

// InitSealedBox initialize enclave's sealed box. This must be called once
// during the app life cycle.
func InitSealedBox(filename, backupName, key string) (err error) {
	if key == "" {
		key = hexKey
	}
	k, _ := hex.DecodeString(key)
	theCipher = crypto.NewCipher(k)
	glog.V(1).Infoln("init enclave", filename)
	sealedBoxFilename = filename
	if backupName == "" {
		backupName = "backup-" + sealedBoxFilename
	}
	return db.Init(db.Cfg{
		Filename:   sealedBoxFilename,
		BackupName: backupName,
		Buckets:    buckets,
	})
}

// WipeSealedBox closes and destroys the enclave permanently. This version only
// removes the sealed box file. In the future we might add sector wiping
// functionality.
func WipeSealedBox() {
	err := db.Wipe()
	if err != nil {
		glog.Error(err.Error())
	}
}

func BackupTicker(interval time.Duration) (done chan<- struct{}) {
	return db.BackupTicker(interval)
}

// PutUser saves the user to database.
func PutUser(u *user.User) (err error) {
	defer err2.Handle(&err)

	try.To(db.AddKeyValueToBucket(buckets[userByte],
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
func GetUser(name string) (u *user.User, exist bool, err error) {
	defer err2.Handle(&err)

	value := &db.Data{
		Write: decrypt,
	}
	already := try.To1(db.GetKeyValueFromBucket(buckets[userByte],
		&db.Data{
			Data: []byte(name),
			Read: hash,
		},
		value,
	))
	if !already {
		return nil, already, err
	}

	return user.NewUserFromData(value.Data), already, err
}

// GetExistingUser returns user by name if exists in enclave
func GetExistingUser(name string) (u *user.User, err error) {
	defer err2.Handle(&err)

	u, already := try.To2(GetUser(name))

	if !already {
		return nil, fmt.Errorf("user (%s) not exist", name)
	}

	return u, err
}

func RemoveUser(name string) (err error) {
	defer err2.Handle(&err)

	_ = try.To1(GetExistingUser(name))
	return db.RmKeyValueFromBucket(buckets[userByte], &db.Data{
		Data: []byte(name),
		Read: hash,
	})
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
