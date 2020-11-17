package enclave

import (
	"errors"
	"fmt"

	"github.com/lainio/err2"
	bolt "go.etcd.io/bbolt"
)

var db *bolt.DB

// ErrSealBoxAlreadyExists is an error for enclave sealed box already exists.
var ErrSealBoxAlreadyExists = errors.New("enclave sealed box exists")

func assertDB() {
	if db == nil {
		panic("don't forget init the seal box")
	}
}

func open(filename string) (err error) {
	if db != nil {
		return ErrSealBoxAlreadyExists
	}
	defer err2.Return(&err)

	db, err = bolt.Open(filename, 0600, nil)
	err2.Check(err)

	err2.Check(db.Update(func(tx *bolt.Tx) (err error) {
		defer err2.Annotate("create buckets", &err)

		err2.Try(tx.CreateBucketIfNotExists(userBucket))
		return nil
	}))
	return err
}

type filter func(value []byte) (k []byte)

type dbData struct {
	data  []byte
	read  filter
	write filter
}

func (d *dbData) get() []byte {
	return d.read(d.data)
}

func (d *dbData) set(b []byte) {
	d.data = d.write(b)
}

// Close closes the sealed box of the enclave. It can be open again with
// InitSealedBox.
func Close() {
	defer err2.CatchTrace(func(err error) {
		fmt.Println(err)
	})
	assertDB()

	err2.Check(db.Close())
	db = nil
}

func addKeyValueToBucket(bucket []byte, keyValue, index *dbData) (err error) {
	assertDB()

	defer err2.Annotate("add key", &err)

	err2.Check(db.Update(func(tx *bolt.Tx) (err error) {
		defer err2.Return(&err)

		b := tx.Bucket(bucket)
		err2.Check(b.Put(index.get(), keyValue.get()))
		return nil
	}))
	return nil
}

func getKeyValueFromBucket(bucket []byte, index, keyValue *dbData) (found bool, err error) {
	assertDB()

	defer err2.Return(&err)

	err2.Check(db.View(func(tx *bolt.Tx) (err error) {
		defer err2.Return(&err)

		b := tx.Bucket(bucket)
		d := b.Get(index.get())
		if d == nil {
			found = false
			return nil
		}
		keyValue.set(d)
		found = true
		return nil
	}))
	return found, nil
}
