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

func Open(filename string, buckets [][]byte) (err error) {
	if db != nil {
		return ErrSealBoxAlreadyExists
	}
	defer err2.Return(&err)

	db, err = bolt.Open(filename, 0600, nil)
	err2.Check(err)

	err2.Check(db.Update(func(tx *bolt.Tx) (err error) {
		defer err2.Annotate("create buckets", &err)

		for _, bucket := range buckets {
			err2.Try(tx.CreateBucketIfNotExists(bucket))
		}
		return nil
	}))
	return err
}

type Filter func(value []byte) (k []byte)

type DbData struct {
	Data  []byte
	Read  Filter
	Write Filter
}

func (d *DbData) get() []byte {
	if d.Read == nil {
		return append(d.Data[:0:0], d.Data...)
	}
	return d.Read(d.Data)
}

func (d *DbData) set(b []byte) {
	if d.Write == nil {
		copy(d.Data, b)
	}
	d.Data = d.Write(b)
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

func AddKeyValueToBucket(bucket []byte, keyValue, index *DbData) (err error) {
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

func GetKeyValueFromBucket(bucket []byte, index, keyValue *DbData) (found bool, err error) {
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
