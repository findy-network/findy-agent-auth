package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/golang/glog"
	"github.com/lainio/err2"
)

type myCipher struct {
	key    []byte
	block  cipher.Block
	aesGCM cipher.AEAD
}

func NewCipher(k []byte) *myCipher {
	defer err2.Catch(func(err error) {
		glog.Error(err)
	})
	//Create a new Cipher Block from the key
	newBlock, err := aes.NewCipher(k)
	err2.Check(err)

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	newAesGCM, err := cipher.NewGCM(newBlock)
	err2.Check(err)

	return &myCipher{key: k, block: newBlock, aesGCM: newAesGCM}
}

func (c *myCipher) encrypt(in []byte) (out []byte, err error) {
	defer err2.Return(&err)
	return c.tryEncrypt(in), nil
}

func (c *myCipher) tryEncrypt(in []byte) (out []byte) {
	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, c.aesGCM.NonceSize())
	err2.Empty.Try(io.ReadFull(rand.Reader, nonce))

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add
	//it as a prefix to the encrypted data. The first nonce argument in Seal is
	//the prefix.
	return c.aesGCM.Seal(nonce, nonce, in, nil)
}

func (c *myCipher) decrypt(in []byte) (out []byte, err error) {
	defer err2.Return(&err)
	return c.tryDecrypt(in), nil
}

func (c *myCipher) tryDecrypt(in []byte) (out []byte) {
	//Get the nonce size
	nonceSize := c.aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := in[:nonceSize], in[nonceSize:]

	//Decrypt the data
	return err2.Bytes.Try(c.aesGCM.Open(nil, nonce, ciphertext, nil))
}
