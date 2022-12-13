package gocrypt

import (
	"crypto/aes"
	"crypto/rand"
	"hash"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	blockCipherType         = iota
	streamCipherType        = iota
	authenticatedCipherType = iota
)

const AESBlockSize = 16
const KeySize256 = 32
const KeySize128 = 16

type AES struct {
	key []byte
}

func NewAES(key []byte) *AES {
	return &AES{key: key}
}

/* newAESCipher is meant to be used by internal functions.
*  Creates a AESWriter with a populated IV and block.
*  Returns AESWriter, error
 */
func (a *AES) newAESWriter(keyIterations int, keySize int, hashFunction func() hash.Hash) (*AESWriter, error) {

	derivedKey := pbkdf2.Key(a.key, nil, keyIterations, keySize, hashFunction)
	aw := AESWriter{
		BlockSize: keySize,
		key:       derivedKey,
		IV:        make([]byte, AESBlockSize),
	}
	rand.Read(aw.IV)

	block, err := aes.NewCipher(aw.key)
	if err != nil {
		return nil, err
	}
	aw.block = block

	return &aw, nil
}

func (a *AES) newAESReader(iv []byte, keyIterations int, keySize int, hashFunction func() hash.Hash) (*AESReader, error) {

	derivedKey := pbkdf2.Key(a.key, nil, keyIterations, keySize, hashFunction)
	ar := AESReader{
		BlockSize: keySize,
		key:       derivedKey,
		IV:        iv,
	}

	block, err := aes.NewCipher(ar.key)
	if err != nil {
		return nil, err
	}
	ar.block = block

	return &ar, nil
}

/* NewWriter is a default simple to use standard. It uses AES-256-CBC (Currently and is subject to change until a stable version 1.0 is released)
*  Returns AESWriter, error
 */
func (a *AES) NewWriter(writer io.Writer) (*AESWriter, []byte, error) {

	aw, err := a.New256CBCWriter(writer)
	if err != nil {
		return nil, nil, err
	}

	return aw, aw.IV, nil
}

/* NewReader is a default simple to use standard. It uses AES-256-CBC (Currently and is subject to change until a stable version 1.0 is released)
*  Returns AESReader, error.
 */

func (a *AES) NewReader(reader io.Reader, iv []byte) (*AESReader, error) {
	return a.New256CBCReader(reader, iv)
}
