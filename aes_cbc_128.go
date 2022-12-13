package gocrypt

import (
	"crypto/cipher"
	"crypto/sha512"
	"hash"
	"io"
)

func (a *AES) New128CBCWriterCustom(downstream io.Writer, keyIterations int, KeySize int, hashFunction func() hash.Hash) (*AESWriter, error) {
	aw, err := a.newAESWriter(keyIterations, KeySize, hashFunction)
	if err != nil {
		return nil, err
	}

	aw.blockMode = cipher.NewCBCEncrypter(aw.block, aw.IV)
	aw.downstream = downstream
	aw.cipherType = blockCipherType

	return aw, nil
}

func (a *AES) New128CBCWriter(downstream io.Writer) (*AESWriter, error) {
	return a.New128CBCWriterCustom(downstream, 4096, KeySize128, sha512.New)
}

func (a *AES) New128CBCReaderCustom(upstream io.Reader, iv []byte, keyIterations int, KeySize int, hashFunction func() hash.Hash) (*AESReader, error) {
	ar, err := a.newAESReader(iv, keyIterations, KeySize, hashFunction)
	if err != nil {
		return nil, err
	}

	ar.blockMode = cipher.NewCBCDecrypter(ar.block, ar.IV)
	ar.upstream = upstream
	ar.cipherType = blockCipherType

	return ar, nil
}

func (a *AES) New128CBCReader(upstream io.Reader, iv []byte) (*AESReader, error) {
	return a.New128CBCReaderCustom(upstream, iv, 4096, KeySize128, sha512.New)
}
