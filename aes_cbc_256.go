package gocrypt

import (
	"crypto/cipher"
	"crypto/sha512"
	"hash"
	"io"
)

func (a *AES) New256CBCWriterCustom(downstream io.Writer, keyIterations int, KeySize int, hashFunction func() hash.Hash) (*AESWriter, error) {
	aw, err := a.newAESWriter(keyIterations, KeySize, hashFunction)
	if err != nil {
		return nil, err
	}

	aw.blockMode = cipher.NewCBCEncrypter(aw.block, aw.IV)
	aw.downstream = downstream
	aw.cipherType = blockCipherType

	return aw, nil
}

func (a *AES) New256CBCWriter(downstream io.Writer) (*AESWriter, error) {
	return a.New256CBCWriterCustom(downstream, 4096, KeySize256, sha512.New)
}

func (a *AES) New256CBCReaderCustom(upstream io.Reader, iv []byte, keyIterations int, KeySize int, hashFunction func() hash.Hash) (*AESReader, error) {
	ar, err := a.newAESReader(iv, keyIterations, KeySize, hashFunction)
	if err != nil {
		return nil, err
	}

	ar.blockMode = cipher.NewCBCDecrypter(ar.block, ar.IV)
	ar.upstream = upstream
	ar.cipherType = blockCipherType

	return ar, nil
}

func (a *AES) New256CBCReader(upstream io.Reader, iv []byte) (*AESReader, error) {
	return a.New256CBCReaderCustom(upstream, iv, 4096, KeySize256, sha512.New)
}
