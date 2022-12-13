package gocrypt

import (
	"crypto/cipher"
	"crypto/sha512"
	"hash"
	"io"
)

func (a *AES) New128CFBWriterCustom(downstream io.Writer, keyIterations int, KeySize int, hashFunction func() hash.Hash) (*AESWriter, []byte, error) {
	aw, err := a.newAESWriter(keyIterations, KeySize, hashFunction)
	if err != nil {
		return nil, nil, err
	}

	aw.stream = cipher.NewCFBEncrypter(aw.block, aw.IV)
	aw.downstream = downstream
	aw.cipherType = streamCipherType

	return aw, aw.IV, nil
}

func (a *AES) New128CFBWriter(downstream io.Writer) (*AESWriter, []byte, error) {
	return a.New128CFBWriterCustom(downstream, 4096, KeySize128, sha512.New)
}

func (a *AES) New128CFBReaderCustom(upstream io.Reader, iv []byte, keyIterations int, KeySize int, hashFunction func() hash.Hash) (*AESReader, error) {
	ar, err := a.newAESReader(iv, keyIterations, KeySize, hashFunction)
	if err != nil {
		return nil, err
	}

	ar.stream = cipher.NewCFBDecrypter(ar.block, ar.IV)
	ar.upstream = upstream
	ar.cipherType = streamCipherType

	return ar, nil
}

func (a *AES) New128CFBReader(upstream io.Reader, iv []byte) (*AESReader, error) {
	return a.New128CFBReaderCustom(upstream, iv, 4096, KeySize128, sha512.New)
}
