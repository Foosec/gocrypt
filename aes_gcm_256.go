/*
golangs AES GCM does not allow it to encrypt any number of bytes
with a given nonce. This complicates the implementation of aes_reader and aes_writer, due to having to:

- split the stream into chunks
- include the (multiple) nonces
- know the chunk size


*/

package gocrypt

import (
	"crypto/cipher"
	"crypto/sha512"
	"hash"
	"io"
)

// The maximum size for the encryption will be 2^32 * defaultChunkSize in bytes. This results in a little over 17TB
const defaultChunkSize = 4096

func (a *AES) New256GCMWriterCustom(downstream io.Writer, keyIterations int, keySize int, hashFunction func() hash.Hash, chunkSize int) (*AESWriter, error) {
	aw, err := a.newAESWriter(keyIterations, keySize, hashFunction)
	if err != nil {
		return nil, err
	}

	aw.aead, err = cipher.NewGCM(aw.block)
	if err != nil {
		return nil, err
	}
	aw.downstream = downstream
	aw.cipherType = authenticatedCipherType
	aw.chunkSize = chunkSize

	return aw, nil
}

func (a *AES) New256GCMWriter(downstream io.Writer) (*AESWriter, error) {
	return a.New256GCMWriterCustom(downstream, 4096, KeySize256, sha512.New, defaultChunkSize)
}

//Readers

func (a *AES) New256GCMReaderCustom(upstream io.Reader, keyIterations int, KeySize int, hashFunction func() hash.Hash, chunkSize int) (*AESReader, error) {
	ar, err := a.newAESReader(nil, keyIterations, KeySize, hashFunction)
	if err != nil {
		return nil, err
	}

	ar.aead, err = cipher.NewGCM(ar.block)
	if err != nil {
		return nil, err
	}
	ar.upstream = upstream
	ar.cipherType = authenticatedCipherType
	ar.chunkSize = chunkSize

	return ar, nil
}

func (a *AES) New256GCMReader(upstream io.Reader) (*AESReader, error) {
	return a.New256GCMReaderCustom(upstream, 4096, KeySize256, sha512.New, defaultChunkSize)
}
