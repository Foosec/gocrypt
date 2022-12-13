package gocrypt

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
	"io/ioutil"
	"math/rand"
)

var ErrUnknownCipherType error = errors.New("incorrect cipher type")

type AESWriter struct {
	BlockSize int
	key       []byte
	IV        []byte

	downstream io.Writer //The writer that Write() will subsequently write cipher text to.

	closed bool

	cipherType int

	buffer bytes.Buffer

	block     cipher.Block
	blockMode cipher.BlockMode

	stream cipher.Stream

	aead      cipher.AEAD
	chunkSize int
}

/*
* Close() Closes the AES stream, and flushes any remaining data to the downstream writer.
* Applies PKCS#7 padding to the remaining data, if required
 */
func (aw *AESWriter) Close() error {

	defer func() {
		aw.closed = true
	}()

	switch aw.cipherType {
	case blockCipherType:
		leftovers := aw.buffer.Len()
		if leftovers%AESBlockSize != 0 { //Apply padding
			toPad := (AESBlockSize - leftovers%AESBlockSize) % AESBlockSize
			padBytes := make([]byte, toPad)
			for i := range padBytes {
				padBytes[i] = byte(toPad)
			}
			aw.buffer.Write(padBytes)
		} else { //Full block of padding incase its a multiple of the block size
			padBytes := make([]byte, AESBlockSize)
			for i := range padBytes {
				padBytes[i] = byte(AESBlockSize)
			}
			aw.buffer.Write(padBytes)
		}

		for aw.buffer.Len() >= AESBlockSize {
			_, err := aw.Flush()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

/*
* Flushes the current buffer contents to the downstream writer.
* Write and close already do this implicitly, so unless you have a
* specific need for this, its best to leave it alone
 */
func (aw *AESWriter) Flush() (written int, err error) {

	switch aw.cipherType {
	case blockCipherType:
		dst := make([]byte, AESBlockSize)
		for aw.buffer.Len() >= AESBlockSize {
			aw.blockMode.CryptBlocks(dst, aw.buffer.Next(AESBlockSize))
			written, err = aw.downstream.Write(dst)
			if err != nil {
				return written, err
			}
		}

		return written, err

	//TODO this should be taking as large as blocks as possible
	//Because you can never re-use a nonce for a seal with the same KEY, limiting the total size.
	//This should be adjustable with sane defaults, and a protection against re-use
	case authenticatedCipherType:
		nonce := make([]byte, aw.aead.NonceSize())
		rand.Read(nonce)

		for aw.buffer.Len() >= aw.chunkSize {
			cipherText := aw.aead.Seal(nil, nonce, aw.buffer.Next(aw.chunkSize), nil)

			written, err := aw.downstream.Write(cipherText)
			if err != nil {
				return written, err
			}

		}
		return written, err

	case streamCipherType:

		dst := make([]byte, aw.buffer.Len())
		src, _ := ioutil.ReadAll(&aw.buffer)
		aw.stream.XORKeyStream(dst, src)

		written, err := aw.downstream.Write(dst)
		return written, err

	default:
		return 0, ErrUnknownCipherType
	}
}

/*
* Write() writes any number of bytes to an internal buffer, and flushes as many as possible
* to the downstream writer. Returning the number of bytes written downstream, or an error.
* If the internal buffer fails to write, the number of bytes returned is the number of bytes written into the internal buffer.
 */
func (aw *AESWriter) Write(plaintext []byte) (n int, err error) {

	if aw.closed {
		return 0, io.ErrClosedPipe
	}

	written, err := aw.buffer.Write(plaintext)
	if err != nil {
		return written, err
	}
	written, err = aw.Flush()

	return written, err
}
