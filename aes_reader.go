package gocrypt

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"io"
)

var ErrPaddingError error = errors.New("padding error")

type AESReader struct {
	upstream io.Reader

	BlockSize int
	IV        []byte
	key       []byte

	buffer bytes.Buffer

	eof        bool
	cipherType int

	block     cipher.Block
	blockMode cipher.BlockMode

	stream cipher.Stream

	aead      cipher.AEAD
	chunkSize int
}

/* Read() reads from upstream ciphertext, returning plaintext.
 * Does internal buffering, and unpadding
 */
func (r *AESReader) Read(dst []byte) (int, error) {

	//If upstream is already EOF'ed, read directly from buffer
	if r.eof {
		return r.buffer.Read(dst)
	}

	switch r.cipherType {
	case blockCipherType:

		//Read to the nearest multiple of block size + 1 block
		toRead := len(dst)

		cipherText := make([]byte, nearestMultiple(toRead, AESBlockSize))
		read, err := r.upstream.Read(cipherText)
		if read != len(cipherText) || err == io.EOF {
			r.eof = true
		} else if err != nil {
			return 0, err
		}

		if read%AESBlockSize != 0 {
			return 0, ErrPaddingError
		}

		plainText := make([]byte, len(cipherText))
		r.blockMode.CryptBlocks(plainText[:read], cipherText[:read])

		if r.eof {
			//Check if this read resulted in not an entire blocks worth of bytes, if so the padding must be at the end of the current buffer and should be removed
			if read == 0 {
				rawBytes := r.buffer.Bytes()
				r.buffer.Truncate(len(rawBytes) - int(rawBytes[len(rawBytes)-1]))

				return r.buffer.Read(dst)
			}
			plainText = plainText[:read-int(plainText[read-1])]
		}

		_, err = r.buffer.Write(plainText)
		if err != nil {
			return 0, err
		}

	case streamCipherType:

		cipherText := make([]byte, len(dst))
		read, err := r.upstream.Read(cipherText)
		if read != len(cipherText) || err == io.EOF {
			r.eof = true
		} else if err != nil {
			return read, err
		}

		r.stream.XORKeyStream(dst[:read], cipherText[:read])

		return read, nil

	default:
		return 0, ErrUnknownCipherType
	}

	return r.buffer.Read(dst)
}

func nearestMultiple(wanted int, multiple int) int {
	return (wanted + (multiple-wanted%multiple)%multiple) + wanted
}
