package gocrypt

import (
	"bytes"
	"io"
	"testing"
)

func TestNewAES(t *testing.T) {
	aes := NewAES([]byte("This is a secret"))
	if aes == nil {
		t.Fatal("Failed to create AES")
	}
}

func TestAESWriter(t *testing.T) {
	aes := NewAES([]byte("This is a secret"))
	if aes == nil {
		t.Error("Failed to create AES")
	}

	res := bytes.NewBuffer([]byte{})
	writer, _, err := aes.NewWriter(res)
	if err != nil {
		t.Error("Failed to create AES Writer", err)
	}
	if writer == nil {
		t.Error("Writer nil")
	}
	writer.Close()
}

func TestAESWriteAndClose(t *testing.T) {
	aes := NewAES([]byte("This is a secret"))
	if aes == nil {
		t.Error("Failed to create AES")
	}

	res := bytes.NewBuffer([]byte{})
	writer, _, err := aes.NewWriter(res)
	if err != nil {
		t.Error("Failed to create AES Writer", err)
	}
	if writer == nil {
		t.Error("Writer nil")
	}

	written, err := writer.Write([]byte("AAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Error("Failed to write to AES Writer", err)
	}
	if written != 16 {
		t.Error("Written bytes not 16", written)
	}

	err = writer.Close()
	if err != nil {
		t.Error("Failed to close AES Writer", err)
	}

	if len(res.Bytes()) != 32 {
		t.Error("Written bytes not 32, padding wrong?", len(res.Bytes()))
	}

}

func TestReadAndClose(t *testing.T) {
	aes := NewAES([]byte("This is a secret"))

	buf := bytes.NewBuffer([]byte{})
	aw, iv, err := aes.NewWriter(buf)
	if err != nil {
		t.Error(err)
	}

	message := []byte("THIS IS A SECRET MESSAGE")

	aw.Write(message)
	aw.Close()

	pbuf := make([]byte, 10000)
	reader, err := aes.NewReader(buf, iv)
	if err != nil {
		t.Error(err)
	}

	r, err := reader.Read(pbuf)
	if err != nil {
		t.Error(err)
	}
	if string(pbuf[:r]) != string(message) {
		t.Error("Read bytes not equal to written bytes")
	}
}

func TestAES128CFBWriter(t *testing.T) {
	aes := NewAES([]byte("this is a secret"))

	buf := bytes.NewBuffer(nil)
	writer, _, err := aes.New128CFBWriter(buf)
	if err != nil {
		t.Error(err)
	}
	message := []byte("This is a secret message")

	_, err = writer.Write(message)
	if err != nil {
		t.Error(err)
	}

	err = writer.Close()
	if err != nil {
		t.Error(err)
	}
}

func TestAES128CFBReader(t *testing.T) {
	aes := NewAES([]byte("this is a secret"))

	buf := bytes.NewBuffer(nil)
	writer, iv, err := aes.New128CFBWriter(buf)
	if err != nil {
		t.Error(err)
	}
	message := []byte("This is a secret message")

	_, err = writer.Write(message)
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	reader, err := aes.New128CFBReader(buf, iv)
	if err != nil {
		t.Error(err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(out, message) {
		t.Error("Decrypted plaintext does not equal original plaintext", out)
	}

}

func TestAES256CFBWriter(t *testing.T) {
	aes := NewAES([]byte("this is a secret"))

	buf := bytes.NewBuffer(nil)
	writer, _, err := aes.New256CFBWriter(buf)
	if err != nil {
		t.Error(err)
	}
	message := []byte("This is a secret message")

	_, err = writer.Write(message)
	if err != nil {
		t.Error(err)
	}

	err = writer.Close()
	if err != nil {
		t.Error(err)
	}
}

func TestAES256CFBReader(t *testing.T) {
	aes := NewAES([]byte("this is a secret"))

	buf := bytes.NewBuffer(nil)
	writer, iv, err := aes.New256CFBWriter(buf)
	if err != nil {
		t.Error(err)
	}
	message := []byte("This is a secret message")

	_, err = writer.Write(message)
	if err != nil {
		t.Error(err)
	}
	err = writer.Close()
	if err != nil {
		t.Error(err)
	}

	reader, err := aes.New256CFBReader(buf, iv)
	if err != nil {
		t.Error(err)
	}
	out, err := io.ReadAll(reader)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(out, message) {
		t.Error("Decrypted plaintext does not equal original plaintext", out)
	}

}

// Fuzz CFB
func FuzzAESCFB128(f *testing.F) {
	f.Add([]byte("password"), []byte("data to encrypt"))
	f.Fuzz(func(t *testing.T, secret []byte, data []byte) {
		aes := NewAES(secret)

		buf := bytes.NewBuffer(nil)
		writer, iv, err := aes.New128CFBWriter(buf)
		if err != nil {
			t.Error(err)
		}
		_, err = writer.Write(data)
		if err != nil {
			t.Error(err)
		}
		err = writer.Close()
		if err != nil {
			t.Error(err)
		}

		reader, err := aes.New128CFBReader(buf, iv)
		if err != nil {
			t.Error(err)
		}
		out, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(out, data) {
			t.Error("Decrypted plaintext does not equal original plaintext", out)
		}
	})
}

func FuzzAESCFB256(f *testing.F) {
	f.Add([]byte("password"), []byte("data to encrypt"))
	f.Fuzz(func(t *testing.T, secret []byte, data []byte) {
		aes := NewAES(secret)

		buf := bytes.NewBuffer(nil)
		writer, iv, err := aes.New256CFBWriter(buf)
		if err != nil {
			t.Error(err)
		}
		_, err = writer.Write(data)
		if err != nil {
			t.Error(err)
		}
		err = writer.Close()
		if err != nil {
			t.Error(err)
		}

		reader, err := aes.New256CFBReader(buf, iv)
		if err != nil {
			t.Error(err)
		}
		out, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
		}
		if !bytes.Equal(out, data) {
			t.Error("Decrypted plaintext does not equal original plaintext", out)
		}
	})
}

// Fuzz the contents, lengths and keys
func FuzzAESDefaultsInputs(f *testing.F) {

	f.Add([]byte("password"), []byte("data to encrypt"))
	f.Fuzz(func(t *testing.T, secret []byte, data []byte) {
		aes := NewAES(secret)

		buf := bytes.NewBuffer(nil)
		writer, iv, err := aes.NewWriter(buf)
		if err != nil {
			t.Error(err)
		}
		writer.Write(data)
		writer.Close()

		reader, err := aes.NewReader(buf, iv)
		if err != nil {
			t.Error(err)
		}

		out, err := io.ReadAll(reader)
		if err != nil {
			t.Error(err)
		}

		if !bytes.Equal(out, data) {
			t.Error("Input and output not the same!")
			t.FailNow()
		}
	})
}

func FuzzAESDefaultsBuffers(f *testing.F) {
	f.Add([]byte("password"), []byte("data to encrypt"), 10, 10)
	f.Fuzz(func(t *testing.T, secret []byte, data []byte, writeSize int, readSize int) {

		//Zero sized buffers will fail on io.CopyBuffer
		if writeSize <= 0 || readSize <= 0 {
			t.Skip()
		}

		aes := NewAES(secret)

		buf := bytes.NewBuffer(nil)
		writer, iv, err := aes.NewWriter(buf)
		if err != nil {
			t.Error(err)
		}

		dataBuf := bytes.NewBuffer(data)

		writeBuffer := make([]byte, writeSize)
		io.CopyBuffer(writer, dataBuf, writeBuffer)

		writer.Close()

		reader, err := aes.NewReader(buf, iv)
		if err != nil {
			t.Error(err)
		}

		out := bytes.NewBuffer(nil)

		readBuffer := make([]byte, readSize)
		io.CopyBuffer(out, reader, readBuffer)

		if !bytes.Equal(out.Bytes(), data) {
			t.Error("Input and output not the same!")
			t.FailNow()
		}
	})
}
