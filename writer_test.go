package chacha20poly1305

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

func newSealMessage(msgLen int, key, nonce []byte) (plaintext, ciphertext []byte) {
	var aead cipher.AEAD
	var err error
	switch len(nonce) {
	case 8:
		aead, err = NewCipher(key)
		if err != nil {
			panic(fmt.Sprintf("Failed to create AEAD with 8 byte nonce: %v", err))
		}
	case 12:
		aead, err = NewIETFCipher(key)
		if err != nil {
			panic(fmt.Sprintf("Failed to create AEAD with 12 byte nonce: %v", err))
		}
	case 24:
		aead, err = NewXCipher(key)
		if err != nil {
			panic(fmt.Sprintf("Failed to create AEAD with 24 byte nonce: %v", err))
		}
	default:
		panic(fmt.Sprintf("Invalid nonce length: %d", len(nonce)))
	}

	plaintext = make([]byte, msgLen)
	ciphertext = aead.Seal(nil, nonce, plaintext, nil)
	return
}

func TestEncryptedWriter(t *testing.T) {
	key, nonce := make([]byte, 32), make([]byte, 8)

	for m := 0; m <= 256; m++ {
		nonce[0] = byte(m)
		plaintext, ciphertext := newSealMessage(m, key, nonce)

		mem := bytes.NewBuffer(nil)
		encWriter, err := EncryptWriter(mem, key, nonce)
		if err != nil {
			t.Errorf("Failed to create encrypted writer: %v", err)
		}
		encWriter.Write(plaintext)
		if err := encWriter.Close(); err != nil {
			t.Errorf("Failed to finish encryption: %v", err)
		}

		if encrypted := mem.Bytes(); !bytes.Equal(ciphertext, encrypted) {
			t.Errorf("EncryptedWriter differs from Seal:\ngot : %v\nwant: %v\n", encrypted, ciphertext)
		}

		if len(plaintext) > 40 {
			plaintext, ciphertext := newSealMessage(m, key, nonce)
			mem = bytes.NewBuffer(nil)
			encWriter, err = EncryptWriter(mem, key, nonce)
			if err != nil {
				t.Errorf("Failed to create encrypted writer: %v", err)
			}
			encWriter.Write(plaintext[:1])
			encWriter.Write(plaintext[1:5])
			encWriter.Write(plaintext[5:17])
			encWriter.Write(plaintext[17:40])
			encWriter.Write(plaintext[40:])

			if err := encWriter.Close(); err != nil {
				t.Errorf("Failed to finish encryption: %v", err)
			}
			if encrypted := mem.Bytes(); !bytes.Equal(ciphertext, encrypted) {
				t.Errorf("EncryptedWriter differs from Seal:\ngot : %v\nwant: %v\n", encrypted, ciphertext)
			}
		}
	}
}

func TestDecryptedWriter(t *testing.T) {
	key, nonce := make([]byte, 32), make([]byte, 8)

	for m := 0; m <= 256; m++ {
		nonce[0] = byte(m)
		plaintext, ciphertext := newSealMessage(m, key, nonce)

		mem := bytes.NewBuffer(nil)
		decWriter, err := DecryptWriter(mem, key, nonce)
		if err != nil {
			t.Errorf("Failed to create decrypted writer: %v", err)
		}
		decWriter.Write(ciphertext)
		if err := decWriter.Close(); err != nil {
			t.Errorf("Failed to decrypt ciphertext: %v", err)
		}

		if decrypted := mem.Bytes(); !bytes.Equal(plaintext, decrypted) {
			t.Errorf("DecryptedWriter differs from Seal:\ngot : %v\nwant: %v\n", decrypted, plaintext)
		}

		if len(ciphertext) > 40 {
			plaintext, ciphertext := newSealMessage(m, key, nonce)
			mem = bytes.NewBuffer(nil)
			decWriter, err = DecryptWriter(mem, key, nonce)
			if err != nil {
				t.Errorf("Failed to create decrypted writer: %v", err)
			}
			decWriter.Write(ciphertext[:1])
			decWriter.Write(ciphertext[1:5])
			decWriter.Write(ciphertext[5:17])
			decWriter.Write(ciphertext[17:40])
			decWriter.Write(ciphertext[40:])

			if err := decWriter.Close(); err != nil {
				t.Errorf("Failed to decrypt ciphertext: %v", err)
			}
			if decrypted := mem.Bytes(); !bytes.Equal(plaintext, decrypted) {
				t.Errorf("DecryptedWriter differs from Seal:\ngot : %v\nwant: %v\n", decrypted, plaintext)
			}

		}
	}
}

type nilWriter struct{}

func (w *nilWriter) Write(p []byte) (n int, err error) {
	return
}

func benchmarkWriter(w io.WriteCloser, size int, b *testing.B) {
	msg := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.Write(msg)
		w.Close()
	}
}

func BenchmarkEncryptedWriter64(b *testing.B) {
	writer, _ := EncryptWriter(new(nilWriter), make([]byte, 32), make([]byte, 12))
	benchmarkWriter(writer, 64, b)
}

func BenchmarkEncryptedWriter1K(b *testing.B) {
	writer, _ := EncryptWriter(new(nilWriter), make([]byte, 32), make([]byte, 12))
	benchmarkWriter(writer, 1024, b)
}

func BenchmarkEncryptedWriter8K(b *testing.B) {
	writer, _ := EncryptWriter(new(nilWriter), make([]byte, 32), make([]byte, 12))
	benchmarkWriter(writer, 8*1024, b)
}

func BenchmarkDecryptedWriter64(b *testing.B) {
	writer, _ := DecryptWriter(new(nilWriter), make([]byte, 32), make([]byte, 12))
	benchmarkWriter(writer, 64, b)
}

func BenchmarkDecryptedWriter1K(b *testing.B) {
	writer, _ := DecryptWriter(new(nilWriter), make([]byte, 32), make([]byte, 12))
	benchmarkWriter(writer, 1024, b)
}

func BenchmarkDecryptedWriter8K(b *testing.B) {
	writer, _ := DecryptWriter(new(nilWriter), make([]byte, 32), make([]byte, 12))
	benchmarkWriter(writer, 8*1024, b)
}

func ExampleEncryptWriter() {
	// we write to memory, real code may write to a file, network connection or ...
	mem := bytes.NewBuffer(nil)

	// Create a secret key - can also be generated from a passwort or ...
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Sprintf("Failed to create random encryption key: %v", err))
	}

	// Set the nonce, in this case we encrypt the first message so we set it to 1.
	// Be aware that the nonce must be unique for every message under the same key.
	nonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonce, 1)

	encryptedWriter, err := EncryptWriter(mem, key, nonce)
	if err != nil {
		panic(fmt.Sprintf("Cannot create encrypted writer: %v", err))
	}
	// Close finishes the encryption, so it MUST be called! We ensure this through defer.
	defer func() {
		if err := encryptedWriter.Close(); err != nil {
			panic(fmt.Sprintf("Failed to finish encryption: %v", err))
		}
	}()

	msg := []byte("Nobody should see this - ever!")
	// encrypt the message
	encryptedWriter.Write(msg)
	//Output:
}

func ExampleDecryptWriter() {
	// Create a secret key - can also be generated from a passwort or ...
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(fmt.Sprintf("Failed to create random encryption key: %v", err))
	}
	// Set the nonce, in this case we encrypt the first message so we set it to 1.
	// Be aware that the nonce must be unique for every message under the same key.
	nonce := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonce, 1)

	// We first encrypt a stream.
	mem := bytes.NewBuffer(nil)
	encryptedWriter, err := EncryptWriter(mem, key, nonce)
	if err != nil {
		panic(fmt.Sprintf("Cannot create encrypted writer: %v", err))
	}
	msg := []byte("Nobody should see this - ever!")
	encryptedWriter.Write(msg)
	if err := encryptedWriter.Close(); err != nil {
		panic(fmt.Sprintf("Failed to finish encryption: %v", err))
	}
	ciphertext := mem.Bytes()

	mem = bytes.NewBuffer(nil)
	// So now we want to decrypt the message
	decryptedWriter, err := DecryptWriter(mem, key, nonce)
	if err != nil {
		panic(fmt.Sprintf("Cannot create decrypted writer: %v", err))
	}
	decryptedWriter.Write(ciphertext)

	// Close finishes the decryption. Close MUST be called to successfully decrypt a
	// ciphertext. Further Close returns a non-nil error if the decryption failed - e.g. if
	// the authentication failed - so we MUST invoke Close and MUST check if the returned error
	// is nil. Otherwise the decryption will fail / was not successfull.
	if err := decryptedWriter.Close(); err != nil {
		panic(fmt.Sprintf("Failed to finish decryption: %v", err))
	}
	fmt.Println(string(mem.Bytes()))
	//Output: Nobody should see this - ever!
}
