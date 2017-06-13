package chacha20poly1305

import (
	"bytes"
	"io"
	"testing"

	gochacha20 "golang.org/x/crypto/chacha20poly1305"
)

func TestEncryptWriterSinglePart(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	aead, err := gochacha20.New(key)
	if err != nil {
		t.Errorf("Failed to create C20P1305 cipher: %v", err)
	}

	plaintext := []byte("minio is awesome - really, really awesome!")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	buf := bytes.NewBuffer(nil)

	w, err := EncryptWriter(buf, key, nonce)
	if err != nil {
		t.Errorf("Failed to create AES-GCM encrypted writer: %v", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		t.Errorf("Failed to write to Writer: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("Failed to close to Writer: %v", err)
	}

	if !bytes.Equal(ciphertext, buf.Bytes()) {
		t.Errorf("Ciphertext are not equal\n got: %v\nwant: %v", buf.Bytes(), ciphertext)
	}
}

func TestEncryptWriterMultiPart(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	aead, err := gochacha20.New(key)
	if err != nil {
		t.Errorf("Failed to create C20P1305 cipher: %v", err)
	}

	plaintext := []byte("minio is awesome - really, really awesome!")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	buf := bytes.NewBuffer(nil)

	w, err := EncryptWriter(buf, key, nonce)
	if err != nil {
		t.Errorf("Failed to create C20P1305 encrypted writer: %v", err)
	}
	for i := range plaintext {
		if _, err := w.Write(plaintext[i : i+1]); err != nil {
			t.Errorf("Failed to write to Writer: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Errorf("Failed to close to Writer: %v", err)
	}

	if !bytes.Equal(ciphertext, buf.Bytes()) {
		t.Errorf("Ciphertext are not equal\n got: %v\nwant: %v", buf.Bytes(), ciphertext)
	}
}

func TestDecryptWriterSinglePart(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	aead, err := gochacha20.New(key)
	if err != nil {
		t.Errorf("Failed to create C20P1305 cipher: %v", err)
	}

	plaintext := []byte("minio is awesome - really, really awesome!")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Errorf("Failed to open ciphertext: %v", err)
	}

	buf := bytes.NewBuffer(nil)

	w, err := DecryptWriter(buf, key, nonce)
	if err != nil {
		t.Errorf("Failed to create C20P1305-GCM decrypted writer: %v", err)
	}
	if _, err := w.Write(ciphertext); err != nil {
		t.Errorf("Failed to write to Writer: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Errorf("Failed to close to Writer: %v", err)
	}

	if !bytes.Equal(decrypted, buf.Bytes()) {
		t.Errorf("Decrypted ciphertext are not equal\n got: %v\nwant: %v", buf.Bytes(), decrypted)
	}
}

func TestDecryptWriterMultiPart(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)

	aead, err := NewIETFCipher(key)
	if err != nil {
		t.Errorf("Failed to create C20P1305 cipher: %v", err)
	}

	plaintext := []byte("minio is awesome - really, really awesome!")
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	decrypted, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		t.Errorf("Failed to open ciphertext: %v", err)
	}

	buf := bytes.NewBuffer(nil)

	w, err := DecryptWriter(buf, key, nonce)
	if err != nil {
		t.Errorf("Failed to create C20P1305-GCM decrypted writer: %v", err)
	}
	if _, err := w.Write(ciphertext[:33]); err != nil {
		t.Errorf("Failed to write to Writer: %v", err)
	}
	if _, err := w.Write(ciphertext[33:]); err != nil {
		t.Errorf("Failed to write to Writer: %v", err)
	}

	if err := w.Close(); err != nil {
		t.Errorf("Failed to close the Writer: %v", err)
	}

	if !bytes.Equal(decrypted, buf.Bytes()) {
		t.Errorf("Decrypted ciphertext are not equal\n got: %v\nwant: %v", buf.Bytes(), decrypted)
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
