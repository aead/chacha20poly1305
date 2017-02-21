// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package chacha20poly1305

import (
	"bytes"
	"encoding/hex"
	"math/rand"
	"testing"
)

func TestVectorsIETF(t *testing.T) { testVectors(t, chacha20Poly1305IETFTests) }

type testVector struct {
	key, nonce, aad, plaintext, out string
}

func testVectors(t *testing.T, vec []testVector) {
	for i, test := range vec {
		key, _ := hex.DecodeString(test.key)
		nonce, _ := hex.DecodeString(test.nonce)
		ad, _ := hex.DecodeString(test.aad)
		plaintext, _ := hex.DecodeString(test.plaintext)

		aead, err := NewIETFCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		ct := aead.Seal(nil, nonce, plaintext, ad)
		if ctHex := hex.EncodeToString(ct); ctHex != test.out {
			t.Errorf("#%d: got %s, want %s", i, ctHex, test.out)
			continue
		}

		plaintext2, err := aead.Open(nil, nonce, ct, ad)
		if err != nil {
			t.Errorf("#%d: Open failed", i)
			continue
		}

		if !bytes.Equal(plaintext, plaintext2) {
			t.Errorf("#%d: plaintext's don't match: got %x vs %x", i, plaintext2, plaintext)
			continue
		}

		if len(ad) > 0 {
			alterAdIdx := rand.Intn(len(ad))
			ad[alterAdIdx] ^= 0x80
			if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
				t.Errorf("#%d: Open was successful after altering additional data", i)
			}
			ad[alterAdIdx] ^= 0x80
		}

		alterNonceIdx := rand.Intn(aead.NonceSize())
		nonce[alterNonceIdx] ^= 0x80
		if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
			t.Errorf("#%d: Open was successful after altering nonce", i)
		}
		nonce[alterNonceIdx] ^= 0x80

		alterCtIdx := rand.Intn(len(ct))
		ct[alterCtIdx] ^= 0x80
		if _, err := aead.Open(nil, nonce, ct, ad); err == nil {
			t.Errorf("#%d: Open was successful after altering ciphertext", i)
		}
		ct[alterCtIdx] ^= 0x80
	}
}

func benchamarkIETFSeal(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var nonce [12]byte
	var ad [13]byte
	var out []byte

	aead, _ := NewIETFCipher(key[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out = aead.Seal(out[:0], nonce[:], buf[:], ad[:])
	}
}

func benchamarkIETFOpen(b *testing.B, buf []byte) {
	b.SetBytes(int64(len(buf)))

	var key [32]byte
	var nonce [12]byte
	var ad [13]byte
	var ct []byte
	var out []byte

	aead, _ := NewIETFCipher(key[:])
	ct = aead.Seal(ct[:0], nonce[:], buf[:], ad[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, _ = aead.Open(out[:0], nonce[:], ct[:], ad[:])
	}
}

func BenchmarkChacha20Poly1305Open_64(b *testing.B) { benchamarkIETFOpen(b, make([]byte, 64)) }
func BenchmarkChacha20Poly1305Seal_64(b *testing.B) { benchamarkIETFSeal(b, make([]byte, 64)) }
func BenchmarkChacha20Poly1305Open_1K(b *testing.B) { benchamarkIETFOpen(b, make([]byte, 1024)) }
func BenchmarkChacha20Poly1305Seal_1K(b *testing.B) { benchamarkIETFSeal(b, make([]byte, 1024)) }
func BenchmarkChacha20Poly1305Open_8K(b *testing.B) { benchamarkIETFOpen(b, make([]byte, 8*1024)) }
func BenchmarkChacha20Poly1305Seal_8K(b *testing.B) { benchamarkIETFSeal(b, make([]byte, 8*1024)) }
