package cryptochallenges

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"testing"

	cryptochallenges "github.com/ka3de/go-cryptochallenges/set1"
	"github.com/ka3de/go-cryptochallenges/tools"
)

func TestPKCS7Padding(t *testing.T) {
	// given
	plaintext := "YELLOW SUBMARINE"
	blockSize := 20

	expectedPlaintext := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	// when
	paddedPlaintext := tools.ApplyPkcs7Padding([]byte(plaintext), blockSize)

	// then
	if !bytes.Equal(paddedPlaintext, expectedPlaintext) {
		t.Errorf("ApplyPkcs7Padding(%s) = %s, expected %s",
			plaintext, string(paddedPlaintext), expectedPlaintext)
	}
}

func TestDecryptCBC(t *testing.T) {
	// given
	key := []byte("YELLOW SUBMARINE")
	iv := []byte("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Error invalid key: %s", err.Error())
	}

	b64Ciphertext, err := tools.ReadFileContent("./10.txt")
	if err != nil {
		t.Fatalf("Error reading ciphertext file: %s", err.Error())
	}

	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		t.Fatalf("Error decoding b64 ciphertext: %s", err.Error())
	}

	// when
	plaintext, err := DecryptCBC(ciphertext, iv, aesCipher, cryptochallenges.AESBlockSize)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext: %s", err.Error())
	}

	// then
	if string(plaintext) != challenge10ExpectedPlaintext {
		t.Errorf("DecryptCBC(...) = %s\n, expected\n%s",
			string(plaintext), challenge10ExpectedPlaintext)
	}
}
