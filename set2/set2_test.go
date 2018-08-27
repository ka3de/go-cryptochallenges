package cryptochallenges

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"math"
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

func TestEncryptAndDecryptCBC(t *testing.T) {
	// given
	plaintext := []byte("plaintext")
	key := []byte("YELLOW SUBMARINE")
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Error invalid key: %s", err.Error())
	}

	// when
	iv, ciphertext, err := EncryptCBC(plaintext, aesCipher, cryptochallenges.AESBlockSize)
	if err != nil {
		t.Fatalf("Error encrypting plaintext: %s", err.Error())
	}

	decryptedCiphertext, err := DecryptCBC(ciphertext, iv, aesCipher, cryptochallenges.AESBlockSize)
	if err != nil {
		t.Fatalf("Error decrypting ciphertext: %s", err.Error())
	}

	// then
	if string(plaintext) != string(decryptedCiphertext) {
		t.Errorf("Error encrypting and decrypting in CBC mode:\nobtained -> %s\nexpected ->%s",
			string(decryptedCiphertext), string(plaintext))
	}
}

func TestEcbCbcDetectionOracle(t *testing.T) {
	// given
	totalEncryptions := 250
	maxErrorMargin := 6.0

	plaintext := bytes.Repeat([]byte("A"), 4*cryptochallenges.AESBlockSize)
	ecbCounter, cbcCounter := 0.0, 0.0

	// when
	for i := 0; i < totalEncryptions; i++ {
		ciphertext, err := RandomEncryptionOracle(plaintext)
		if err != nil {
			t.Fatalf("Error encryption oracle: %s", err.Error())
		}

		if IsECBEncrypted(ciphertext, cryptochallenges.AESBlockSize) {
			ecbCounter++
		} else {
			cbcCounter++
		}
	}

	// then
	diffPercentage := (math.Abs(ecbCounter-cbcCounter) * 100) / float64(totalEncryptions)
	if diffPercentage > maxErrorMargin {
		t.Errorf("Error detecting ECB encryption, max error margin overcome:\nmax: %f\nerr:%f",
			maxErrorMargin, diffPercentage)
	}
}

func TestByteAtATimeECBDecryptionSimple(t *testing.T) {
	// given

	// when
	unknownPlaintext, err := ByteAtATimeECBDecryptionSimple()
	if err != nil {
		t.Fatalf("Error decrypting ECB byte at a time: %s", err.Error())
	}

	// then
	if string(unknownPlaintext) != challenge12ExpectedPlaintext {
		t.Errorf("Error breaking ECB byte at a time:\nobtained -> %s\nexpected ->%s",
			string(unknownPlaintext), challenge12ExpectedPlaintext)
	}
}
