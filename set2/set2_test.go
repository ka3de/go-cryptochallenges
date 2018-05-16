package cryptochallenges

import (
	"bytes"
	"testing"

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
