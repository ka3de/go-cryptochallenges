package cryptochallenges

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	random "math/rand"

	"github.com/ka3de/go-cryptochallenges/tools"

	cryptochallenges "github.com/ka3de/go-cryptochallenges/set1"
)

// DecryptCBC decrypts a ciphertext previously encrypted in CBC mode using the
// input block cipher
func DecryptCBC(ciphertext, iv []byte, blockCipher cipher.Block, blockSize int) ([]byte, error) {
	if len(iv) != blockSize {
		return nil, errors.New("Invalid IV size!")
	}

	blocksNumber := len(ciphertext) / blockSize
	paddedPlaintext := make([]byte, blocksNumber*blockSize)

	previousBlock := make([]byte, blockSize)
	previousBlock = iv

	for iBlock := 0; iBlock < blocksNumber; iBlock++ {
		blockStart := iBlock * blockSize
		blockEnd := blockStart + blockSize

		xorBlock := make([]byte, blockSize)
		ciphertextBlock := ciphertext[blockStart:blockEnd]
		blockCipher.Decrypt(xorBlock, ciphertextBlock)

		plaintextBlock, err := cryptochallenges.Xor(previousBlock, xorBlock)
		if err != nil {
			return nil, err
		}

		copy(paddedPlaintext[blockStart:blockEnd], plaintextBlock)
		previousBlock = ciphertextBlock
	}

	return tools.RemovePkcs7Padding(paddedPlaintext), nil
}

// EncryptsCBC encrypts in CBC mode using the input block cipher
// returns a tuple of IV, ciphertext, error (if any)
func EncryptCBC(plaintext []byte, blockCipher cipher.Block, blockSize int) ([]byte, []byte, error) {
	iv, err := generateIV(blockSize)
	if err != nil {
		return nil, nil, err
	}

	paddedPlaintext := tools.ApplyPkcs7Padding(plaintext, blockSize)
	ciphertext := make([]byte, len(paddedPlaintext))

	previousCiphertextBlock := make([]byte, blockSize)
	previousCiphertextBlock = iv

	for iBlock := 0; iBlock < len(paddedPlaintext)/blockSize; iBlock++ {
		blockStart := iBlock * blockSize
		blockEnd := blockStart + blockSize

		xoredData, err := cryptochallenges.Xor(previousCiphertextBlock, paddedPlaintext[blockStart:blockEnd])
		if err != nil {
			return nil, nil, err
		}

		ciphertextBlock := make([]byte, blockSize)
		blockCipher.Encrypt(ciphertextBlock, xoredData)

		copy(ciphertext[blockStart:blockEnd], ciphertextBlock)
		previousCiphertextBlock = ciphertextBlock
	}

	return iv, ciphertext, nil
}

func generateIV(blockSize int) ([]byte, error) {
	iv := make([]byte, blockSize)
	_, err := rand.Read(iv)
	return iv, err
}

func generateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	return key, err
}

func EncryptionOracle(plaintext []byte) ([]byte, error) {
	plaintext, err := randomizePlaintext(plaintext)
	if err != nil {
		return nil, err
	}

	key, err := generateKey(cryptochallenges.AESBlockSize)
	if err != nil {
		return nil, err

	}

	var ciphertext []byte

	if random.Intn(2) == 0 {
		// encrypt ecb
		ciphertext, err = cryptochallenges.EncryptAESinECB(plaintext, key)
	} else {
		// encrypt cbc
		aesCipher, _ := aes.NewCipher(key)
		_, ciphertext, err = EncryptCBC(plaintext, aesCipher, cryptochallenges.AESBlockSize)
	}

	return ciphertext, err
}

// randomizePlaintext adds 5-10 bytes of random data
// before and after the  input plaintext
func randomizePlaintext(plaintext []byte) ([]byte, error) {
	beforeDataSize := random.Intn(10-5) + 5
	afterDataSize := random.Intn(10-5) + 5

	beforeData := make([]byte, beforeDataSize)
	afterData := make([]byte, afterDataSize)

	_, errBefore := rand.Read(beforeData)
	_, errAfter := rand.Read(afterData)

	if errBefore != nil || errAfter != nil {
		return nil, errors.New("Error generating random data")
	}

	return append(append(beforeData, plaintext...), afterData...), nil
}

// IsECBEncrypted counts the number of repeated ciphertext blocks
// if one or more blocks are repeated the ciphertext is assumed to be encrypted in ECB mode
func IsECBEncrypted(ciphertext []byte) bool {
	return tools.CountRepeatedBlocks(ciphertext, cryptochallenges.AESBlockSize) > 0
}
