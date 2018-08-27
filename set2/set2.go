package cryptochallenges

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	random "math/rand"

	"github.com/ka3de/go-cryptochallenges/tools"

	cryptochallenges "github.com/ka3de/go-cryptochallenges/set1"
)

const (
	ch12UnkownStringB64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4g" +
		"YmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLC" +
		"BJIGp1c3QgZHJvdmUgYnkK"
)

// global variable to use with ECB encryption oracle
var oracleAESKey []byte

type encryptionOracle func(plaintext []byte) ([]byte, error)

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

func RandomEncryptionOracle(plaintext []byte) ([]byte, error) {
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

// IsECBEncrypted - guesses if the ciphertext has been encrypted using ECB mode
func IsECBEncrypted(ciphertext []byte, blockSize int) bool {
	return tools.CountRepeatedBlocks(ciphertext, blockSize) > 0
}

// IsECBEncryption - guesses if the input oracle encrypts data using ECB mode
func IsECBEncryption(oracle encryptionOracle, blockSize int) (bool, error) {
	plaintext := bytes.Repeat([]byte("A"), 4*blockSize)
	ciphertext, err := oracle(plaintext)
	if err != nil {
		return false, err
	}

	return tools.CountRepeatedBlocks(ciphertext, blockSize) > 0, nil
}

func ECBEncryptionOracle(plaintext []byte) ([]byte, error) {
	// assign global fixed key as key
	key := oracleAESKey

	// decode and append unkown string to plaintext
	unkownString, err := base64.StdEncoding.DecodeString(ch12UnkownStringB64)
	if err != nil {
		return nil, err
	}
	plaintext = append(plaintext, unkownString...)

	// encrypt
	return cryptochallenges.EncryptAESinECB(plaintext, key)
}

func ByteAtATimeECBDecryptionSimple() ([]byte, error) {
	// generate global fixed key
	oracleAESKey = make([]byte, cryptochallenges.AESBlockSize)
	_, err := rand.Read(oracleAESKey)

	// get block size
	blockSize, err := getBlockSize(ECBEncryptionOracle)
	if err != nil {
		return nil, err
	}

	// detect ECB
	isECB, err := IsECBEncryption(ECBEncryptionOracle, blockSize)
	if err != nil {
		return nil, err
	}
	if !isECB {
		return nil, errors.New("ciphertext is not ECB encrypted")
	}

	// decrypt ECB
	unkownText, err := breakECB(ECBEncryptionOracle, blockSize)
	if err != nil {
		return nil, err
	}

	return unkownText, nil
}

// getBlockSize - returns the block size being used by the input encryption oracle
func getBlockSize(oracle encryptionOracle) (int, error) {
	plaintext := []byte("A")
	baseCiphertext, err := oracle(plaintext)
	if err != nil {
		return 0, err
	}

	ciphertext := make([]byte, len(baseCiphertext))
	copy(ciphertext, baseCiphertext)

	for i := 1; len(ciphertext) == len(baseCiphertext); i++ {
		plaintext = bytes.Repeat([]byte("A"), i)
		ciphertext, err = oracle(plaintext)
		if err != nil {
			return 0, err
		}
	}

	return len(ciphertext) - len(baseCiphertext), nil
}

func breakECB(oracle encryptionOracle, blockSize int) ([]byte, error) {
	var decryptedText []byte

	unknownTextCiphertext, err := oracle([]byte(""))
	if err != nil {
		return nil, err
	}

	for iBlock := 1; iBlock <= len(unknownTextCiphertext)/blockSize; iBlock++ {
		for i := 1; i <= blockSize; i++ {
			plaintext := bytes.Repeat([]byte("A"), blockSize-i)

			ciphertext, err := oracle(plaintext)
			if err != nil {
				return nil, err
			}

			for c := 0; c <= 255; c++ {
				auxPlaintext := append(plaintext, decryptedText...)
				auxPlaintext = append(auxPlaintext, byte(c))

				auxCiphertext, err := oracle(auxPlaintext)
				if err != nil {
					return nil, err
				}

				if equalSlices(auxCiphertext[:iBlock*blockSize], ciphertext[:iBlock*blockSize]) {
					decryptedText = append(decryptedText, byte(c))
					break
				}
			}
		}
	}

	return tools.RemovePkcs7Padding(decryptedText), nil
}

func equalSlices(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
