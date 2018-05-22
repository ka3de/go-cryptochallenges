package cryptochallenges

import (
	"crypto/cipher"
	"errors"

	"github.com/ka3de/go-cryptochallenges/tools"

	cryptochallenges "github.com/ka3de/go-cryptochallenges/set1"
)

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
