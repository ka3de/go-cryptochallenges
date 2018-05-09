package cryptochallenges

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"

	"github.com/ka3de/go-cryptochallenges/tools"
)

const aesBlockSize = 16

func HexToB64(hexData string) (string, error) {
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

func XorHexData(hexData1, hexData2 string) (string, error) {
	if len(hexData1) != len(hexData2) {
		return "", errors.New("input datas do not match!")
	}

	data1, err1 := hex.DecodeString(hexData1)
	data2, err2 := hex.DecodeString(hexData2)
	if err1 != nil || err2 != nil {
		return "", errors.New("Error decoding HEX data!")
	}

	xorData, err := Xor(data1, data2)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(xorData), nil
}

func Xor(data1, data2 []byte) ([]byte, error) {
	key := data1
	plaintext := data2

	if len(data2) < len(data1) {
		key = data2
		plaintext = data1
	}

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i++ {
		ciphertext[i] = plaintext[i] ^ key[i%len(key)]
	}

	return ciphertext, nil
}

type SingleByteXorResult struct {
	score     int
	key       rune
	plaintext string
}

// BreakSingleByteXor tries to decrypt by brute force a ciphertext
// that's supposed to have  been encrypted by a one byte key
// returns the most probable plaintext, the key and its score assuming it's an english text
func BreakSingleByteXor(ciphertext []byte) (SingleByteXorResult, error) {
	bestScore := 0
	bestPlaintext := ""
	bestKey := rune(0)

	for char := rune(0); char <= 255; char++ {
		plaintext, err := Xor(ciphertext, []byte(string(char)))
		if err != nil {
			return SingleByteXorResult{}, err
		}

		score := tools.GetLangScoring(string(plaintext))
		if score > bestScore {
			bestScore = score
			bestPlaintext = string(plaintext)
			bestKey = char
		}
	}

	return SingleByteXorResult{bestScore, bestKey, bestPlaintext}, nil
}

// DetectSingleByteXor detects which of the ciphertexts from the
// input list has been encrypted using xor function and a single
// byte key
// ciphertextList is an HEX encoded list of ciphertexts
// returns the plaintext of the guessed ciphertext
func DetectSingleByteXor(ciphertextList []string) (string, error) {
	bestScore := 0
	bestPlaintext := ""

	for _, hexCiphertext := range ciphertextList {
		ciphertext, err := hex.DecodeString(hexCiphertext)
		if err != nil {
			return "", err
		}

		singleByteXorResult, err := BreakSingleByteXor(ciphertext)
		if err != nil {
			return "", err
		}

		if singleByteXorResult.score > bestScore {
			bestScore = singleByteXorResult.score
			bestPlaintext = singleByteXorResult.plaintext
		}
	}

	return bestPlaintext, nil
}

func BreakRepeatingKeyXor(ciphertext []byte) ([]byte, error) {
	keySize, err := guessRepeatingKeyXorSize(ciphertext, 2, 40)
	if err != nil {
		return nil, err
	}

	ciphertextBlocks := tools.SplitCiphertextInBlocks(ciphertext, keySize)
	transposedCiphertextBlocks := tools.TransposeBlocks(ciphertextBlocks)

	key := make([]byte, len(transposedCiphertextBlocks))
	for iBlock := 0; iBlock < len(transposedCiphertextBlocks); iBlock++ {
		singleByteXorResult, err := BreakSingleByteXor(transposedCiphertextBlocks[iBlock])
		if err != nil {
			return nil, err
		}
		key[iBlock] = byte(singleByteXorResult.key)
	}

	return Xor(ciphertext, key)
}

func guessRepeatingKeyXorSize(ciphertext []byte, minKeySize, maxKeySize int) (int, error) {
	var minHammingDistance float64 = float64(maxKeySize) * 8
	guessedKeySize := 0

	for keySize := minKeySize; keySize <= maxKeySize; keySize++ {

		ciphertextBlocksSize := len(ciphertext) / keySize
		var hammingDistance float64 = 0

		for iBlock := 0; iBlock < ciphertextBlocksSize-1; iBlock++ {
			firstBlockStart := iBlock * keySize
			firstBlockEnd := firstBlockStart + keySize

			secondBlockStart := firstBlockEnd
			secondBlockEnd := secondBlockStart + keySize

			blocksDistance, err := tools.HammingDistance(ciphertext[firstBlockStart:firstBlockEnd],
				ciphertext[secondBlockStart:secondBlockEnd])
			if err != nil {
				return 0, err
			}

			hammingDistance += float64(blocksDistance) / float64(keySize)
		}

		averageHammingDistance := hammingDistance / float64(ciphertextBlocksSize)
		if averageHammingDistance < minHammingDistance {
			minHammingDistance = averageHammingDistance
			guessedKeySize = keySize
		}
	}

	return guessedKeySize, nil
}

func DecryptAESinECB(ciphertext, key []byte) ([]byte, error) {
	if len(ciphertext)%aesBlockSize != 0 {
		return nil, errors.New("Invalid ciphertext length")
	}

	plaintext := make([]byte, len(ciphertext))
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	for iBlock := 0; iBlock < len(ciphertext)/aesBlockSize; iBlock++ {
		blockStart := iBlock * aesBlockSize
		blockEnd := blockStart + aesBlockSize

		aesCipher.Decrypt(plaintext[blockStart:blockEnd], ciphertext[blockStart:blockEnd])
	}

	return plaintext, nil
}

// DetectAESinECB parses a list of hex encoded ciphertext
// and returns the one that guesses has been encrypted using
// AES block cipher in ECB mode
func DetectAESinECB(hexCiphertextList []string) (string, error) {
	maxRepeatedBlocks := 0
	aesEcbCiphertext := ""

	for _, hexCiphertext := range hexCiphertextList {
		if len(hexCiphertext)%(aesBlockSize/2) != 0 {
			return "", errors.New("Invalid ciphertext length!")
		}

		ciphertext, err := hex.DecodeString(hexCiphertext)
		if err != nil {
			return "", err
		}
		repeatedBlocks := tools.CountRepeatedBlocks(ciphertext, aesBlockSize)

		if repeatedBlocks > maxRepeatedBlocks {
			maxRepeatedBlocks = repeatedBlocks
			aesEcbCiphertext = hexCiphertext
		}
	}

	return aesEcbCiphertext, nil
}
