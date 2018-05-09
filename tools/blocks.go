package tools

import (
	"bytes"
)

func SplitCiphertextInBlocks(ciphertext []byte, blockSize int) [][]byte {
	blockListSize := len(ciphertext) / blockSize
	blockList := make([][]byte, blockListSize)

	for iBlock := 0; iBlock < blockListSize; iBlock++ {
		blockStart := iBlock * blockSize
		blockEnd := blockStart + blockSize

		block := make([]byte, blockSize)
		copy(block, ciphertext[blockStart:blockEnd])

		blockList[iBlock] = block
	}

	return blockList
}

func TransposeBlocks(blockList [][]byte) [][]byte {
	transposedblockSize := len(blockList)
	transposedBlocksNumber := len(blockList[0])

	transposedBlockList := make([][]byte, transposedBlocksNumber)

	for iByte := 0; iByte < transposedBlocksNumber; iByte++ {

		block := make([]byte, transposedblockSize)
		for iBlock := 0; iBlock < transposedblockSize; iBlock++ {
			block[iBlock] = blockList[iBlock][iByte]
		}

		transposedBlockList[iByte] = block
	}

	return transposedBlockList
}

// CountRepeatedBlocksHex counts the repeated blocks in an hex encoded ciphertext
// blocksize is the block size in bytes
func CountRepeatedBlocksHex(hexCiphertext string, blockSize int) int {
	blockSizeHex := blockSize / 2

	repeatedBlocks := 0

	for len(hexCiphertext) > 0 {
		block := hexCiphertext[:blockSizeHex]
		hexCiphertext = hexCiphertext[blockSizeHex:]

		for iBlock := 0; iBlock < len(hexCiphertext)/(blockSizeHex); iBlock++ {
			blockStart := iBlock * blockSizeHex
			blockEnd := blockStart + blockSizeHex

			if block == hexCiphertext[blockStart:blockEnd] {
				repeatedBlocks++
				iBlock--
				hexCiphertext = hexCiphertext[:blockStart] + hexCiphertext[blockEnd:]
			}
		}
	}

	return repeatedBlocks
}

func CountRepeatedBlocks(ciphertext []byte, blockSize int) int {
	ciphertextBlocks := len(ciphertext) / blockSize
	repeatedBlocks := 0

	for i := 0; i < ciphertextBlocks; i++ {
		for j := 0; j < ciphertextBlocks; j++ {
			if i != j {
				iBlock := ciphertext[i*blockSize : (i+1)*blockSize]
				jBlock := ciphertext[j*blockSize : (j+1)*blockSize]

				if bytes.Equal(iBlock, jBlock) {
					repeatedBlocks++
				}
			}
		}
	}

	return repeatedBlocks
}
