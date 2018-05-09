package tools

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
