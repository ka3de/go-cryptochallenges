package tools

func SplitCiphertextInBlocks(ciphertext []byte, blockSize int) [][]byte {
	blockListSize := len(ciphertext) / blockSize
	blockList := make([][]byte, blockListSize)

	for iBlock := 0; iBlock < blockListSize; iBlock++ {
		blockStart := iBlock * blockSize
		blockEnd := (iBlock + 1) * blockSize

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
