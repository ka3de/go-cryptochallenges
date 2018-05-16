package tools

func ApplyPkcs7Padding(plaintext []byte, blockSize int) []byte {
	var lastBlock []byte
	plaintextBlocksCount := len(plaintext) / blockSize

	if plaintextBlocksCount > 0 {
		lastBlock = plaintext[(plaintextBlocksCount-1)*blockSize:]
	} else {
		lastBlock = plaintext
	}

	var padding []byte
	if len(lastBlock) == blockSize {
		for i := 0; i < blockSize; i++ {
			padding = append(padding, byte(blockSize))
		}
	} else {
		for i := len(lastBlock); i < blockSize; i++ {
			padding = append(padding, byte(blockSize-len(lastBlock)))
		}
	}

	return append(plaintext, padding...)
}

func RemovePkcs7Padding(plaintext []byte) []byte {
	plaintextSize := len(plaintext)
	paddingSize := int(plaintext[plaintextSize-1])
	return plaintext[:len(plaintext)-paddingSize]
}
