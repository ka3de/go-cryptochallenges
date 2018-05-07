package tools

func RemovePkcs7Padding(plaintext []byte) []byte {
	plaintextSize := len(plaintext)
	paddingSize := int(plaintext[plaintextSize-1])
	return plaintext[:len(plaintext)-paddingSize]
}
