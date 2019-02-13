package cryptochallenges

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	random "math/rand"
	"strings"

	"github.com/ka3de/go-cryptochallenges/tools"

	cryptochallenges "github.com/ka3de/go-cryptochallenges/set1"
)

const (
	ch12UnkownStringB64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4g" +
		"YmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLC" +
		"BJIGp1c3QgZHJvdmUgYnkK"
)

// global symmetric key variable to use with encryption oracles
var oracleAESKey []byte

type encryptionOracle func(plaintext []byte) ([]byte, error)

type profileOracle func(email string) ([]byte, error)

// DecryptCBC decrypts a ciphertext previously encrypted in CBC mode using the
// input block cipher
func DecryptCBC(ciphertext, iv []byte, blockCipher cipher.Block, blockSize int) ([]byte, error) {
	if len(iv) != blockSize {
		return nil, errors.New("invalid IV size")
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

// EncryptCBC encrypts in CBC mode using the input block cipher
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

// RandomEncryptionOracle - encrypts the given plaintext after prepending and appending some random text to it
// encryption on average 50% of the time using AES in ECB mode and 50% of the time using AES in CBC mode
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

// isECBEncryption - guesses if the input oracle encrypts data using ECB mode
func isECBEncryption(oracle encryptionOracle, blockSize int) (bool, error) {
	plaintext := bytes.Repeat([]byte("A"), 4*blockSize)
	ciphertext, err := oracle(plaintext)
	if err != nil {
		return false, err
	}

	return tools.CountRepeatedBlocks(ciphertext, blockSize) > 0, nil
}

func initializeOracleKey() error {
	if len(oracleAESKey) > 0 {
		return nil // already initialized
	}

	oracleAESKey = make([]byte, cryptochallenges.AESBlockSize)
	_, err := rand.Read(oracleAESKey)
	return err
}

func ecbEncryptionOracle(plaintext []byte) ([]byte, error) {
	// initialize and assign oracle key
	err := initializeOracleKey()
	if err != nil {
		return nil, err
	}
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
	// get block size
	blockSize, err := getBlockSize(ecbEncryptionOracle)
	if err != nil {
		return nil, err
	}

	// detect ECB
	isECB, err := isECBEncryption(ecbEncryptionOracle, blockSize)
	if err != nil {
		return nil, err
	}
	if !isECB {
		return nil, errors.New("ciphertext is not ECB encrypted")
	}

	// decrypt ECB
	unkownText, err := breakECB(ecbEncryptionOracle, blockSize)
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

// UserProfile - represents a user profile
type UserProfile struct {
	Email string `json:"email"`
	UID   string `json:"uid"`
	Role  string `json:"role"`
}

// NewUserProfile - returns a new encoded user profile given a user email
func NewUserProfile(email string) string {
	// strip '&' and '=' characters
	email = strings.Replace(email, "&", "", -1)
	email = strings.Replace(email, "=", "", -1)
	return "email=" + email + "&uid=10&role=user" //TODO: Improve this!
}

// ParseUserProfile - parses an encoded user profile and returns its JSON object representation
func ParseUserProfile(profile string) (UserProfile, error) {
	profileAttributes := strings.Split(profile, "&")

	// build JSON object string
	profileObject := "{\n"
	for i, attribute := range profileAttributes {
		if i != 0 {
			profileObject += ",\n"
		}

		attributeComponents := strings.Split(attribute, "=")
		attributeKey := attributeComponents[0]
		attributeValue := attributeComponents[1]

		profileObject += "\"" + attributeKey + "\"" + ":" + "\"" + attributeValue + "\""
	}
	profileObject += "\n}"

	// unmarshal JSON and return object
	userProfile := UserProfile{}
	err := json.Unmarshal([]byte(profileObject), &userProfile)
	if err != nil {
		return UserProfile{}, err
	}

	return userProfile, nil
}

// keyValueProfileOracle - generates a new encrypted user profile from given email
func keyValueProfileOracle(email string) ([]byte, error) {
	// initialize and assign oracle key
	err := initializeOracleKey()
	if err != nil {
		return nil, err
	}
	key := oracleAESKey

	// create encoded profile
	encodedProfile := NewUserProfile(email)

	// encrypt AES ECB
	return cryptochallenges.EncryptAESinECB([]byte(encodedProfile), key)
}

// BreakECBwithCutAndPaste - breaks ECB encryption performed by an oracle that encrypts
// a user profile for a given email by using cut and paste of ciphertext due to ECB blocks malleability
func BreakECBwithCutAndPaste() (string, error) {
	profileOracle := keyValueProfileOracle

	// isolate 'admin' in a block
	paddedAdminRole := string(tools.ApplyPkcs7Padding([]byte("admin"), cryptochallenges.AESBlockSize))
	isolateAdminEmail := "          " + paddedAdminRole // email that makes 'admin' to fit at the start of a block
	isolateAdminEncryptedProfile, err := profileOracle(isolateAdminEmail)
	if err != nil {
		return "", err
	}
	adminCiphertext := isolateAdminEncryptedProfile[cryptochallenges.AESBlockSize : 2*cryptochallenges.AESBlockSize] // second block

	// get ciphertext for an email that makes the second block
	// ending match the begining of the role value
	emailThatLetsRoleFitInLastBlock := "emailThatFits"
	emailThatFitsEncryptedProfile, err := profileOracle(emailThatLetsRoleFitInLastBlock)
	if err != nil {
		return "", err
	}
	roleValueBlockPos := ((len(emailThatFitsEncryptedProfile) / cryptochallenges.AESBlockSize) - 1) * cryptochallenges.AESBlockSize
	userProfileThatFitsRoleInLastBlock := emailThatFitsEncryptedProfile[:roleValueBlockPos]

	// concatenate and decrypt to obtain admin user profile
	adminUserProfileCiphertext := append(userProfileThatFitsRoleInLastBlock, adminCiphertext...)
	adminUserProfilePlaintext, err := cryptochallenges.DecryptAESinECB(adminUserProfileCiphertext, oracleAESKey)
	if err != nil {
		return "", nil
	}
	return string(adminUserProfilePlaintext), nil
}
