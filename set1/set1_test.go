package cryptochallenges

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/ka3de/go-cryptochallenges/tools"
)

func TestHexToB64(t *testing.T) {
	// given
	expectedB64Data := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	hexData := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	// when
	b64Data, err := HexToB64(hexData)
	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	// then
	if b64Data != expectedB64Data {
		t.Errorf("HexToB64(%s) = %s, expected %s", hexData, b64Data, expectedB64Data)
	}
}

func TestXorHexData(t *testing.T) {
	// given
	expectedXorHexData := "746865206b696420646f6e277420706c6179"
	hexData1 := "1c0111001f010100061a024b53535009181c"
	hexData2 := "686974207468652062756c6c277320657965"

	// when
	xorHexData, err := XorHexData(hexData1, hexData2)
	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	// then
	if xorHexData != expectedXorHexData {
		t.Errorf("XorHexData(%s, %s) = %s, expected %s", hexData1, hexData2, xorHexData, expectedXorHexData)
	}
}

func TestBreakSingleByteXor(t *testing.T) {
	// given
	ciphertext, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	expectedPlaintext := "Cooking MC's like a pound of bacon"

	// when
	singleByteXorResult, err := BreakSingleByteXor(ciphertext)
	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	// then
	if singleByteXorResult.plaintext != expectedPlaintext {
		t.Errorf("BreakSingleByteXor(%x) = %s, expected %s",
			ciphertext, singleByteXorResult.plaintext, expectedPlaintext)
	}
}

func TestDetectSingleByteXor(t *testing.T) {
	// given
	expectedPlaintext := "Now that the party is jumping\n"
	ciphertextList, err := tools.ReadFileLines("./4.txt")
	if err != nil {
		t.Errorf("Error opening ciphertext list file: %s", err.Error())
	}

	// when
	plaintext, err := DetectSingleByteXor(ciphertextList)
	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	// then
	if plaintext != expectedPlaintext {
		t.Errorf("DetectSingleByteXor(..) = %s, expected %s", plaintext, expectedPlaintext)
	}
}

func TestRepeatingKeyXor(t *testing.T) {
	// given
	plaintext := []byte("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal")
	key := []byte("ICE")

	expectedCiphertext := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	// when
	ciphertext, err := Xor(plaintext, key)
	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	// then
	if hex.EncodeToString(ciphertext) != expectedCiphertext {
		t.Errorf("RepeatingKeyXor(%s, %s) = %x, expected %s", string(plaintext), string(key),
			ciphertext, expectedCiphertext)
	}
}

func TestBreakRepeatingKeyXor(t *testing.T) {
	// given
	b64Ciphertext, err := tools.ReadFileContent("./6.txt")
	if err != nil {
		t.Errorf("Error reading ciphertext file: %s", err.Error())
	}

	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		t.Errorf("Error decoding b64 ciphertext: %s", err.Error())
	}

	// when
	plaintext, err := BreakRepeatingKeyXor(ciphertext)
	if err != nil {
		t.Errorf("Error trying to decrypt ciphertext: %s", err.Error())
	}

	// then
	if string(plaintext) != challenge6ExpectedPlaintext {
		t.Errorf("BreakRepeatingKeyXor(...) = %s\n, expected\n%s",
			string(plaintext), challenge6ExpectedPlaintext)
	}
}

func TestDecryptAESinECB(t *testing.T) {
	// given
	key := []byte("YELLOW SUBMARINE")
	b64Ciphertext, err := tools.ReadFileContent("./7.txt")
	if err != nil {
		t.Errorf("Error reading ciphertext file: %s", err.Error())
	}

	ciphertext, err := base64.StdEncoding.DecodeString(b64Ciphertext)
	if err != nil {
		t.Errorf("Error decoding b64 ciphertext: %s", err.Error())
	}

	// when
	paddedPlaintext, err := DecryptAESinECB(ciphertext, key)
	if err != nil {
		t.Errorf("Error decrypting ciphertext: %s", err.Error())
	}
	plaintext := tools.RemovePkcs7Padding(paddedPlaintext)

	// then
	if string(plaintext) != challenge7ExpectedPlaintext {
		t.Errorf("DecryptAESinECB(...) = %s\n, expected\n%s",
			string(plaintext), challenge7ExpectedPlaintext)
	}
}
