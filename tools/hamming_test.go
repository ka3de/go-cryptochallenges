package tools

import "testing"

func TestHammingDistance(t *testing.T) {
	// given
	text1 := "this is a test"
	text2 := "wokka wokka!!!"

	expectedHammingDistance := 37

	// when
	hammingDistance, err := HammingDistanceString(text1, text2)
	if err != nil {
		t.Errorf("Error: %s", err.Error())
	}

	// then
	if hammingDistance != expectedHammingDistance {
		t.Errorf("HammingDistance(%s, %s) = %d, expected %d", text1, text2,
			hammingDistance, expectedHammingDistance)
	}
}
