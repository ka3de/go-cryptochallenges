package tools

func HammingDistanceString(text1, text2 string) (int, error) {
	return HammingDistance([]byte(text1), []byte(text2))
}

func HammingDistance(data1, data2 []byte) (int, error) {
	var lengthDifference int
	if len(data1) > len(data2) {
		lengthDifference = len(data1) - len(data2)
	} else {
		lengthDifference = len(data2) - len(data1)
	}

	hammingDistance := lengthDifference * 8
	for i, b := range data1 {
		xor := b ^ data2[i]
		for x := xor; x > 0; x >>= 1 {
			hammingDistance += int(x & 1)
		}
	}

	return hammingDistance, nil
}
