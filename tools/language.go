package tools

func GetLangScoring(text string) int {
	score := 0
	for _, char := range text {
		if isEnglishCharacter(char) {
			score++
		}
	}

	return score
}

func isEnglishCharacter(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
		r == ' ' || r == '-' || r == '\'' || r == '\n' || r == '/' || r == ',' || r == '.' || r == '?'
}
