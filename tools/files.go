package tools

import (
	"bufio"
	"os"
)

func ReadFileLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var fileLines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fileLines = append(fileLines, scanner.Text())
	}

	return fileLines, scanner.Err()
}

func ReadFileContent(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileContent := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fileContent += scanner.Text()
	}

	return fileContent, nil
}
