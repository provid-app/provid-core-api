package helper

import (
	"io"
	"log"
	"os"
)

func ReadHTMLFileAsString(filepath string) (string, error) {
	// Open the file
	file, err := os.Open(filepath)
	if err != nil {
		log.Printf("Error opening file %s: %v", filepath, err)
		return "", err
	}
	defer file.Close()

	// Read the file content
	content, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	// Convert the content to a string and return
	return string(content), nil
}

func CheckIfFileExists(filepath string) bool {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return false
	}

	return true
}

func CreateDirectory(path string) error {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}
