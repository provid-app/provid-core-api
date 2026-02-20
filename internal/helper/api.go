package helper

import (
	"bytes"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"strings"

	"github.com/goccy/go-json"
)

func APIRequest(method, url string, payload interface{}, headers map[string]string) ([]byte, error) {
	var reqBody []byte
	var err error

	// Marshal the payload to JSON if it's not nil
	if payload != nil {
		reqBody, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}

	// Create a new HTTP request
	req, err := http.NewRequest(method, url, bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Make the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Check for non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("API request failed with status: " + resp.Status)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func APIRequestFormData(method, url string, formData map[string]string, headers map[string]string) ([]byte, error) {
	// Create a form-data body
	var body strings.Builder
	writer := multipart.NewWriter(&body)

	for key, value := range formData {
		err := writer.WriteField(key, value)
		if err != nil {
			return nil, err
		}
	}

	// Close the writer to finalize the form-data
	err := writer.Close()
	if err != nil {
		return nil, err
	}

	// Create a new HTTP request
	req, err := http.NewRequest(method, url, strings.NewReader(body.String()))
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())

	//req.Header.Set("Content-Type", "multipart/form-data;application/x-www-form-urlencoded;application/json")
	//req.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Make the HTTP request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	//defer resp.Body.Close()
	//bodyBytes, err := io.ReadAll(resp.Body)
	//if err != nil {
	//	return nil, err
	//}
	//
	//var responseMap map[string]interface{}
	//err = json.Unmarshal(bodyBytes, &responseMap)

	// Check for non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New("API request failed with status: " + resp.Status)
	}

	//Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return bodyBytes, nil
}
