package helper

import (
	"fmt"
	"provid-backend/internal/model/data"
	"regexp"
	"strconv"
	"strings"

	ozzo "github.com/go-ozzo/ozzo-validation"
)

var Field = ozzo.Field

var errorMessages = map[string]string{
	"required":     "%s harus diisi!",
	"email":        "Format Email tidak valid!",
	"min_length":   "%s minimal %d karakter!",
	"max_length":   "%s maksimal %d karakter!",
	"exact_length": "%s harus %d karakter!",
	"numeric":      "%s harus berupa angka!",
	"unique":       "%s sudah digunkan!",
	"digit":        "%s harus berisi angka saja!",
}

func translateError(list map[string]string, field string, err error) data.ValidationErrorData {
	fieldName := getDisplayName(field, list)
	msg := err.Error()

	// Extract validation rule and parameters
	switch {
	case strings.Contains(msg, "cannot be blank"):
		msg = fmt.Sprintf(errorMessages["required"], fieldName)
	case strings.Contains(msg, "must be a valid email address"):
		msg = errorMessages["email"]
	case strings.Contains(msg, "the length must be no less than"):
		mins := extractFirstNumber(msg)
		msg = fmt.Sprintf(errorMessages["min_length"], fieldName, mins)
	case strings.Contains(msg, "the length must be no more than"):
		maxs := extractFirstNumber(msg)
		msg = fmt.Sprintf(errorMessages["max_length"], fieldName, maxs)
	case strings.Contains(msg, "the length must be exactly"):
		length := extractFirstNumber(msg)
		msg = fmt.Sprintf(errorMessages["exact_length"], fieldName, length)
	case strings.Contains(msg, "must contain digits only"):
		length := extractFirstNumber(msg)
		msg = fmt.Sprintf(errorMessages["digit"], fieldName, length)
	case strings.Contains(msg, "password and confirm"):
		msg = "Password dan Konfirmasi Password harus sama!"
	case strings.Contains(msg, "password must"):
		msg = "Password harus mengandung huruf besar, huruf kecil, angka, dan karakter khusus!"
	case strings.Contains(msg, "must be in a valid format"):
		if fieldName == "Nomor Telepon" {
			msg = "Nomor telepon harus dalam format yang valid!(08XXXXXXXXX/021XXXXXXXXX)"
		} else {
			msg = fmt.Sprintf("Format %s tidak valid", fieldName)
		}
	// Add more cases as needed
	default:
		msg = fmt.Sprintf("Terjadi kesalahan pada %s", fieldName)
	}

	return data.ValidationErrorData{
		Field:   field,
		Message: msg,
	}
}

func extractFirstNumber(msg string) int {
	//var num int
	//fmt.Sscanf(msg, "%*[^0-9]%d", &num)
	//return num
	re := regexp.MustCompile(`\d+`)
	match := re.FindString(msg)
	if match == "" {
		return 0
	}
	num, err := strconv.Atoi(match)
	if err != nil {
		return 0
	}
	return num
}

func getDisplayName(field string, list map[string]string) string {
	if name, exists := list[field]; exists {
		return name
	}
	return field
}

func ValidateStruct(list map[string]string, s interface{}, fields ...*ozzo.FieldRules) []data.ValidationErrorData {
	err := ozzo.ValidateStruct(s, fields...)
	if err == nil {
		return nil
	}

	var errors []data.ValidationErrorData
	if validationErrors, ok := err.(ozzo.Errors); ok {
		for field, err := range validationErrors {
			errors = append(errors, translateError(list, field, err))
		}
	}
	return errors
}
