package helper

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

// Indonesia timezone (Asia/Jakarta - GMT+7)
var IndonesiaTimezone = time.FixedZone("WIB", 7*60*60)

func GetCurrentTime() time.Time {
	return time.Now().In(IndonesiaTimezone)
}

func GetCurrentTimeWithFormat(format string) string {
	return time.Now().In(IndonesiaTimezone).Format(format)
}

func GenerateUID() string {
	return uuid.New().String()
}

func GenerateToken(length int) (string, error) {
	bytes := make([]byte, length/2) // Each byte is represented by 2 hex characters
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func IsNumeric(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

// ParseDate converts a string to time.Time using the specified format
func ParseDate(dateStr string, format string) (time.Time, error) {
	return time.Parse(format, dateStr)
}

// ParseDateDefault converts a string to time.Time using "2006-01-02" format
func ParseDateDefault(dateStr string) (time.Time, error) {
	return time.Parse("02-01-2006", dateStr)
}

// ParseDateTime converts a string to time.Time using "2006-01-02 15:04:05" format
func ParseDateTime(dateStr string) (time.Time, error) {
	return time.Parse("2006-01-02 15:04:05", dateStr)
}
