package helper

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	randMath "math/rand"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GenerateRandomID(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[randMath.Intn(len(charset))]
	}
	return string(b)
}

func Generate32ByteKey() []byte {
	key := make([]byte, chacha20poly1305.KeySize) // 32 bytes for ChaCha20-Poly1305
	_, err := rand.Read(key)
	if err != nil {
		return nil
	}
	return key
}

func GenerateOTP(length int) ([]string, error) {
	otp := ""
	otpArray := make([]string, length+1) // Create a slice with length+1 to store digits and the full OTP
	for i := 0; i < length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(10)) // Generate a random number between 0-9
		if err != nil {
			return nil, err
		}
		digit := strconv.Itoa(int(num.Int64()))
		otp += digit
		otpArray[i] = digit // Store each digit in the slice
	}
	otpArray[length] = otp // Store the full OTP as the last element
	return otpArray, nil
}

func GenerateLoginJTI() string {
	timeNow := time.Now().Format("020106150405") // Format: DDMMYYHHMMSS

	str := "JTI-USER-LOGIN-" + timeNow + "-" + GenerateRandomID(5)

	return str
}

// GenerateHMACSHA256 generates an HMAC-SHA256 hash of the input string
// Returns []byte which can be directly inserted into PostgreSQL bytea field (e.g., OtpRequest.OtpHash)
// Uses HMAC_SECRET_KEY from environment variable as the secret key
func GenerateHMACSHA256(data string) []byte {
	secretKey := os.Getenv("HMAC_SECRET_KEY")
	if secretKey == "" {
		secretKey = "default-secret-key-change-in-production"
	}

	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(data))
	return h.Sum(nil)
}

// GenerateHMACSHA256WithKey generates an HMAC-SHA256 hash with a custom secret key
// Returns []byte which can be directly inserted into PostgreSQL bytea field
func GenerateHMACSHA256WithKey(data string, secretKey string) []byte {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(data))
	return h.Sum(nil)
}

// VerifyHMACSHA256 verifies if the provided data matches the expected hash
// Returns true if the hash matches, false otherwise
func VerifyHMACSHA256(data string, expectedHash []byte) bool {
	computedHash := GenerateHMACSHA256(data)
	return hmac.Equal(computedHash, expectedHash)
}

// VerifyHMACSHA256WithKey verifies if the provided data matches the expected hash using a custom key
// Returns true if the hash matches, false otherwise
func VerifyHMACSHA256WithKey(data string, secretKey string, expectedHash []byte) bool {
	computedHash := GenerateHMACSHA256WithKey(data, secretKey)
	return hmac.Equal(computedHash, expectedHash)
}
