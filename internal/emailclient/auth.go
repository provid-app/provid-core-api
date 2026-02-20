package emailclient

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// GenerateSignature creates HMAC authentication headers for the email service API
// Returns the timestamp and signature to be used in X-Request-Timestamp and X-Request-Signature headers
func GenerateSignature(secretKey, method, path, body string) (timestamp, signature string) {
	timestamp = fmt.Sprintf("%d", time.Now().Unix())
	signingString := fmt.Sprintf("%s.%s.%s.%s", timestamp, method, path, body)

	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(signingString))
	signature = hex.EncodeToString(h.Sum(nil))

	return timestamp, signature
}
