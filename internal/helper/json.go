package helper

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

// isProductionMode checks if ENCRYPTION_BEHAVIOR is set to "production"
func isProductionMode() bool {
	return os.Getenv("ENCRYPTION_BEHAVIOR") == "production"
}

func ReadJSONFromByte(data []byte, out any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	err := decoder.Decode(out)

	return err
}

// ReadJSON reads and decodes JSON from the request body.
// In production mode (ENCRYPTION_BEHAVIOR=production), it expects the body
// to be a JWE-encrypted token and will decrypt it first.
// In development mode, it reads plain JSON directly.
func ReadJSON(c *gin.Context, out any) error {
	if isProductionMode() {
		return readEncryptedJSON(c, out)
	}
	return readPlainJSON(c, out)
}

// readPlainJSON reads and decodes plain JSON from the request body
func readPlainJSON(c *gin.Context, out any) error {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}
	defer c.Request.Body.Close()

	return json.Unmarshal(body, out)
}

// readEncryptedJSON reads the JWE token from the request body and decrypts it
func readEncryptedJSON(c *gin.Context, out any) error {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return err
	}
	defer c.Request.Body.Close()

	// The body should contain the JWE token as a string
	jweToken := strings.TrimSpace(string(body))

	// Decrypt the JWE token into the target struct
	return JWEDecrypt(jweToken, out)
}

// WriteJSON writes JSON response to the client.
// In production mode (ENCRYPTION_BEHAVIOR=production), it encrypts the response
// as a JWE token before sending.
// In development mode, it writes plain JSON directly.
func WriteJSON(c *gin.Context, status int, data any) {
	if isProductionMode() {
		writeEncryptedJSON(c, status, data)
		return
	}
	writePlainJSON(c, status, data)
}

// writePlainJSON writes plain JSON response to the client
func writePlainJSON(c *gin.Context, status int, data any) {
	c.JSON(status, data)
}

// writeEncryptedJSON encrypts the data as JWE and writes it to the client
func writeEncryptedJSON(c *gin.Context, status int, data any) {
	jweToken, err := JWEEncrypt(data)
	if err != nil {
		// If encryption fails, return an error response
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to encrypt response",
		})
		return
	}

	// Set content type and write the JWE token
	c.Header("Content-Type", "application/jose")
	c.String(status, jweToken)
}
