package helper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters - following OWASP recommendations
const (
	argon2Time    = 1         // Number of iterations
	argon2Memory  = 64 * 1024 // 64 MB memory
	argon2Threads = 4         // Number of threads
	argon2KeyLen  = 32        // Length of the generated key
	argon2SaltLen = 16        // Length of the salt
)

func GenerateHashPaseto(token string) (string, error) {
	shaHash := sha256.Sum256([]byte(token))
	shaHashHex := hex.EncodeToString(shaHash[:])

	hashed, err := bcrypt.GenerateFromPassword([]byte(shaHashHex), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.New("failed to generate hash")
	}

	return base64.StdEncoding.EncodeToString(hashed), nil
}

func CheckHashPaseto(base64HashedToken string, token string) error {
	shaHash := sha256.Sum256([]byte(token))
	shaHashHex := hex.EncodeToString(shaHash[:])

	hashedToken, err := base64.StdEncoding.DecodeString(base64HashedToken)
	if err != nil {
		return errors.New("invalid base64 hashed token")
	}

	//return bcrypt.CompareHashAndPassword(hashedToken, []byte(shaHashHex))
	return bcrypt.CompareHashAndPassword(hashedToken, []byte(shaHashHex))
}

func GenerateHash(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", errors.New("email or password is incorrect")
	}

	//return string(hashedPassword), nil
	return base64.StdEncoding.EncodeToString(hashedPassword), nil
}

func CheckHash(base64HashedPassword string, password string) error {
	hashedPassword, err := base64.StdEncoding.DecodeString(base64HashedPassword)
	if err != nil {
		return errors.New("invalid base64 hashed password")
	}

	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// GenerateHashArgon2id hashes a password using Argon2id algorithm
// Returns base64 encoded string in format: salt$hash
func GenerateHashArgon2id(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Generate hash using Argon2id
	hash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Encode salt and hash to base64
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Return combined format: salt$hash
	return fmt.Sprintf("%s$%s", b64Salt, b64Hash), nil
}

// CheckHashArgon2id verifies a password against an Argon2id hash
// The encodedHash should be in format: salt$hash (base64 encoded)
func CheckHashArgon2id(encodedHash string, password string) error {
	// Split the encoded hash to get salt and hash
	var b64Salt, b64Hash string
	for i := 0; i < len(encodedHash); i++ {
		if encodedHash[i] == '$' {
			b64Salt = encodedHash[:i]
			b64Hash = encodedHash[i+1:]
			break
		}
	}

	if b64Salt == "" || b64Hash == "" {
		return errors.New("invalid hash format")
	}

	// Decode salt
	salt, err := base64.RawStdEncoding.DecodeString(b64Salt)
	if err != nil {
		return errors.New("invalid salt encoding")
	}

	// Decode expected hash
	expectedHash, err := base64.RawStdEncoding.DecodeString(b64Hash)
	if err != nil {
		return errors.New("invalid hash encoding")
	}

	// Compute hash of the provided password
	computedHash := argon2.IDKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Compare hashes using constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(expectedHash, computedHash) != 1 {
		return errors.New("password does not match")
	}

	return nil
}

// EncryptPayload encrypts any JSON-serializable struct using AES-GCM
func EncryptPayload(data interface{}) (string, error) {
	// Get base64-encoded key from environment
	base64Key := os.Getenv("AES_KEY")
	if base64Key == "" {
		return "", errors.New("ENCRYPTION_KEY not set in environment")
	}

	// Decode base64 key
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes")
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("json marshal failed: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher creation failed: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM creation failed: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}

	// Encrypt and seal
	ciphertext := gcm.Seal(nonce, nonce, jsonData, nil)
	return hex.EncodeToString(ciphertext), nil
}

// DecryptPayload decrypts into the target struct
func DecryptPayload(encrypted string, target interface{}) error {
	// Get base64-encoded key from environment
	base64Key := os.Getenv("AES_KEY")
	if base64Key == "" {
		return errors.New("ENCRYPTION_KEY not set in environment")
	}

	// Decode base64 key
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return fmt.Errorf("invalid base64 key: %w", err)
	}
	if len(key) != 32 {
		return errors.New("encryption key must be 32 bytes")
	}

	// Decode from hex
	ciphertext, err := hex.DecodeString(encrypted)
	if err != nil {
		return fmt.Errorf("hex decode failed: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher creation failed: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("GCM creation failed: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Unmarshal JSON
	if err := json.Unmarshal(plaintext, target); err != nil {
		return fmt.Errorf("json unmarshal failed: %w", err)
	}

	return nil
}
