package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/go-jose/go-jose/v4"
)

var (
	jwePrivateKey *ecdsa.PrivateKey
	jwePublicKey  *ecdsa.PublicKey
	jweKeyID      string
	jweKeyOnce    sync.Once
	jweKeyError   error
)

// InitJWEKeys initializes the JWE keys from environment variables.
// Expected env vars:
// - JWE_PRIVATE_KEY: Base64-encoded PKCS8 ECDSA P-256 private key
// - JWE_PUBLIC_KEY: Base64-encoded PKIX ECDSA P-256 public key
// - JWE_KEY_ID: Key ID for key rotation support
func InitJWEKeys() error {
	jweKeyOnce.Do(func() {
		jweKeyError = loadJWEKeys()
	})
	return jweKeyError
}

func loadJWEKeys() error {
	// Load Key ID
	jweKeyID = os.Getenv("JWE_KEY_ID")
	if jweKeyID == "" {
		jweKeyID = "default-key-1" // Default key ID if not provided
	}

	// Load private key
	privateKeyBase64 := os.Getenv("JWE_PRIVATE_KEY")
	if privateKeyBase64 == "" {
		return errors.New("JWE_PRIVATE_KEY not set in environment")
	}

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyBase64)
	if err != nil {
		return fmt.Errorf("failed to decode JWE_PRIVATE_KEY: %w", err)
	}

	privateKeyParsed, err := x509.ParsePKCS8PrivateKey(privateKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse JWE_PRIVATE_KEY: %w", err)
	}

	var ok bool
	jwePrivateKey, ok = privateKeyParsed.(*ecdsa.PrivateKey)
	if !ok {
		return errors.New("JWE_PRIVATE_KEY is not an ECDSA key")
	}

	if jwePrivateKey.Curve != elliptic.P256() {
		return errors.New("JWE_PRIVATE_KEY must use P-256 curve")
	}

	// Derive public key from private key
	jwePublicKey = &jwePrivateKey.PublicKey

	// Optionally load public key from environment (for verification)
	publicKeyBase64 := os.Getenv("JWE_PUBLIC_KEY")
	if publicKeyBase64 != "" {
		publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyBase64)
		if err != nil {
			return fmt.Errorf("failed to decode JWE_PUBLIC_KEY: %w", err)
		}

		publicKeyParsed, err := x509.ParsePKIXPublicKey(publicKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to parse JWE_PUBLIC_KEY: %w", err)
		}

		pubKey, ok := publicKeyParsed.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("JWE_PUBLIC_KEY is not an ECDSA key")
		}

		if pubKey.Curve != elliptic.P256() {
			return errors.New("JWE_PUBLIC_KEY must use P-256 curve")
		}

		jwePublicKey = pubKey
	}

	return nil
}

// GetJWEPublicKey returns the JWE public key for client distribution
func GetJWEPublicKey() (*ecdsa.PublicKey, string, error) {
	if err := InitJWEKeys(); err != nil {
		return nil, "", err
	}
	return jwePublicKey, jweKeyID, nil
}

// JWEEncrypt encrypts data using JWE with ECDH-ES and A256GCM
// Returns a compact serialized JWE token
func JWEEncrypt(data any) (string, error) {
	if err := InitJWEKeys(); err != nil {
		return "", err
	}

	// Serialize data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("failed to marshal data: %w", err)
	}

	// Create recipient with ECDH-ES key agreement and the public key
	recipient := jose.Recipient{
		Algorithm: jose.ECDH_ES,
		Key:       jwePublicKey,
		KeyID:     jweKeyID,
	}

	// Create encrypter with A256GCM content encryption
	encrypterOptions := (&jose.EncrypterOptions{}).WithType("JWE").WithContentType("application/json")
	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, encrypterOptions)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %w", err)
	}

	// Encrypt the JSON data
	jweObject, err := encrypter.Encrypt(jsonData)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Return compact serialized JWE
	return jweObject.CompactSerialize()
}

// JWEDecrypt decrypts a JWE token and unmarshals into the target struct
func JWEDecrypt(jweToken string, target any) error {
	if err := InitJWEKeys(); err != nil {
		return err
	}

	// Parse the JWE token
	jweObject, err := jose.ParseEncrypted(jweToken, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return fmt.Errorf("failed to parse JWE token: %w", err)
	}

	// Decrypt using the private key
	plaintext, err := jweObject.Decrypt(jwePrivateKey)
	if err != nil {
		return fmt.Errorf("failed to decrypt JWE token: %w", err)
	}

	// Unmarshal JSON into target
	if err := json.Unmarshal(plaintext, target); err != nil {
		return fmt.Errorf("failed to unmarshal decrypted data: %w", err)
	}

	return nil
}

// JWEDecryptRaw decrypts a JWE token and returns the raw JSON bytes
func JWEDecryptRaw(jweToken string) ([]byte, error) {
	if err := InitJWEKeys(); err != nil {
		return nil, err
	}

	// Parse the JWE token
	jweObject, err := jose.ParseEncrypted(jweToken, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWE token: %w", err)
	}

	// Decrypt using the private key
	plaintext, err := jweObject.Decrypt(jwePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt JWE token: %w", err)
	}

	return plaintext, nil
}
