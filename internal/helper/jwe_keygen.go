package helper

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// JWEKeyPair holds a generated ECDSA key pair for JWE
type JWEKeyPair struct {
	PrivateKeyBase64 string // Base64-encoded PKCS8 private key
	PublicKeyBase64  string // Base64-encoded PKIX public key
	KeyID            string // Suggested key ID
}

// GenerateJWEKeyPair generates a new ECDSA P-256 key pair for JWE encryption.
// Returns base64-encoded keys ready to be stored in environment variables.
// Use this function to generate new keys for deployment.
func GenerateJWEKeyPair(keyID string) (*JWEKeyPair, error) {
	// Generate new ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Encode private key to PKCS8
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Encode public key to PKIX
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	return &JWEKeyPair{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKeyBytes),
		PublicKeyBase64:  base64.StdEncoding.EncodeToString(publicKeyBytes),
		KeyID:            keyID,
	}, nil
}

// PrintJWEKeyPair prints the key pair in a format suitable for .env files
func (kp *JWEKeyPair) PrintEnvFormat() string {
	return fmt.Sprintf(`# JWE Keys for ECDH-ES + A256GCM encryption
# Key ID: %s
JWE_KEY_ID=%s
JWE_PRIVATE_KEY=%s
JWE_PUBLIC_KEY=%s
`, kp.KeyID, kp.KeyID, kp.PrivateKeyBase64, kp.PublicKeyBase64)
}
