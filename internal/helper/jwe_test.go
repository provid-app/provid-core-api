package helper

import (
	"os"
	"sync"
	"testing"
)

// resetJWEKeys resets the JWE key state for testing
func resetJWEKeys() {
	jweKeyOnce = sync.Once{}
	jwePrivateKey = nil
	jwePublicKey = nil
	jweKeyID = ""
	jweKeyError = nil
}

func TestJWEEncryptDecrypt(t *testing.T) {
	// Reset state before test
	resetJWEKeys()

	// Generate test keys
	keyPair, err := GenerateJWEKeyPair("test-key-1")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Set environment variables
	os.Setenv("JWE_PRIVATE_KEY", keyPair.PrivateKeyBase64)
	os.Setenv("JWE_PUBLIC_KEY", keyPair.PublicKeyBase64)
	os.Setenv("JWE_KEY_ID", keyPair.KeyID)

	// Test data
	type TestData struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Age   int    `json:"age"`
	}

	original := TestData{
		Name:  "John Doe",
		Email: "john@example.com",
		Age:   30,
	}

	// Encrypt
	encrypted, err := JWEEncrypt(original)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	t.Logf("Encrypted token length: %d", len(encrypted))

	// Verify it's a valid JWE compact serialization (5 parts separated by dots)
	parts := 0
	for _, c := range encrypted {
		if c == '.' {
			parts++
		}
	}
	if parts != 4 {
		t.Errorf("Expected 4 dots in JWE compact serialization, got %d", parts)
	}

	// Decrypt
	var decrypted TestData
	err = JWEDecrypt(encrypted, &decrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	// Verify
	if decrypted.Name != original.Name {
		t.Errorf("Name mismatch: expected %s, got %s", original.Name, decrypted.Name)
	}
	if decrypted.Email != original.Email {
		t.Errorf("Email mismatch: expected %s, got %s", original.Email, decrypted.Email)
	}
	if decrypted.Age != original.Age {
		t.Errorf("Age mismatch: expected %d, got %d", original.Age, decrypted.Age)
	}
}

func TestJWEKeyGeneration(t *testing.T) {
	keyPair, err := GenerateJWEKeyPair("my-key-id")
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if keyPair.PrivateKeyBase64 == "" {
		t.Error("Private key is empty")
	}
	if keyPair.PublicKeyBase64 == "" {
		t.Error("Public key is empty")
	}
	if keyPair.KeyID != "my-key-id" {
		t.Errorf("Key ID mismatch: expected my-key-id, got %s", keyPair.KeyID)
	}

	// Verify the keys can be decoded
	envOutput := keyPair.PrintEnvFormat()
	if envOutput == "" {
		t.Error("PrintEnvFormat returned empty string")
	}
	t.Logf("Generated env format:\n%s", envOutput)
}

func TestIsProductionMode(t *testing.T) {
	// Test development mode (default)
	os.Unsetenv("ENCRYPTION_BEHAVIOR")
	if isProductionMode() {
		t.Error("Expected development mode when ENCRYPTION_BEHAVIOR is not set")
	}

	// Test explicit development mode
	os.Setenv("ENCRYPTION_BEHAVIOR", "development")
	if isProductionMode() {
		t.Error("Expected development mode when ENCRYPTION_BEHAVIOR=development")
	}

	// Test production mode
	os.Setenv("ENCRYPTION_BEHAVIOR", "production")
	if !isProductionMode() {
		t.Error("Expected production mode when ENCRYPTION_BEHAVIOR=production")
	}
}
