package emailclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGenerateSignature(t *testing.T) {
	secretKey := "test-secret-key"
	method := "POST"
	path := "/api/v1/email/send"
	body := `{"template_name":"test","email":"test@example.com","data":{}}`

	timestamp, signature := GenerateSignature(secretKey, method, path, body)

	// Verify timestamp is a valid Unix timestamp
	if timestamp == "" {
		t.Error("Timestamp should not be empty")
	}

	// Verify signature is a valid hex string (64 characters for SHA256)
	if len(signature) != 64 {
		t.Errorf("Signature should be 64 characters, got %d", len(signature))
	}

	// Verify signature is consistent
	timestamp2, signature2 := GenerateSignature(secretKey, method, path, body)
	if timestamp == timestamp2 && signature != signature2 {
		t.Error("Same inputs should produce same signature when timestamp is the same")
	}
}

func TestNewClient(t *testing.T) {
	cfg := Config{
		BaseURL:   "http://localhost:8080",
		SecretKey: "test-secret",
		Timeout:   10 * time.Second,
	}

	client := NewClient(cfg)

	if client == nil {
		t.Fatal("NewClient should not return nil")
	}

	if client.config.BaseURL != cfg.BaseURL {
		t.Errorf("Expected BaseURL %s, got %s", cfg.BaseURL, client.config.BaseURL)
	}

	if client.config.SecretKey != cfg.SecretKey {
		t.Errorf("Expected SecretKey %s, got %s", cfg.SecretKey, client.config.SecretKey)
	}

	if client.config.Timeout != cfg.Timeout {
		t.Errorf("Expected Timeout %v, got %v", cfg.Timeout, client.config.Timeout)
	}
}

func TestNewClientDefaultTimeout(t *testing.T) {
	cfg := Config{
		BaseURL:   "http://localhost:8080",
		SecretKey: "test-secret",
	}

	client := NewClient(cfg)

	if client.config.Timeout != defaultTimeout {
		t.Errorf("Expected default timeout %v, got %v", defaultTimeout, client.config.Timeout)
	}
}

func TestSendEmail(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST method, got %s", r.Method)
		}

		// Verify path
		if r.URL.Path != "/api/v1/email/send" {
			t.Errorf("Expected path /api/v1/email/send, got %s", r.URL.Path)
		}

		// Verify headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("Content-Type header should be application/json")
		}

		if r.Header.Get("X-Request-Timestamp") == "" {
			t.Error("X-Request-Timestamp header should not be empty")
		}

		if r.Header.Get("X-Request-Signature") == "" {
			t.Error("X-Request-Signature header should not be empty")
		}

		// Send response
		resp := SendEmailResponse{
			MessageID: "test-message-id",
			Status:    "queued",
			Message:   "Email queued successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		SecretKey: "test-secret",
	})

	resp, err := client.SendEmail(context.Background(), SendEmailRequest{
		TemplateName: "test_template",
		Email:        "test@example.com",
		Data: map[string]interface{}{
			"name": "Test User",
		},
	})

	if err != nil {
		t.Fatalf("SendEmail should not return error: %v", err)
	}

	if resp.MessageID != "test-message-id" {
		t.Errorf("Expected message ID 'test-message-id', got '%s'", resp.MessageID)
	}

	if resp.Status != "queued" {
		t.Errorf("Expected status 'queued', got '%s'", resp.Status)
	}
}

func TestSendEmailInvalidEmail(t *testing.T) {
	client := NewClient(Config{
		BaseURL:   "http://localhost:8080",
		SecretKey: "test-secret",
	})

	_, err := client.SendEmail(context.Background(), SendEmailRequest{
		TemplateName: "test_template",
		Email:        "invalid-email",
		Data:         map[string]interface{}{},
	})

	if err != ErrInvalidEmail {
		t.Errorf("Expected ErrInvalidEmail, got %v", err)
	}
}

func TestSendEmailUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		resp := ErrorResponse{
			Error:   "unauthorized",
			Message: "invalid signature",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		SecretKey: "wrong-secret",
	})

	_, err := client.SendEmail(context.Background(), SendEmailRequest{
		TemplateName: "test_template",
		Email:        "test@example.com",
		Data:         map[string]interface{}{},
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("Expected unauthorized error, got %v", err)
	}
}

func TestSendEmailValidationError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		resp := ErrorResponse{
			Error:   "validation_error",
			Message: "template not found",
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		SecretKey: "test-secret",
	})

	_, err := client.SendEmail(context.Background(), SendEmailRequest{
		TemplateName: "unknown_template",
		Email:        "test@example.com",
		Data:         map[string]interface{}{},
	})

	if err == nil {
		t.Fatal("Expected error, got nil")
	}

	if !strings.Contains(err.Error(), "validation") {
		t.Errorf("Expected validation error, got %v", err)
	}
}

func TestSendEmailWithAttachment(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/email/send-with-attachment" {
			t.Errorf("Expected path /api/v1/email/send-with-attachment, got %s", r.URL.Path)
		}

		resp := SendEmailResponse{
			MessageID: "test-message-id",
			Status:    "queued",
			Message:   "Email queued successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		SecretKey: "test-secret",
	})

	resp, err := client.SendEmailWithAttachment(context.Background(), SendEmailWithAttachmentRequest{
		TemplateName: "invoice",
		Email:        "test@example.com",
		Data:         map[string]interface{}{"invoice_number": "INV-001"},
		Attachments: []Attachment{
			{Bucket: "documents", Object: "invoices/INV-001.pdf"},
		},
	})

	if err != nil {
		t.Fatalf("SendEmailWithAttachment should not return error: %v", err)
	}

	if resp.MessageID != "test-message-id" {
		t.Errorf("Expected message ID 'test-message-id', got '%s'", resp.MessageID)
	}
}

func TestGetEmailStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("Expected GET method, got %s", r.Method)
		}

		if r.URL.Path != "/api/v1/email/status/test-message-id" {
			t.Errorf("Expected path /api/v1/email/status/test-message-id, got %s", r.URL.Path)
		}

		resp := EmailStatusResponse{
			MessageID:    "test-message-id",
			Status:       "sent",
			Recipient:    "test@example.com",
			Subject:      "Test Subject",
			AttemptCount: 1,
			CreatedAt:    "2024-01-22T10:30:00Z",
			SentAt:       "2024-01-22T10:30:05Z",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		SecretKey: "test-secret",
	})

	resp, err := client.GetEmailStatus(context.Background(), "test-message-id")

	if err != nil {
		t.Fatalf("GetEmailStatus should not return error: %v", err)
	}

	if resp.MessageID != "test-message-id" {
		t.Errorf("Expected message ID 'test-message-id', got '%s'", resp.MessageID)
	}

	if resp.Status != "sent" {
		t.Errorf("Expected status 'sent', got '%s'", resp.Status)
	}
}

func TestGetEmailStatusEmptyID(t *testing.T) {
	client := NewClient(Config{
		BaseURL:   "http://localhost:8080",
		SecretKey: "test-secret",
	})

	_, err := client.GetEmailStatus(context.Background(), "")

	if err == nil {
		t.Fatal("Expected error for empty message ID")
	}
}

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"test@example.com", true},
		{"user.name@domain.co.uk", true},
		{"user+tag@example.com", true},
		{"invalid-email", false},
		{"@example.com", false},
		{"user@", false},
		{"", false},
	}

	for _, tt := range tests {
		result := isValidEmail(tt.email)
		if result != tt.expected {
			t.Errorf("isValidEmail(%q) = %v, expected %v", tt.email, result, tt.expected)
		}
	}
}

func TestEmailServiceError(t *testing.T) {
	err := &EmailServiceError{
		StatusCode: 400,
		ErrorCode:  "validation_error",
		Message:    "template not found",
	}

	expected := "email service error [400]: validation_error - template not found"
	if err.Error() != expected {
		t.Errorf("Expected error message '%s', got '%s'", expected, err.Error())
	}
}

func TestRetryOn5xxError(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			resp := ErrorResponse{
				Error:   "internal_error",
				Message: "server error",
			}
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Success on 3rd attempt
		resp := SendEmailResponse{
			MessageID: "test-message-id",
			Status:    "queued",
			Message:   "Email queued successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(Config{
		BaseURL:   server.URL,
		SecretKey: "test-secret",
	})

	resp, err := client.SendEmail(context.Background(), SendEmailRequest{
		TemplateName: "test_template",
		Email:        "test@example.com",
		Data:         map[string]interface{}{},
	})

	if err != nil {
		t.Fatalf("Expected success after retry, got error: %v", err)
	}

	if resp.MessageID != "test-message-id" {
		t.Errorf("Expected message ID 'test-message-id', got '%s'", resp.MessageID)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}
