package emailclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"
)

const (
	defaultTimeout  = 30 * time.Second
	maxRetries      = 3
	initialBackoff  = 500 * time.Millisecond
	sendEmailPath   = "/api/v1/email/send"
	sendWithAttPath = "/api/v1/email/send-with-attachment"
	emailStatusPath = "/api/v1/email/status"
)

// Config holds the configuration for the email service client
type Config struct {
	BaseURL   string        // Email service URL
	SecretKey string        // HMAC secret key
	Timeout   time.Duration // HTTP timeout (default 30s)
}

// Client is the email service HTTP client
type Client struct {
	config     Config
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient creates a new email service client with the given configuration
func NewClient(cfg Config) *Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultTimeout
	}

	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout:   cfg.Timeout,
			Transport: transport,
		},
		logger: slog.Default(),
	}
}

// NewClientFromEnv creates a new email service client from environment variables
// Required environment variables:
//   - EMAIL_SERVICE_URL: Base URL of the email service
//   - EMAIL_SERVICE_HMAC_KEY: HMAC secret key for authentication
//
// Optional environment variables:
//   - EMAIL_SERVICE_TIMEOUT: HTTP timeout in seconds (default: 30)
func NewClientFromEnv() (*Client, error) {
	baseURL := os.Getenv("EMAIL_SERVICE_URL")
	if baseURL == "" {
		return nil, errors.New("EMAIL_SERVICE_URL environment variable is required")
	}

	secretKey := os.Getenv("EMAIL_SERVICE_HMAC_KEY")
	if secretKey == "" {
		return nil, errors.New("EMAIL_SERVICE_HMAC_KEY environment variable is required")
	}

	timeout := defaultTimeout
	if timeoutStr := os.Getenv("EMAIL_SERVICE_TIMEOUT"); timeoutStr != "" {
		if seconds, err := strconv.Atoi(timeoutStr); err == nil && seconds > 0 {
			timeout = time.Duration(seconds) * time.Second
		}
	}

	return NewClient(Config{
		BaseURL:   baseURL,
		SecretKey: secretKey,
		Timeout:   timeout,
	}), nil
}

// SendEmail sends an email using the specified template
func (c *Client) SendEmail(ctx context.Context, req SendEmailRequest) (*SendEmailResponse, error) {
	// Validate email format
	if !isValidEmail(req.Email) {
		return nil, ErrInvalidEmail
	}

	// Generate idempotency key if not provided
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = uuid.New().String()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequestWithRetry(ctx, http.MethodPost, sendEmailPath, body)
	if err != nil {
		return nil, err
	}

	var result SendEmailResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

// SendEmailWithAttachment sends an email with attachments from MinIO
func (c *Client) SendEmailWithAttachment(ctx context.Context, req SendEmailWithAttachmentRequest) (*SendEmailResponse, error) {
	// Validate email format
	if !isValidEmail(req.Email) {
		return nil, ErrInvalidEmail
	}

	// Generate idempotency key if not provided
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = uuid.New().String()
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	resp, err := c.doRequestWithRetry(ctx, http.MethodPost, sendWithAttPath, body)
	if err != nil {
		return nil, err
	}

	var result SendEmailResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

// GetEmailStatus retrieves the status of a sent email
func (c *Client) GetEmailStatus(ctx context.Context, messageID string) (*EmailStatusResponse, error) {
	if messageID == "" {
		return nil, errors.New("message ID is required")
	}

	path := fmt.Sprintf("%s/%s", emailStatusPath, messageID)
	resp, err := c.doRequestWithRetry(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result EmailStatusResponse
	if err := json.Unmarshal(resp, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &result, nil
}

// doRequestWithRetry performs an HTTP request with retry logic for 5xx errors
func (c *Client) doRequestWithRetry(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff
			backoff := time.Duration(float64(initialBackoff) * math.Pow(2, float64(attempt-1)))
			c.logger.Debug("retrying request",
				slog.Int("attempt", attempt),
				slog.Duration("backoff", backoff),
				slog.String("path", path),
			)

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		resp, err := c.doRequest(ctx, method, path, body)
		if err != nil {
			// Check if it's a retryable error (5xx)
			var svcErr *EmailServiceError
			if errors.As(err, &svcErr) && svcErr.StatusCode >= 500 {
				lastErr = err
				continue
			}
			return nil, err
		}

		return resp, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// doRequest performs a single HTTP request with HMAC authentication
func (c *Client) doRequest(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	url := c.config.BaseURL + path

	var bodyReader io.Reader
	bodyStr := ""
	if body != nil {
		bodyReader = bytes.NewReader(body)
		bodyStr = string(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Generate HMAC signature
	timestamp, signature := GenerateSignature(c.config.SecretKey, method, path, bodyStr)

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Timestamp", timestamp)
	req.Header.Set("X-Request-Signature", signature)

	c.logger.Debug("sending request to email service",
		slog.String("method", method),
		slog.String("path", path),
		slog.String("timestamp", timestamp),
	)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrTimeout
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Handle non-2xx status codes
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, c.handleErrorResponse(resp.StatusCode, respBody)
	}

	return respBody, nil
}

// handleErrorResponse parses error responses and returns appropriate errors
func (c *Client) handleErrorResponse(statusCode int, body []byte) error {
	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		return &EmailServiceError{
			StatusCode: statusCode,
			ErrorCode:  "unknown",
			Message:    string(body),
		}
	}

	svcErr := &EmailServiceError{
		StatusCode: statusCode,
		ErrorCode:  errResp.Error,
		Message:    errResp.Message,
	}

	// Return sentinel errors for common cases
	switch statusCode {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", ErrUnauthorized, errResp.Message)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, errResp.Message)
	case http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrValidation, errResp.Message)
	case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
		return fmt.Errorf("%w: %s", ErrServiceUnavailable, errResp.Message)
	}

	return svcErr
}

// isValidEmail validates email format using a simple regex
func isValidEmail(email string) bool {
	// Simple email regex pattern
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(pattern, email)
	return matched
}

// Close closes the HTTP client (releases idle connections)
func (c *Client) Close() {
	if transport, ok := c.httpClient.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}
