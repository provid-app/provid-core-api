package emailclient

// SendEmailRequest represents a request to send an email
type SendEmailRequest struct {
	TemplateName   string                 `json:"template_name"`
	Email          string                 `json:"email"`
	Data           map[string]interface{} `json:"data"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
}

// SendEmailWithAttachmentRequest represents a request to send an email with attachments
type SendEmailWithAttachmentRequest struct {
	TemplateName   string                 `json:"template_name"`
	Email          string                 `json:"email"`
	Data           map[string]interface{} `json:"data"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
	Attachments    []Attachment           `json:"attachments"`
}

// Attachment represents a MinIO object attachment
type Attachment struct {
	Bucket string `json:"bucket"`
	Object string `json:"object"`
}

// SendEmailResponse represents the response from sending an email
type SendEmailResponse struct {
	MessageID string `json:"message_id"`
	Status    string `json:"status"`
	Message   string `json:"message"`
}

// EmailStatusResponse represents the response from checking email status
type EmailStatusResponse struct {
	MessageID    string `json:"message_id"`
	Status       string `json:"status"`
	Recipient    string `json:"recipient"`
	Subject      string `json:"subject"`
	AttemptCount int    `json:"attempt_count"`
	CreatedAt    string `json:"created_at"`
	SentAt       string `json:"sent_at,omitempty"`
}

// ErrorResponse represents an error response from the email service
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
