package helper

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"io"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jordan-wright/email"
)

// MailConfig holds the SMTP configuration
type MailConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	From        string
	FromName    string
	UseTLS      bool          // Use STARTTLS for port 25/587 (upgrades plain connection to TLS)
	UseSSL      bool          // Use implicit SSL/TLS for port 465 (connection is encrypted from start)
	PoolSize    int           // Number of connections in the pool (default: 4)
	KeepAlive   time.Duration // Interval to refresh pool to keep connections warm (default: 2m)
	ConnMaxLife time.Duration // Max lifetime of a connection before refresh (default: 10m)
	SendTimeout time.Duration // Timeout for sending email (default: 30s)
}

// Attachment represents an email attachment
type Attachment struct {
	Filename string
	Content  []byte
	MimeType string
}

// MailMessage represents an email message
type MailMessage struct {
	To           []string
	Cc           []string
	Bcc          []string
	Subject      string
	Body         string
	IsHTML       bool
	Attachments  []Attachment
	TemplatePath string                 // Path to .tmpl file (optional)
	TemplateData map[string]interface{} // Data to pass to template (optional)
}

// Ensure Mailer implements EmailSender interface
var _ EmailSender = (*Mailer)(nil)

// Mailer handles email sending operations with connection pooling
type Mailer struct {
	config      MailConfig
	pool        *email.Pool
	poolMu      sync.RWMutex
	stopChan    chan struct{}
	lastUsed    time.Time
	lastUsedMu  sync.RWMutex
	initialized bool
	wg          sync.WaitGroup // Track background goroutines
}

// NewMailer creates a new Mailer instance with connection pooling
func NewMailer(config MailConfig) *Mailer {
	// Set defaults
	if config.PoolSize <= 0 {
		config.PoolSize = 4
	}
	if config.KeepAlive <= 0 {
		config.KeepAlive = 2 * time.Minute // Refresh pool every 2 minutes to keep connections warm
	}
	if config.ConnMaxLife <= 0 {
		config.ConnMaxLife = 10 * time.Minute // Max connection lifetime before forced refresh
	}
	if config.SendTimeout <= 0 {
		config.SendTimeout = 30 * time.Second
	}

	m := &Mailer{
		config:   config,
		stopChan: make(chan struct{}),
	}

	// Initialize the connection pool
	if err := m.initPool(); err != nil {
		// Log the error but don't fail - will retry on first send
		fmt.Printf("Warning: Failed to initialize SMTP pool: %v\n", err)
	}

	// Start keepalive goroutine that periodically refreshes the pool
	m.wg.Add(1)
	go m.keepAliveLoop()

	return m
}

// NewMailerFromEnv creates a new Mailer instance from environment variables
// Expected env vars: SMTP_HOST, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, SMTP_FROM, SMTP_FROM_NAME, SMTP_USE_TLS
func NewMailerFromEnv() *Mailer {
	port := 587
	if portStr := os.Getenv("SMTP_PORT"); portStr != "" {
		_, _ = fmt.Sscanf(portStr, "%d", &port)
	}

	useTLS := true
	if tlsStr := os.Getenv("SMTP_USE_TLS"); tlsStr == "false" {
		useTLS = false
	}

	poolSize := 4
	if poolSizeStr := os.Getenv("SMTP_POOL_SIZE"); poolSizeStr != "" {
		_, _ = fmt.Sscanf(poolSizeStr, "%d", &poolSize)
	}

	return NewMailer(MailConfig{
		Host:        os.Getenv("SMTP_HOST"),
		Port:        port,
		Username:    os.Getenv("SMTP_USERNAME"),
		Password:    os.Getenv("SMTP_PASSWORD"),
		From:        os.Getenv("SMTP_FROM"),
		FromName:    os.Getenv("SMTP_FROM_NAME"),
		UseTLS:      useTLS,
		PoolSize:    poolSize,
		KeepAlive:   2 * time.Minute,  // Refresh pool every 2 minutes
		ConnMaxLife: 10 * time.Minute, // Max connection lifetime
		SendTimeout: 30 * time.Second, // Timeout for sending
	})
}

// initPool initializes the SMTP connection pool
func (m *Mailer) initPool() error {
	m.poolMu.Lock()
	defer m.poolMu.Unlock()

	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)

	var pool *email.Pool
	var err error

	if m.config.UseTLS {
		tlsConfig := &tls.Config{
			ServerName: m.config.Host,
		}

		if m.config.Port == 465 {
			// Implicit TLS (SSL)
			pool, err = email.NewPool(addr, m.config.PoolSize, smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host), tlsConfig)
		} else {
			// STARTTLS
			pool, err = email.NewPool(addr, m.config.PoolSize, smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host), tlsConfig)
		}
	} else {
		pool, err = email.NewPool(addr, m.config.PoolSize, smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host))
	}

	if err != nil {
		return fmt.Errorf("failed to create email pool: %w", err)
	}

	m.pool = pool
	m.initialized = true
	m.updateLastUsed()

	return nil
}

// updateLastUsed updates the last used timestamp
func (m *Mailer) updateLastUsed() {
	m.lastUsedMu.Lock()
	defer m.lastUsedMu.Unlock()
	m.lastUsed = time.Now()
}

// getLastUsed returns the last used timestamp
func (m *Mailer) getLastUsed() time.Time {
	m.lastUsedMu.RLock()
	defer m.lastUsedMu.RUnlock()
	return m.lastUsed
}

// keepAliveLoop periodically refreshes the pool to keep connections warm
// Since jordan-wright/email pool doesn't support NOOP commands, we proactively
// refresh the pool before connections go stale
func (m *Mailer) keepAliveLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.config.KeepAlive)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.poolMu.RLock()
			initialized := m.initialized
			m.poolMu.RUnlock()

			if !initialized {
				// Try to initialize if not yet done
				if err := m.initPool(); err != nil {
					fmt.Printf("Warning: Failed to initialize SMTP pool in keepalive: %v\n", err)
				}
				continue
			}

			// Proactively refresh the pool to keep connections warm
			// This prevents the "first email after idle" slowness
			if err := m.refreshPool(); err != nil {
				fmt.Printf("Warning: Failed to refresh SMTP pool: %v\n", err)
			}
		}
	}
}

// refreshPool closes the existing pool and creates a new one
func (m *Mailer) refreshPool() error {
	m.poolMu.Lock()
	if m.pool != nil {
		m.pool.Close()
		m.pool = nil
		m.initialized = false
	}
	m.poolMu.Unlock()

	return m.initPool()
}

// ensurePool ensures the pool is initialized
func (m *Mailer) ensurePool() error {
	m.poolMu.RLock()
	if m.initialized && m.pool != nil {
		m.poolMu.RUnlock()
		return nil
	}
	m.poolMu.RUnlock()

	return m.initPool()
}

// Close closes the mailer and its connection pool
func (m *Mailer) Close() {
	// Signal the keepalive goroutine to stop
	select {
	case <-m.stopChan:
		// Already closed
	default:
		close(m.stopChan)
	}

	// Wait for background goroutines to finish
	m.wg.Wait()

	m.poolMu.Lock()
	defer m.poolMu.Unlock()

	if m.pool != nil {
		m.pool.Close()
		m.pool = nil
		m.initialized = false
	}
}

// Send sends an email message using the connection pool
func (m *Mailer) Send(msg MailMessage) error {
	// Ensure pool is initialized
	if err := m.ensurePool(); err != nil {
		return fmt.Errorf("failed to ensure SMTP pool: %w", err)
	}

	// If template path is provided, parse and execute the template
	if msg.TemplatePath != "" {
		body, err := m.parseTemplate(msg.TemplatePath, msg.TemplateData)
		if err != nil {
			return fmt.Errorf("failed to parse template: %w", err)
		}
		msg.Body = body
		msg.IsHTML = true // Templates are assumed to be HTML
	}

	// Build the email using jordan-wright/email
	e := m.buildEmail(msg)

	// Send using the pool with timeout
	m.poolMu.RLock()
	pool := m.pool
	m.poolMu.RUnlock()

	if pool == nil {
		return fmt.Errorf("SMTP pool is not initialized")
	}

	err := pool.Send(e, m.config.SendTimeout)
	if err != nil {
		// If send fails, try to refresh the pool and retry once
		if refreshErr := m.refreshPool(); refreshErr != nil {
			return fmt.Errorf("failed to send email and refresh pool: %w (refresh error: %v)", err, refreshErr)
		}

		m.poolMu.RLock()
		pool = m.pool
		m.poolMu.RUnlock()

		if pool == nil {
			return fmt.Errorf("SMTP pool is not initialized after refresh")
		}

		err = pool.Send(e, m.config.SendTimeout)
		if err != nil {
			return fmt.Errorf("failed to send email after retry: %w", err)
		}
	}

	m.updateLastUsed()
	return nil
}

// buildEmail builds an email.Email from MailMessage
func (m *Mailer) buildEmail(msg MailMessage) *email.Email {
	e := email.NewEmail()

	// Set sender
	if m.config.FromName != "" {
		e.From = fmt.Sprintf("%s <%s>", m.config.FromName, m.config.From)
	} else {
		e.From = m.config.From
	}

	// Set recipients
	e.To = msg.To
	e.Cc = msg.Cc
	e.Bcc = msg.Bcc
	e.Subject = msg.Subject

	// Set body
	if msg.IsHTML {
		e.HTML = []byte(msg.Body)
	} else {
		e.Text = []byte(msg.Body)
	}

	// Add attachments
	for _, att := range msg.Attachments {
		mimeType := att.MimeType
		if mimeType == "" {
			mimeType = getMimeType(att.Filename)
		}

		_, _ = e.Attach(
			bytes.NewReader(att.Content),
			att.Filename,
			mimeType,
		)
	}

	return e
}

// parseTemplate parses a .tmpl file and executes it with the provided data
func (m *Mailer) parseTemplate(templatePath string, data map[string]interface{}) (string, error) {
	// Parse the template file
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to parse template file: %w", err)
	}

	// Execute the template with the provided data
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// SendWithTemplate sends an email using a template file
// templatePath: path to the .tmpl file
// data: map of data to pass to the template
func (m *Mailer) SendWithTemplate(to []string, subject string, templatePath string, data map[string]interface{}) error {
	return m.Send(MailMessage{
		To:           to,
		Subject:      subject,
		TemplatePath: templatePath,
		TemplateData: data,
		IsHTML:       true,
	})
}

// SendWithTemplateAndAttachments sends an email using a template file with attachments
func (m *Mailer) SendWithTemplateAndAttachments(to []string, subject string, templatePath string, data map[string]interface{}, attachments []Attachment) error {
	return m.Send(MailMessage{
		To:           to,
		Subject:      subject,
		TemplatePath: templatePath,
		TemplateData: data,
		IsHTML:       true,
		Attachments:  attachments,
	})
}

// SendWithTemplateFile sends an email using a template file with full options
func (m *Mailer) SendWithTemplateFile(msg MailMessage, templatePath string, data map[string]interface{}) error {
	msg.TemplatePath = templatePath
	msg.TemplateData = data
	return m.Send(msg)
}

// AttachmentFromFile creates an Attachment from a file path
func AttachmentFromFile(filePath string) (Attachment, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return Attachment{}, fmt.Errorf("failed to read file: %w", err)
	}

	filename := filepath.Base(filePath)
	mimeType := getMimeType(filename)

	return Attachment{
		Filename: filename,
		Content:  content,
		MimeType: mimeType,
	}, nil
}

// AttachmentFromReader creates an Attachment from an io.Reader
func AttachmentFromReader(reader io.Reader, filename string, mimeType string) (Attachment, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return Attachment{}, fmt.Errorf("failed to read content: %w", err)
	}

	if mimeType == "" {
		mimeType = getMimeType(filename)
	}

	return Attachment{
		Filename: filename,
		Content:  content,
		MimeType: mimeType,
	}, nil
}

// getMimeType returns the MIME type based on file extension
func getMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))

	mimeTypes := map[string]string{
		".pdf":  "application/pdf",
		".doc":  "application/msword",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xls":  "application/vnd.ms-excel",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".ppt":  "application/vnd.ms-powerpoint",
		".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".txt":  "text/plain",
		".csv":  "text/csv",
		".html": "text/html",
		".htm":  "text/html",
		".json": "application/json",
		".xml":  "application/xml",
		".zip":  "application/zip",
		".rar":  "application/x-rar-compressed",
		".7z":   "application/x-7z-compressed",
		".tar":  "application/x-tar",
		".gz":   "application/gzip",
		".png":  "image/png",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".gif":  "image/gif",
		".bmp":  "image/bmp",
		".webp": "image/webp",
		".svg":  "image/svg+xml",
		".ico":  "image/x-icon",
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".mp4":  "video/mp4",
		".avi":  "video/x-msvideo",
		".mov":  "video/quicktime",
	}

	if mimeType, ok := mimeTypes[ext]; ok {
		return mimeType
	}

	return "application/octet-stream"
}

// SendSimple is a convenience function to send a simple email without attachments
func (m *Mailer) SendSimple(to []string, subject, body string, isHTML bool) error {
	return m.Send(MailMessage{
		To:      to,
		Subject: subject,
		Body:    body,
		IsHTML:  isHTML,
	})
}

// SendWithAttachment is a convenience function to send an email with a single attachment
func (m *Mailer) SendWithAttachment(to []string, subject, body string, isHTML bool, attachmentPath string) error {
	attachment, err := AttachmentFromFile(attachmentPath)
	if err != nil {
		return err
	}

	return m.Send(MailMessage{
		To:          to,
		Subject:     subject,
		Body:        body,
		IsHTML:      isHTML,
		Attachments: []Attachment{attachment},
	})
}

// SendOTPEmail sends an OTP email (convenience method for your auth service)
func (m *Mailer) SendOTPEmail(to string, otp string, purpose string) error {
	subject := "Kode OTP Anda"

	purposeText := "verifikasi"
	switch purpose {
	case "verify_email":
		purposeText = "verifikasi email"
	case "password_reset":
		purposeText = "reset password"
	case "change_email":
		purposeText = "perubahan email"
	}

	body := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .otp-code { font-size: 32px; font-weight: bold; color: #2563eb; letter-spacing: 8px; text-align: center; padding: 20px; background: #f3f4f6; border-radius: 8px; margin: 20px 0; }
        .footer { font-size: 12px; color: #666; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Kode OTP untuk %s</h2>
        <p>Gunakan kode berikut untuk melanjutkan proses %s:</p>
        <div class="otp-code">%s</div>
        <p>Kode ini berlaku selama 15 menit. Jangan bagikan kode ini kepada siapapun.</p>
        <p>Jika Anda tidak meminta kode ini, abaikan email ini.</p>
        <div class="footer">
            <p>Email ini dikirim secara otomatis, mohon tidak membalas email ini.</p>
        </div>
    </div>
</body>
</html>
`, purposeText, purposeText, otp)

	return m.SendSimple([]string{to}, subject, body, true)
}
