package helper

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"net"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"
)

// EmailSender is an interface for email sending operations
// Both Mailer and SMTPMailer implement this interface
type EmailSender interface {
	Send(msg MailMessage) error
	SendWithTemplate(to []string, subject string, templatePath string, data map[string]interface{}) error
	SendWithTemplateAndAttachments(to []string, subject string, templatePath string, data map[string]interface{}, attachments []Attachment) error
	SendSimple(to []string, subject, body string, isHTML bool) error
	SendWithAttachment(to []string, subject, body string, isHTML bool, attachmentPath string) error
	SendOTPEmail(to string, otp string, purpose string) error
	Close()
}

// Ensure SMTPMailer implements EmailSender interface
var _ EmailSender = (*SMTPMailer)(nil)

// SMTPMailer handles email sending with a persistent SMTP connection
type SMTPMailer struct {
	config     MailConfig
	client     *smtp.Client
	clientMu   sync.Mutex
	stopChan   chan struct{}
	wg         sync.WaitGroup
	lastActive time.Time
}

// NewSMTPMailer creates a new SMTPMailer instance with persistent connection
func NewSMTPMailer(config MailConfig) *SMTPMailer {
	// Set defaults
	if config.KeepAlive <= 0 {
		config.KeepAlive = 30 * time.Second // Send NOOP every 30 seconds
	}
	if config.SendTimeout <= 0 {
		config.SendTimeout = 30 * time.Second
	}

	m := &SMTPMailer{
		config:   config,
		stopChan: make(chan struct{}),
	}

	// Initialize connection in background (non-blocking)
	go func() {
		if err := m.connect(); err != nil {
			fmt.Printf("Warning: Initial SMTP connection failed: %v\n", err)
		}
	}()

	// Start keepalive goroutine
	m.wg.Add(1)
	go m.keepAliveLoop()

	return m
}

// NewSMTPMailerFromEnv creates a new SMTPMailer from environment variables
func NewSMTPMailerFromEnv() *SMTPMailer {
	port := 587
	if portStr := os.Getenv("SMTP_PORT"); portStr != "" {
		_, _ = fmt.Sscanf(portStr, "%d", &port)
	}

	// Default TLS settings based on port
	useTLS := true
	useSSL := false

	// Auto-detect SSL mode for port 465
	if port == 465 {
		useSSL = true
		useTLS = false // SSL doesn't need STARTTLS
	}

	// Allow override via environment variables
	if tlsStr := os.Getenv("SMTP_USE_TLS"); tlsStr == "false" {
		useTLS = false
	} else if tlsStr == "true" {
		useTLS = true
	}

	if sslStr := os.Getenv("SMTP_USE_SSL"); sslStr == "true" {
		useSSL = true
	} else if sslStr == "false" {
		useSSL = false
	}

	return NewSMTPMailer(MailConfig{
		Host:        os.Getenv("SMTP_HOST"),
		Port:        port,
		Username:    os.Getenv("SMTP_USERNAME"),
		Password:    os.Getenv("SMTP_PASSWORD"),
		From:        os.Getenv("SMTP_FROM"),
		FromName:    os.Getenv("SMTP_FROM_NAME"),
		UseTLS:      useTLS,
		UseSSL:      useSSL,
		KeepAlive:   30 * time.Second, // NOOP every 30 seconds
		SendTimeout: 30 * time.Second,
	})
}

// connect establishes a new SMTP connection
// Supports three connection modes:
// 1. Implicit SSL/TLS (UseSSL=true or port 465): Connection is encrypted from the start
// 2. STARTTLS (UseTLS=true, port 587/25): Starts plain, upgrades to TLS after EHLO
// 3. Plain (UseTLS=false, UseSSL=false): No encryption (not recommended)
func (m *SMTPMailer) connect() error {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()

	// Close existing connection if any
	if m.client != nil {
		_ = m.client.Quit()
		m.client = nil
	}

	addr := fmt.Sprintf("%s:%d", m.config.Host, m.config.Port)

	// Set connection timeout
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	tlsConfig := &tls.Config{
		ServerName:         m.config.Host,
		InsecureSkipVerify: false, // Always verify certificates
	}

	var conn net.Conn
	var err error
	var useImplicitSSL bool

	// Determine if we should use implicit SSL (connection encrypted from start)
	// This is used for port 465 (SMTPS) or when UseSSL is explicitly set
	useImplicitSSL = m.config.UseSSL || m.config.Port == 465

	if useImplicitSSL {
		// Implicit SSL/TLS: Connection is encrypted from the start
		// Used for port 465 (SMTPS) or when UseSSL is explicitly enabled
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to dial SMTP server with implicit SSL (port %d): %w", m.config.Port, err)
		}
	} else {
		// Plain connection: will upgrade to TLS via STARTTLS if needed
		conn, err = dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to dial SMTP server (port %d): %w", m.config.Port, err)
		}
	}

	// Create SMTP client
	client, err := smtp.NewClient(conn, m.config.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}

	// Send EHLO/HELO - required before STARTTLS
	if err := client.Hello("localhost"); err != nil {
		client.Close()
		return fmt.Errorf("failed to send HELO/EHLO: %w", err)
	}

	// STARTTLS: Upgrade plain connection to TLS (only if not using implicit SSL)
	// Port 587 always requires STARTTLS
	// Port 25 uses STARTTLS if UseTLS is enabled
	// Other ports use STARTTLS if UseTLS is enabled
	if !useImplicitSSL {
		shouldStartTLS := false
		switch m.config.Port {
		case 587:
			// Port 587 (submission) always requires STARTTLS per RFC 6409
			shouldStartTLS = true
		case 25:
			// Port 25 uses STARTTLS only if UseTLS is enabled
			shouldStartTLS = m.config.UseTLS
		default:
			// Other ports use STARTTLS if UseTLS is enabled
			shouldStartTLS = m.config.UseTLS
		}

		if shouldStartTLS {
			// Check if server supports STARTTLS
			ok, _ := client.Extension("STARTTLS")
			if !ok {
				client.Close()
				return fmt.Errorf("SMTP server does not support STARTTLS on port %d", m.config.Port)
			}

			if err := client.StartTLS(tlsConfig); err != nil {
				client.Close()
				return fmt.Errorf("failed to upgrade connection with STARTTLS: %w", err)
			}
		}
	}

	// Authenticate if credentials are provided
	if m.config.Username != "" && m.config.Password != "" {
		auth := smtp.PlainAuth("", m.config.Username, m.config.Password, m.config.Host)
		if err := client.Auth(auth); err != nil {
			client.Close()
			return fmt.Errorf("failed to authenticate: %w", err)
		}
	}

	m.client = client
	m.lastActive = time.Now()

	return nil
}

// keepAliveLoop sends NOOP commands to keep the connection alive
// Reconnections happen silently - this is normal behavior when SMTP server closes idle connections
func (m *SMTPMailer) keepAliveLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.config.KeepAlive)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.clientMu.Lock()
			if m.client != nil {
				// Send NOOP to keep connection alive
				if err := m.client.Noop(); err != nil {
					// Connection is dead, close it silently and reconnect
					_ = m.client.Quit()
					m.client = nil
					m.clientMu.Unlock()

					// Reconnect silently - this is normal behavior
					_ = m.connect()
				} else {
					m.lastActive = time.Now()
					m.clientMu.Unlock()
				}
			} else {
				m.clientMu.Unlock()
				// No connection, try to establish one silently
				_ = m.connect()
			}
		}
	}
}

// ensureConnection ensures we have a valid connection
func (m *SMTPMailer) ensureConnection() error {
	m.clientMu.Lock()
	client := m.client
	m.clientMu.Unlock()

	if client != nil {
		// Test connection with NOOP
		m.clientMu.Lock()
		err := m.client.Noop()
		m.clientMu.Unlock()

		if err == nil {
			return nil
		}
		// Connection is dead, reconnect
	}

	return m.connect()
}

// Close closes the mailer and its connection
func (m *SMTPMailer) Close() {
	// Signal keepalive to stop
	select {
	case <-m.stopChan:
		// Already closed
	default:
		close(m.stopChan)
	}

	// Wait for goroutines
	m.wg.Wait()

	m.clientMu.Lock()
	defer m.clientMu.Unlock()

	if m.client != nil {
		_ = m.client.Quit()
		m.client = nil
	}
}

// Send sends an email message
func (m *SMTPMailer) Send(msg MailMessage) error {
	// Ensure we have a connection
	if err := m.ensureConnection(); err != nil {
		return fmt.Errorf("failed to ensure SMTP connection: %w", err)
	}

	// If template path is provided, parse and execute the template
	if msg.TemplatePath != "" {
		body, err := m.parseTemplate(msg.TemplatePath, msg.TemplateData)
		if err != nil {
			return fmt.Errorf("failed to parse template: %w", err)
		}
		msg.Body = body
		msg.IsHTML = true
	}

	// Build email content
	emailData := m.buildEmailData(msg)

	// Send the email
	if err := m.sendEmail(msg, emailData); err != nil {
		// Retry once with reconnection
		if reconnErr := m.connect(); reconnErr != nil {
			return fmt.Errorf("send failed and reconnect failed: %w (reconnect: %v)", err, reconnErr)
		}

		if err := m.sendEmail(msg, emailData); err != nil {
			return fmt.Errorf("send failed after retry: %w", err)
		}
	}

	return nil
}

// sendEmail performs the actual SMTP send
func (m *SMTPMailer) sendEmail(msg MailMessage, emailData []byte) error {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()

	if m.client == nil {
		return fmt.Errorf("no SMTP connection")
	}

	// Set sender
	from := m.config.From
	if err := m.client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Set recipients
	allRecipients := append(append(msg.To, msg.Cc...), msg.Bcc...)
	for _, rcpt := range allRecipients {
		if err := m.client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %w", rcpt, err)
		}
	}

	// Send data
	w, err := m.client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	if _, err := w.Write(emailData); err != nil {
		w.Close()
		return fmt.Errorf("writing email data failed: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing data writer failed: %w", err)
	}

	// Reset for next email (keeps connection alive)
	// Ignore reset errors - connection will be refreshed on next keepalive if needed
	_ = m.client.Reset()

	m.lastActive = time.Now()
	return nil
}

// buildEmailData builds the raw email data with proper MIME formatting
func (m *SMTPMailer) buildEmailData(msg MailMessage) []byte {
	var buf bytes.Buffer

	// From header
	if m.config.FromName != "" {
		buf.WriteString(fmt.Sprintf("From: %s <%s>\r\n", m.config.FromName, m.config.From))
	} else {
		buf.WriteString(fmt.Sprintf("From: %s\r\n", m.config.From))
	}

	// To header
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(msg.To, ", ")))

	// Cc header
	if len(msg.Cc) > 0 {
		buf.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(msg.Cc, ", ")))
	}

	// Subject header
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", msg.Subject))

	// Date header
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))

	// MIME headers
	buf.WriteString("MIME-Version: 1.0\r\n")

	if len(msg.Attachments) > 0 {
		// Multipart email with attachments
		boundary := fmt.Sprintf("----=_Part_%d", time.Now().UnixNano())
		buf.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
		buf.WriteString("\r\n")

		// Body part
		buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		if msg.IsHTML {
			buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		} else {
			buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		}
		buf.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		buf.WriteString("\r\n")
		buf.WriteString(msg.Body)
		buf.WriteString("\r\n")

		// Attachments
		for _, att := range msg.Attachments {
			buf.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			mimeType := att.MimeType
			if mimeType == "" {
				mimeType = getMimeType(att.Filename)
			}
			buf.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", mimeType, att.Filename))
			buf.WriteString("Content-Transfer-Encoding: base64\r\n")
			buf.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", att.Filename))
			buf.WriteString("\r\n")

			// Base64 encode attachment
			encoded := base64Encode(att.Content)
			buf.WriteString(encoded)
			buf.WriteString("\r\n")
		}

		buf.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Simple email without attachments
		if msg.IsHTML {
			buf.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		} else {
			buf.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		}
		buf.WriteString("\r\n")
		buf.WriteString(msg.Body)
		buf.WriteString("\r\n")
	}

	return buf.Bytes()
}

// base64Encode encodes data to base64 with line wrapping
func base64Encode(data []byte) string {
	encoded := make([]byte, base64StdEncodingLen(len(data)))
	base64StdEncode(encoded, data)

	// Wrap lines at 76 characters
	var result strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		result.Write(encoded[i:end])
		if end < len(encoded) {
			result.WriteString("\r\n")
		}
	}
	return result.String()
}

// base64 encoding constants and functions
const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

func base64StdEncodingLen(n int) int {
	return (n + 2) / 3 * 4
}

func base64StdEncode(dst, src []byte) {
	if len(src) == 0 {
		return
	}

	di, si := 0, 0
	n := (len(src) / 3) * 3
	for si < n {
		val := uint(src[si+0])<<16 | uint(src[si+1])<<8 | uint(src[si+2])
		dst[di+0] = base64Chars[val>>18&0x3F]
		dst[di+1] = base64Chars[val>>12&0x3F]
		dst[di+2] = base64Chars[val>>6&0x3F]
		dst[di+3] = base64Chars[val&0x3F]
		si += 3
		di += 4
	}

	remain := len(src) - si
	if remain == 0 {
		return
	}

	val := uint(src[si+0]) << 16
	if remain == 2 {
		val |= uint(src[si+1]) << 8
	}

	dst[di+0] = base64Chars[val>>18&0x3F]
	dst[di+1] = base64Chars[val>>12&0x3F]

	switch remain {
	case 2:
		dst[di+2] = base64Chars[val>>6&0x3F]
		dst[di+3] = '='
	case 1:
		dst[di+2] = '='
		dst[di+3] = '='
	}
}

// parseTemplate parses a .tmpl file and executes it with the provided data
func (m *SMTPMailer) parseTemplate(templatePath string, data map[string]interface{}) (string, error) {
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		return "", fmt.Errorf("failed to parse template file: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// SendWithTemplate sends an email using a template file
func (m *SMTPMailer) SendWithTemplate(to []string, subject string, templatePath string, data map[string]interface{}) error {
	return m.Send(MailMessage{
		To:           to,
		Subject:      subject,
		TemplatePath: templatePath,
		TemplateData: data,
		IsHTML:       true,
	})
}

// SendWithTemplateAndAttachments sends an email using a template file with attachments
func (m *SMTPMailer) SendWithTemplateAndAttachments(to []string, subject string, templatePath string, data map[string]interface{}, attachments []Attachment) error {
	return m.Send(MailMessage{
		To:           to,
		Subject:      subject,
		TemplatePath: templatePath,
		TemplateData: data,
		IsHTML:       true,
		Attachments:  attachments,
	})
}

// SendSimple is a convenience function to send a simple email
func (m *SMTPMailer) SendSimple(to []string, subject, body string, isHTML bool) error {
	return m.Send(MailMessage{
		To:      to,
		Subject: subject,
		Body:    body,
		IsHTML:  isHTML,
	})
}

// SendWithAttachment sends an email with a single attachment
func (m *SMTPMailer) SendWithAttachment(to []string, subject, body string, isHTML bool, attachmentPath string) error {
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

// SendOTPEmail sends an OTP email
func (m *SMTPMailer) SendOTPEmail(to string, otp string, purpose string) error {
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
