package middleware

import (
	"bytes"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"io"
	"net/http"
	"net/url"
	"provid-backend/internal/logger"
	"strings"
	"time"
)

func HTTPLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip health checks
		if c.Request.URL.Path == "/health" {
			c.Next()
			return
		}

		// Capture request
		start := time.Now()
		reqBody := readBody(c.Request.Body)
		queryParams := c.Request.URL.Query()
		c.Request.Body = io.NopCloser(bytes.NewBuffer(reqBody)) // Reset for Gin

		// Capture response
		//blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		blw := &bodyLogWriter{body: bytes.NewBuffer(nil), ResponseWriter: c.Writer}
		c.Writer = blw

		// Process request
		c.Next()

		// Log to http.log
		//logger.HttpLogger.Info().
		//	Str("method", c.Request.Method).
		//	Str("path", c.Request.URL.Path).
		//	Int("status", c.Writer.Status()).
		//	Dur("latency", time.Since(start)).
		//	Str("client_ip", c.ClientIP()).
		//	Dict("headers", logHeaders(c.Request.Header)).
		//	Str("request_body", string(reqBody)).
		//	Str("response_body", blw.body.String()).
		//	Msg("http_request")

		//logger.AppLogger.Info().
		//	Str("path", c.Request.URL.Path).
		//	Int("status", c.Writer.Status()).
		//	Msg("endpoint_hit")

		latency := time.Since(start)
		resStatus := c.Writer.Status()

		logEvent := logger.AppLogger.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Str("route", c.FullPath()).
			Int("status", resStatus).
			Dur("latency_ms", latency).
			Str("client_ip", c.ClientIP())

		logEvent.Msg("request_processed")

		// Conditionally add error details
		if len(c.Errors) > 0 {
			logEvent = logEvent.
				Strs("errors", c.Errors.Errors()).
				Interface("error_details", c.Errors.JSON())
		}

		httpLog := logger.HttpLogger.Info().
			Str("method", c.Request.Method).
			Str("path", c.Request.URL.Path).
			Int("status", resStatus).
			Str("client_ip", c.ClientIP()).
			Str("user_agent", c.Request.UserAgent()).
			Str("referrer", c.Request.Referer()).
			Dict("query_params", logDictFromValues(queryParams))

		httpLog = httpLog.
			Str("request_body", string(reqBody)).
			//Str("response_body", getResponseBody(c)) // Helper to capture response
			Str("response_body", blw.body.String())
		//if !isSensitivePath(c.Request.URL.Path) {
		//}

		httpLog.Msg("http_trace")
	}
}

// Helpers (keep these private to the package)
func readBody(body io.ReadCloser) []byte {
	if body == nil {
		return nil
	}
	b, _ := io.ReadAll(body)
	return b
}

func logHeaders(h http.Header) *zerolog.Event {
	dict := zerolog.Dict()
	for k, v := range h {
		if strings.EqualFold(k, "Authorization") {
			dict.Str(k, "REDACTED")
		} else {
			dict.Str(k, strings.Join(v, ", "))
		}
	}
	return dict
}

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *bodyLogWriter) Write(b []byte) (int, error) {
	if w.body != nil {
		w.body.Write(b) // Force capture
	}
	return w.ResponseWriter.Write(b)
}

func logDictFromValues(values url.Values) *zerolog.Event {
	dict := zerolog.Dict()
	for k, v := range values {
		dict.Strs(k, v)
	}
	return dict
}

// Checks if path contains sensitive endpoints
func isSensitivePath(path string) bool {
	sensitivePaths := []string{"/login", "/register"}
	for _, p := range sensitivePaths {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

func getResponseBody(c *gin.Context) string {
	if w, ok := c.Writer.(interface{ Body() *bytes.Buffer }); ok {
		return w.Body().String()
	}
	return "[response_not_captured]"
}
