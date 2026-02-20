package logger

import (
	"os"
	"provid-backend/internal/helper"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	AppLogger  zerolog.Logger
	HttpLogger zerolog.Logger
)

func InitLog() {
	// 1. Set log level from env (default: info)
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}

	// 2. Configure caller marshaling (fixed signature)
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		return short + ":" + strconv.Itoa(line)
	}

	// 3. Multi-output: console (pretty) + file (JSON)
	consoleWriter := zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: time.RFC3339,
	}

	// 4. Ensure logs directory exists
	logPath := "logs/" + helper.GetCurrentTimeWithFormat("02-01-2006")

	if err := helper.CheckIfFileExists(logPath); err == false {
		if err := helper.CreateDirectory(logPath); err != nil {
			log.Error().Err(err).Msg("Failed to create log directory")
			return
		}
	}
	//if err := os.MkdirAll("logs", 0755); err != nil {
	//	log.Error().Err(err).Msg("Failed to create logs directory")
	//}

	// 5. Log file (JSON format)
	fileWriter, err := os.OpenFile(
		logPath+"/app.log",
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0664,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to open log file")
	}

	// 6. Combine writers
	multi := zerolog.MultiLevelWriter(consoleWriter, fileWriter)
	log.Logger = zerolog.New(multi).
		With().
		Timestamp().
		Caller().
		Logger()

	// 7. Override global logger
	zerolog.DefaultContextLogger = &log.Logger
}

func Init() {
	// 1. Set log levels from environment variables
	appLogLevel := parseLogLevel(os.Getenv("LOG_LEVEL"), zerolog.InfoLevel)
	httpLogLevel := parseLogLevel(os.Getenv("LOG_LEVEL"), zerolog.InfoLevel)

	// 2. Configure caller info (for AppLogger only)
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		short := file
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' {
				short = file[i+1:]
				break
			}
		}
		return short + ":" + strconv.Itoa(line)
	}

	// 3. Ensure logs directory exists
	logPath := "logs/" + helper.GetCurrentTimeWithFormat("02-01-2006")

	if err := helper.CheckIfFileExists(logPath); err == false {
		if err := helper.CreateDirectory(logPath); err != nil {
			log.Error().Err(err).Msg("Failed to create log directory")
			return
		}
	}

	// 4. AppLogger (console + file, with caller info)
	appFile, _ := os.OpenFile(logPath+"/app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	multiWriter := zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339},
		appFile,
	)
	AppLogger = zerolog.New(multiWriter).
		Level(appLogLevel).
		With().
		Timestamp().
		Caller().
		Logger()

	// 5. HttpLogger (file only, no caller info)
	httpFile, _ := os.OpenFile(logPath+"/http.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0664)
	HttpLogger = zerolog.New(httpFile).
		Level(httpLogLevel).
		With().
		Timestamp().
		Logger()
}

func parseLogLevel(levelStr string, defaultLevel zerolog.Level) zerolog.Level {
	switch strings.ToLower(levelStr) {
	case "debug":
		return zerolog.DebugLevel
	case "info":
		return zerolog.InfoLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return defaultLevel
	}
}
