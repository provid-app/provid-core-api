package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"provid-backend/internal/database"
	"provid-backend/internal/emailclient"
	"provid-backend/internal/helper"
	"provid-backend/internal/logger"
	"provid-backend/internal/model/data"
	"provid-backend/internal/route"
	"syscall"
	"time"

	"aidanwoods.dev/go-paseto"
)

func main() {
	//generateJWEKeys := flag.Bool("generate-jwe-keys", false, "Generate JWE key pair and exit")
	//keyID := flag.String("key-id", "provid-service-latest", "Key ID for JWE key pair generation")
	//flag.Parse()
	//
	//if *generateJWEKeys {
	//	keyPair, err := helper.GenerateJWEKeyPair(*keyID)
	//	if err != nil {
	//		fmt.Printf("Error generating keys: %v\n", err)
	//		os.Exit(1)
	//	}
	//	fmt.Print(keyPair.PrintEnvFormat())
	//	return
	//}

	env := os.Getenv("APP_ENV")
	fmt.Println("Environment: ", env)
	envPath := ""

	if env == "" {
		_ = os.Setenv("APP_ENV", "development")
		env = "development"
		envPath = "config/.env.dev"
	} else if env == "development" {
		envPath = "config/.env.dev"
	} else if env == "staging" {
		envPath = "config/.env.staging"
	} else if env == "production" {
		envPath = "config/.env.production"
	}

	// Set the environment variable for the server config
	if err := helper.SetServerConfig(envPath); err != nil {
		fmt.Printf("Error setting server config: %v\n", err)
		os.Exit(1)
	}

	// Initialize Paseto V4
	secretB64, _ := base64.StdEncoding.DecodeString(os.Getenv("PASETO_SECRET_KEY"))
	publicB64, _ := base64.StdEncoding.DecodeString(os.Getenv("PASETO_PUBLIC_KEY"))
	secretKey, _ := paseto.NewV4AsymmetricSecretKeyFromBytes(secretB64)
	publicKey, _ := paseto.NewV4AsymmetricPublicKeyFromBytes(publicB64)
	pasetoV4 := data.PasetoItemData{
		PasetoSecret: &secretKey,
		PasetoPublic: &publicKey,
	}

	// Initialize the logger
	logger.Init()
	pgClient := database.InitDatabase()
	cmsClient := database.InitDatabaseCMS()

	// Initialize the email client for external email service
	emailClient, err := emailclient.NewClientFromEnv()
	if err != nil {
		fmt.Printf("Error initializing email client: %v\n", err)
		os.Exit(1)
	}
	defer emailClient.Close() // Ensure email client is closed on shutdown

	// Initialize the server
	router := route.InitRoutes(pgClient, cmsClient, pasetoV4, emailClient)

	// Start the server with graceful shutdown
	port := os.Getenv("SERVER_PORT")
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: router,
	}

	// Run server in a goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.AppLogger.Fatal().Err(err).Msg("Error starting server")
		}
	}()

	logger.AppLogger.Info().Str("port", port).Msg("Server started")

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.AppLogger.Info().Msg("Shutting down server...")

	// Create context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown the server gracefully
	if err := srv.Shutdown(ctx); err != nil {
		logger.AppLogger.Fatal().Err(err).Msg("Server forced to shutdown")
	}

	// Close email client connections
	emailClient.Close()

	logger.AppLogger.Info().Msg("Server exited gracefully")

	//log.Debug().Msg("This appears only if LOG_LEVEL=debug")
	//log.Info().Msg("Server started")
	//log.Error().Msg("Failed to connect to DB")

	//fmt.Printf("Build tags: %s\n", runtime.Version())
	//fmt.Printf("Build tags: %s\n", env)
}
