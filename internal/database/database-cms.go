package database

import (
	_ "context"
	"os"
	"provid-backend/internal/logger"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func InitDatabaseCMS() *gorm.DB {
	//mongoClient := InitMongoDB()
	postgresClient := InitPostgresDBCMS()

	return postgresClient
}

func InitPostgresDBCMS() *gorm.DB {
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbName := os.Getenv("DB_NAME")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbPort := os.Getenv("DB_PORT")
	dbSchema := os.Getenv("CMS_DB_SCHEMA")
	dbSSLMode := os.Getenv("DB_SSL_MODE")

	if dbSchema == "" {
		dbSchema = "public"
	}

	//customLogger := logger.NewGormLogService(mongoClient.Database("general_db").Collection("gorm"))

	dsn := "host=" + dbHost +
		" user=" + dbUser +
		" dbname=" + dbName +
		" password=" + dbPassword +
		" port=" + dbPort +
		" sslmode=" + dbSSLMode +
		" TimeZone=Asia/Jakarta" +
		" search_path=" + dbSchema

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		//Logger: customLogger,
	})
	if err != nil {
		logger.AppLogger.Fatal().Err(err).Msg("CC: Failed to connect to database")
		return nil
	}

	logger.AppLogger.Info().Msg("CC: Postgres connection established")

	return db
}
