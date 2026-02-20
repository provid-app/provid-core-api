package database

import (
	"context"
	"os"
	"provid-backend/internal/logger"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func InitDatabase() *gorm.DB {
	//mongoClient := InitMongoDB()
	postgresClient := InitPostgresDB()

	return postgresClient
}

func InitPostgresDB() *gorm.DB {
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbName := os.Getenv("DB_NAME")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbPort := os.Getenv("DB_PORT")
	dbSchema := os.Getenv("DB_SCHEMA")
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

func InitMongoDB() *mongo.Client {
	mongoUrl := os.Getenv("MONGO_URL")
	mongoPort := os.Getenv("MONGO_PORT")

	mongoStr := mongoUrl + mongoPort
	if os.Getenv("MONGO_TYPE") == "srv" {
		mongoStr = os.Getenv("MONGO_SRV_URL")
	}

	clientOptions := options.Client().ApplyURI(mongoStr)
	if os.Getenv("MONGO_TYPE") == "local" {
		clientOptions.SetAuth(options.Credential{
			Username: os.Getenv("MONGO_USERNAME"),
			Password: os.Getenv("MONGO_PASSWORD"),
		})
	} else {
		//clientOptions.set
	}

	c, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		logger.AppLogger.Fatal().Err(err).Msg("Error connecting to mongo")
		return nil
	}

	err = c.Ping(context.TODO(), nil)
	if err != nil {
		logger.AppLogger.Fatal().Err(err).Msg("Error pinging mongo at " + mongoUrl + mongoPort + " = " + err.Error())
		return nil
	}

	logger.AppLogger.Info().Msg("CC: MongoDB connection established")

	return c
}
