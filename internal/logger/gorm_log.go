package logger

//
//import (
//	data2 "authBackend/cmd/internal/model/data"
//	"context"
//	"fmt"
//	"go.mongodb.org/mongo-driver/mongo"
//	"gorm.io/gorm/logger"
//	"log"
//	"time"
//)
//
//type GormLoggerService struct {
//	LogGorm *mongo.Collection
//}
//
//func (c *GormLoggerService) LogMode(level logger.LogLevel) logger.Interface {
//	return c
//}
//
//func (c *GormLoggerService) Info(ctx context.Context, msg string, data ...interface{}) {
//	loc, _ := time.LoadLocation("Asia/Jakarta")
//
//	entry := data2.LogEntry{
//		Timestamp: time.Now().In(loc).Format(time.RFC3339),
//		Level:     "info",
//		Message:   fmt.Sprintf(msg, data...),
//	}
//	_, err := c.LogGorm.InsertOne(ctx, entry)
//	if err != nil {
//		log.Println("Failed to insert log entry:", err)
//	}
//}
//
//func (c *GormLoggerService) Warn(ctx context.Context, msg string, data ...interface{}) {
//	loc, _ := time.LoadLocation("Asia/Jakarta")
//
//	entry := data2.LogEntry{
//		Timestamp: time.Now().In(loc).Format(time.RFC3339),
//		Level:     "warn",
//		Message:   fmt.Sprintf(msg, data...),
//	}
//	_, err := c.LogGorm.InsertOne(ctx, entry)
//	if err != nil {
//		log.Println("Failed to insert log entry:", err)
//	}
//}
//
//func (c *GormLoggerService) Error(ctx context.Context, msg string, data ...interface{}) {
//	loc, _ := time.LoadLocation("Asia/Jakarta")
//
//	entry := data2.LogEntry{
//		Timestamp: time.Now().In(loc).Format(time.RFC3339),
//		Level:     "error",
//		Message:   fmt.Sprintf(msg, data...),
//	}
//	_, err := c.LogGorm.InsertOne(ctx, entry)
//	if err != nil {
//		log.Println("Failed to insert log entry:", err)
//	}
//}
//
//func (c *GormLoggerService) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
//	elapsed := time.Since(begin)
//	sql, _ := fc()
//	loc, _ := time.LoadLocation("Asia/Jakarta")
//
//	entry := data2.LogEntry{
//		Timestamp: time.Now().In(loc).Format(time.RFC3339),
//		Level:     "trace",
//		Message:   "Executed query",
//		Query:     sql,
//		Duration:  elapsed.Milliseconds(),
//	}
//
//	if err != nil {
//		entry.Error = err.Error()
//	}
//
//	_, insertErr := c.LogGorm.InsertOne(ctx, entry)
//	if insertErr != nil {
//		log.Println("Failed to insert log entry:", insertErr)
//	}
//}
//
//func NewGormLogService(logGorm *mongo.Collection) *GormLoggerService {
//	return &GormLoggerService{
//		LogGorm: logGorm,
//	}
//}
