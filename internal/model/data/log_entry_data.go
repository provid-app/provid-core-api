package data

type LogEntry struct {
	Timestamp string `bson:"timestamp"`
	Level     string `bson:"level"`
	Message   string `bson:"message"`
	Query     string `bson:"query,omitempty"`
	Error     string `bson:"error,omitempty"`
	Duration  int64  `bson:"duration,omitempty"` // Duration in milliseconds
}
