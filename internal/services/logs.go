package services

import (
    "context"
    "time"

    "gorm.io/gorm"

    "ginkgoid/internal/storage"
)

// LogService 将审计日志持久化到数据库。
type LogService struct{ db *gorm.DB }

func NewLogService(db *gorm.DB) *LogService { return &LogService{db: db} }

// Write 写入一条审计日志。
func (s *LogService) Write(ctx context.Context, level, event string, userID *uint64, clientID *string, desc string, ip string) {
    _ = s.db.WithContext(ctx).Create(&storage.LogRecord{
        Timestamp:  time.Now(),
        Level:      level,
        Event:      event,
        UserID:     userID,
        ClientID:   clientID,
        Description: desc,
        IPAddress:  ip,
    }).Error
}
