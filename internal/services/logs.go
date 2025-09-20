package services

import (
	"context"
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"
	"gorm.io/gorm"

	"ginkgoid/internal/storage"
)

// LogService 将审计日志持久化到数据库。
type LogService struct{ db *gorm.DB }

func NewLogService(db *gorm.DB) *LogService { return &LogService{db: db} }

// Write 写入一条审计日志。
type LogWriteOpts struct {
	RequestID string
	SessionID string
	Method    string
	Path      string
	Status    int
	UserAgent string
	Outcome   string // success | failure
	ErrorCode string
	Extra     any // 将被序列化为 JSON（注意调用侧脱敏）
}

func (s *LogService) Write(ctx context.Context, level, event string, userID *uint64, clientID *string, desc string, ip string, opts ...LogWriteOpts) error {
	var o LogWriteOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	extra := ""
	if o.Extra != nil {
		if b, err := json.Marshal(o.Extra); err == nil {
			extra = string(b)
		}
	}
	rec := &storage.LogRecord{
		Timestamp:   time.Now(),
		Level:       level,
		Event:       event,
		UserID:      userID,
		ClientID:    clientID,
		Description: desc,
		IPAddress:   ip,
		RequestID:   o.RequestID,
		SessionID:   o.SessionID,
		Method:      o.Method,
		Path:        o.Path,
		Status:      o.Status,
		UserAgent:   o.UserAgent,
		Outcome:     o.Outcome,
		ErrorCode:   o.ErrorCode,
		ExtraJSON:   extra,
	}
	if err := s.db.WithContext(ctx).Create(rec).Error; err != nil {
		log.WithError(err).WithFields(log.Fields{
			"event":      event,
			"level":      level,
			"user_id":    userID,
			"client_id":  clientID,
			"request_id": o.RequestID,
			"path":       o.Path,
		}).Error("audit log write failed")
		return err
	}
	return nil
}

// Query 支持按时间范围/级别/事件/用户/客户端筛选日志，默认倒序，limit<=1000。
func (s *LogService) Query(ctx context.Context, from, to *time.Time, level, event string, userID *uint64, clientID *string, limit int) ([]storage.LogRecord, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := s.db.WithContext(ctx).Model(&storage.LogRecord{})
	if from != nil {
		q = q.Where("timestamp >= ?", *from)
	}
	if to != nil {
		q = q.Where("timestamp <= ?", *to)
	}
	if level != "" {
		q = q.Where("level = ?", level)
	}
	if event != "" {
		q = q.Where("event = ?", event)
	}
	if userID != nil {
		q = q.Where("user_id = ?", *userID)
	}
	if clientID != nil && *clientID != "" {
		q = q.Where("client_id = ?", *clientID)
	}
	var list []storage.LogRecord
	if err := q.Order("id desc").Limit(limit).Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

// LogQuery 更丰富的筛选条件。
type LogQuery struct {
	From, To     *time.Time
	Level, Event string
	UserID       *uint64
	ClientID     *string
	Limit        int
	RequestID    string
	Outcome      string
	ErrorCode    string
	Method       string
	Path         string
	UserAgent    string
	Status       *int
}

// Query2 支持更多字段筛选（向后兼容保留 Query）。
func (s *LogService) Query2(ctx context.Context, qy LogQuery) ([]storage.LogRecord, error) {
	limit := qy.Limit
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	q := s.db.WithContext(ctx).Model(&storage.LogRecord{})
	if qy.From != nil {
		q = q.Where("timestamp >= ?", *qy.From)
	}
	if qy.To != nil {
		q = q.Where("timestamp <= ?", *qy.To)
	}
	if qy.Level != "" {
		q = q.Where("level = ?", qy.Level)
	}
	if qy.Event != "" {
		q = q.Where("event = ?", qy.Event)
	}
	if qy.UserID != nil {
		q = q.Where("user_id = ?", *qy.UserID)
	}
	if qy.ClientID != nil && *qy.ClientID != "" {
		q = q.Where("client_id = ?", *qy.ClientID)
	}
	if qy.RequestID != "" {
		q = q.Where("request_id = ?", qy.RequestID)
	}
	if qy.Outcome != "" {
		q = q.Where("outcome = ?", qy.Outcome)
	}
	if qy.ErrorCode != "" {
		q = q.Where("error_code = ?", qy.ErrorCode)
	}
	if qy.Method != "" {
		q = q.Where("method = ?", qy.Method)
	}
	if qy.Path != "" {
		q = q.Where("path = ?", qy.Path)
	}
	if qy.UserAgent != "" {
		q = q.Where("user_agent = ?", qy.UserAgent)
	}
	if qy.Status != nil {
		q = q.Where("status = ?", *qy.Status)
	}
	var list []storage.LogRecord
	if err := q.Order("id desc").Limit(limit).Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}
