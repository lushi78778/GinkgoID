package services

// 会话服务：在 Redis 中创建、读取与删除 OP 浏览器会话（含 ACR/AMR 与认证时间）。

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"ginkgoid/internal/config"
)

// Session 表示 OP 维护的浏览器会话。
// 存储在 Redis：key=session:<sid>，值为 JSON。
type Session struct {
	SID       string    `json:"sid"`
	UserID    uint64    `json:"user_id"`
	ACR       string    `json:"acr"`
	AMR       []string  `json:"amr"`
	AuthTime  time.Time `json:"auth_time"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
}

// SessionService 提供 OP 会话的创建/读取/删除能力。
type SessionService struct {
	rdb *redis.Client
	cfg config.Config
}

func NewSessionService(rdb *redis.Client, cfg config.Config) *SessionService {
	return &SessionService{rdb: rdb, cfg: cfg}
}

func (s *SessionService) New(ctx context.Context, userID uint64, acr string, amr []string, ip string, ua string) (*Session, error) {
	sid := uuid.NewString()
	sess := &Session{
		SID:       sid,
		UserID:    userID,
		ACR:       acr,
		AMR:       amr,
		AuthTime:  time.Now(),
		LastSeen:  time.Now(),
		UserAgent: ua,
		IP:        ip,
	}
	b, _ := json.Marshal(sess)
	key := fmt.Sprintf("session:%s", sid)
	if err := s.rdb.Set(ctx, key, b, s.cfg.Session.TTL).Err(); err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *SessionService) Get(ctx context.Context, sid string) (*Session, error) {
	key := fmt.Sprintf("session:%s", sid)
	cmd := s.rdb.Get(ctx, key)
	if err := cmd.Err(); err != nil {
		return nil, err
	}
	var sess Session
	if err := json.Unmarshal([]byte(cmd.Val()), &sess); err != nil {
		return nil, err
	}
	if sess.LastSeen.IsZero() {
		sess.LastSeen = sess.AuthTime
	}
	return &sess, nil
}

func (s *SessionService) Delete(ctx context.Context, sid string) error {
	key := fmt.Sprintf("session:%s", sid)
	return s.rdb.Del(ctx, key).Err()
}

// ListByUser 扫描 Redis，返回指定用户的所有会话。
func (s *SessionService) ListByUser(ctx context.Context, userID uint64) ([]Session, error) {
	iter := s.rdb.Scan(ctx, 0, "session:*", 0).Iterator()
	result := make([]Session, 0)
	for iter.Next(ctx) {
		key := iter.Val()
		cmd := s.rdb.Get(ctx, key)
		if cmd.Err() != nil {
			continue
		}
		var sess Session
		if err := json.Unmarshal([]byte(cmd.Val()), &sess); err != nil {
			continue
		}
		if sess.UserID == userID {
			if sess.LastSeen.IsZero() {
				sess.LastSeen = sess.AuthTime
			}
			result = append(result, sess)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteOthers 删除用户除 keepSID 之外的所有会话。
func (s *SessionService) DeleteOthers(ctx context.Context, userID uint64, keepSID string) error {
	sessions, err := s.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if sess.SID == keepSID {
			continue
		}
		_ = s.Delete(ctx, sess.SID)
	}
	return nil
}

// DeleteForUser 删除指定用户的单个会话。
func (s *SessionService) DeleteForUser(ctx context.Context, userID uint64, sid string) error {
	sessions, err := s.ListByUser(ctx, userID)
	if err != nil {
		return err
	}
	for _, sess := range sessions {
		if sess.SID == sid {
			return s.Delete(ctx, sid)
		}
	}
	return fmt.Errorf("session_not_found")
}
