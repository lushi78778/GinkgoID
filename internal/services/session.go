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
}

// SessionService 提供 OP 会话的创建/读取/删除能力。
type SessionService struct {
    rdb *redis.Client
    cfg config.Config
}

func NewSessionService(rdb *redis.Client, cfg config.Config) *SessionService {
    return &SessionService{rdb: rdb, cfg: cfg}
}

func (s *SessionService) New(ctx context.Context, userID uint64, acr string, amr []string) (*Session, error) {
    sid := uuid.NewString()
    sess := &Session{
        SID: sid, UserID: userID, ACR: acr, AMR: amr, AuthTime: time.Now(),
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
    if err := cmd.Err(); err != nil { return nil, err }
    var sess Session
    if err := json.Unmarshal([]byte(cmd.Val()), &sess); err != nil { return nil, err }
    return &sess, nil
}

func (s *SessionService) Delete(ctx context.Context, sid string) error {
    key := fmt.Sprintf("session:%s", sid)
    return s.rdb.Del(ctx, key).Err()
}
