package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"

	"ginkgoid/internal/config"
)

type RefreshRecord struct {
	Token    string    `json:"token"`
	UserID   uint64    `json:"user_id"`
	ClientID string    `json:"client_id"`
	Scope    string    `json:"scope"`
	Subject  string    `json:"sub"`
	SID      string    `json:"sid"`
	IssuedAt time.Time `json:"iat"`
}

type RefreshService struct {
	rdb *redis.Client
	cfg config.Config
}

func NewRefreshService(rdb *redis.Client, cfg config.Config) *RefreshService {
	return &RefreshService{rdb: rdb, cfg: cfg}
}

func (s *RefreshService) key(tok string) string { return fmt.Sprintf("rt:%s", tok) }

// Issue 生成新的刷新令牌并按 TTL 存储。
func (s *RefreshService) Issue(ctx context.Context, userID uint64, clientID, scope, subject, sid string) (string, error) {
	token := uuid.NewString()
	rec := &RefreshRecord{Token: token, UserID: userID, ClientID: clientID, Scope: scope, Subject: subject, SID: sid, IssuedAt: time.Now()}
	b, _ := json.Marshal(rec)
	if err := s.rdb.Set(ctx, s.key(token), b, s.cfg.Token.RefreshTokenTTL).Err(); err != nil {
		return "", err
	}
	return token, nil
}

// Use 校验刷新令牌并执行旋转（返回旧记录与新令牌）。
func (s *RefreshService) Use(ctx context.Context, token string) (*RefreshRecord, string, error) {
	cmd := s.rdb.Get(ctx, s.key(token))
	if err := cmd.Err(); err != nil {
		return nil, "", err
	}
	var rec RefreshRecord
	if err := json.Unmarshal([]byte(cmd.Val()), &rec); err != nil {
		return nil, "", err
	}
	// 旋转：删除旧令牌并签发新令牌
	_ = s.rdb.Del(ctx, s.key(token)).Err()
	newTok, err := s.Issue(ctx, rec.UserID, rec.ClientID, rec.Scope, rec.Subject, rec.SID)
	if err != nil {
		return nil, "", err
	}
	return &rec, newTok, nil
}

// Delete 使刷新令牌失效（撤销，不旋转）。
func (s *RefreshService) Delete(ctx context.Context, token string) error {
	return s.rdb.Del(ctx, s.key(token)).Err()
}

// DeleteByUserClient 遍历删除属于指定用户与客户端的刷新令牌。
func (s *RefreshService) DeleteByUserClient(ctx context.Context, userID uint64, clientID string) (int, error) {
	iter := s.rdb.Scan(ctx, 0, "rt:*", 200).Iterator()
	n := 0
	for iter.Next(ctx) {
		k := iter.Val()
		cmd := s.rdb.Get(ctx, k)
		if cmd.Err() != nil {
			continue
		}
		var rec RefreshRecord
		if err := json.Unmarshal([]byte(cmd.Val()), &rec); err != nil {
			continue
		}
		if rec.UserID == userID && rec.ClientID == clientID {
			_ = s.rdb.Del(ctx, k).Err()
			n++
		}
	}
	if err := iter.Err(); err != nil {
		return n, err
	}
	return n, nil
}
