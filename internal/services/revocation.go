package services

// 撤销服务：将访问令牌的 jti 写入黑名单并设置 TTL，供后续校验拦截。

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

// RevocationService 提供访问令牌撤销（黑名单）能力。
type RevocationService struct{ rdb *redis.Client }

func NewRevocationService(rdb *redis.Client) *RevocationService { return &RevocationService{rdb: rdb} }

func (s *RevocationService) atKey(jti string) string { return fmt.Sprintf("bl:at:%s", jti) }

// RevokeAccessToken 将访问令牌的 jti 标记为撤销状态，TTL 直至过期。
func (s *RevocationService) RevokeAccessToken(ctx context.Context, jti string, ttl time.Duration) error {
	if jti == "" {
		return nil
	}
	return s.rdb.Set(ctx, s.atKey(jti), "1", ttl).Err()
}

// IsAccessTokenRevoked 判断访问令牌 jti 是否已被撤销。
func (s *RevocationService) IsAccessTokenRevoked(ctx context.Context, jti string) bool {
	if jti == "" {
		return false
	}
	val, err := s.rdb.Get(ctx, s.atKey(jti)).Result()
	return err == nil && val == "1"
}
