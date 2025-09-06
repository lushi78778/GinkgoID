package revocation

import (
	"context"
	"errors"
	"time"

	"ginkgoid/internal/infra/cache"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func keyForJTI(jti string) string { return "revoked:" + jti }

// RevokeAccessToken parses a JWT access_token, extracts jti and exp, and stores a
// revocation marker in Redis until token expiry.
// RevokeAccessToken 解析 Access Token，提取 jti 与过期时间，
// 并在 Redis 中写入撤销标记（过期时间与 Token 对齐）。
func RevokeAccessToken(ctx context.Context, token string) (string, error) {
	t, err := jwt.Parse([]byte(token), jwt.WithVerify(false))
	if err != nil {
		return "", err
	}
	jv, ok := t.Get("jti")
	if !ok {
		return "", errors.New("no jti in token")
	}
	jti, _ := jv.(string)
	expv, ok := t.Get("exp")
	if !ok {
		return "", errors.New("no exp in token")
	}
	exp, _ := expv.(time.Time)
	ttl := time.Until(exp)
	if ttl <= 0 {
		ttl = time.Minute
	}
	if r := cache.R(); r != nil {
		if err := r.Set(ctx, keyForJTI(jti), "1", ttl).Err(); err != nil {
			return "", err
		}
		return jti, nil
	}
	return "", errors.New("redis not configured")
}

// RevokeJTI stores a revocation marker for the given jti with provided ttl.
// RevokeJTI 直接按 jti 写入撤销标记，TTL 由调用方控制。
func RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error {
	if r := cache.R(); r != nil {
		return r.Set(ctx, keyForJTI(jti), "1", ttl).Err()
	}
	return errors.New("redis not configured")
}

// IsRevoked checks whether jti is revoked.
// IsRevoked 检查 jti 是否已被撤销。
func IsRevoked(ctx context.Context, jti string) (bool, error) {
	if r := cache.R(); r != nil {
		v, err := r.Get(ctx, keyForJTI(jti)).Result()
		if err != nil {
			return false, nil
		}
		return v != "", nil
	}
	return false, errors.New("redis not configured")
}
