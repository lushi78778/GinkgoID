package services

// 令牌审计仓库：把已签发访问令牌的元数据写入数据库，便于审计与查询。

import (
	"context"
	"time"

	"gorm.io/gorm"

	"ginkgoid/internal/storage"
)

// TokenRepo 简单的令牌审计记录持久化（便于审计/查询）。
type TokenRepo struct{ db *gorm.DB }

func NewTokenRepo(db *gorm.DB) *TokenRepo { return &TokenRepo{db: db} }

// SaveAccessToken 保存访问令牌的审计记录（类型、客户端、用户、scope、jti、过期时间）。
func (r *TokenRepo) SaveAccessToken(ctx context.Context, clientID string, userID uint64, scope string, jti string, exp time.Time) error {
	rec := &storage.TokenRecord{Type: "access", ClientID: clientID, UserID: userID, Scope: scope, JTI: jti, ExpiresAt: exp, Revoked: false, CreatedAt: time.Now()}
	return r.db.WithContext(ctx).Create(rec).Error
}
