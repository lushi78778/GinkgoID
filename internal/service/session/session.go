package session

import (
	"context"
	"fmt"
	"time"

	"ginkgoid/internal/infra/cache"
	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	"ginkgoid/internal/utility/randx"
	"github.com/gin-gonic/gin"
)

// CookieName 为会话 Cookie 名称。
const CookieName = "gid_session"

// Create 创建会话记录并返回 SID，同时写入（可选）缓存，并执行并发会话上限控制。
func Create(ctx context.Context, userID uint64, ua, ip string, ttl time.Duration) (string, error) {
	sid, _ := randx.ID(16)
	s := entity.Session{SID: sid, UserID: userID, UA: ua, IP: ip, CreatedAt: time.Now(), ExpireAt: time.Now().Add(ttl)}
	if err := db.G().WithContext(ctx).Create(&s).Error; err != nil {
		return "", err
	}
	if r := cache.R(); r != nil {
		key := fmt.Sprintf("sid:%s", sid)
		_ = r.Set(ctx, key, fmt.Sprintf("%d", userID), ttl).Err()
	}
	// Enforce max concurrent sessions
	max := config.C().Security.MaxSessionsPerUser
	if max <= 0 {
		max = 5
	}
	_ = EnforceMaxSessions(ctx, userID, max)
	return sid, nil
}

// Get 根据 SID 获取会话（先读缓存，后查库）。
func Get(ctx context.Context, sid string) (*entity.Session, error) {
	if r := cache.R(); r != nil {
		key := fmt.Sprintf("sid:%s", sid)
		if v, err := r.Get(ctx, key).Result(); err == nil && v != "" {
			// minimal session from cache
			var uid uint64
			_, _ = fmt.Sscanf(v, "%d", &uid)
			return &entity.Session{SID: sid, UserID: uid, CreatedAt: time.Now()}, nil
		}
	}
	var s entity.Session
	if err := db.G().WithContext(ctx).Where("sid = ? AND revoked = 0 AND expire_at > ?", sid, time.Now()).First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

// Revoke 注销指定 SID 的会话（缓存删除 + 标记数据库记录）。
func Revoke(ctx context.Context, sid string) error {
	if r := cache.R(); r != nil {
		_ = r.Del(ctx, fmt.Sprintf("sid:%s", sid)).Err()
	}
	return db.G().WithContext(ctx).Model(&entity.Session{}).Where("sid = ?", sid).Update("revoked", true).Error
}

// EnforceMaxSessions keeps only the most recent `max` active sessions for a user
// EnforceMaxSessions 仅保留最近的 max 个活跃会话，超出部分自动注销。
func EnforceMaxSessions(ctx context.Context, userID uint64, max int) error {
	var list []entity.Session
	if err := db.G().WithContext(ctx).
		Where("user_id = ? AND revoked = 0 AND expire_at > ?", userID, time.Now()).
		Order("created_at DESC").
		Find(&list).Error; err != nil {
		return err
	}
	if len(list) <= max {
		return nil
	}
	// revoke older beyond max
	for i := max; i < len(list); i++ {
		_ = Revoke(ctx, list[i].SID)
	}
	return nil
}

// RevokeAllForUser revokes all active sessions for a user
// RevokeAllForUser 注销某用户的全部活跃会话。
func RevokeAllForUser(ctx context.Context, userID uint64) error {
	var list []entity.Session
	if err := db.G().WithContext(ctx).Where("user_id = ? AND revoked = 0", userID).Find(&list).Error; err != nil {
		return err
	}
	for _, s := range list {
		_ = Revoke(ctx, s.SID)
	}
	return nil
}

// SetCookie 设置会话 Cookie（受配置 secure 与域名控制）。
func SetCookie(c *gin.Context, sid string, ttl time.Duration) {
	cfg := config.C()
	c.SetCookie(CookieName, sid, int(ttl.Seconds()), "/", cfg.Server.CookieDomain, cfg.Server.SecureCookies, true)
}

// ClearCookie 清除会话 Cookie。
func ClearCookie(c *gin.Context) {
	cfg := config.C()
	c.SetCookie(CookieName, "", -1, "/", cfg.Server.CookieDomain, cfg.Server.SecureCookies, true)
}
