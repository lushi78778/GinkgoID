package client

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	"ginkgoid/internal/utility/passhash"
	"gorm.io/gorm"
)

// Get 获取启用中的客户端。
func Get(ctx context.Context, clientID string) (*entity.Client, error) {
	var cli entity.Client
	if err := db.G().WithContext(ctx).Where("client_id = ? AND status = 1", clientID).First(&cli).Error; err != nil {
		return nil, err
	}
	return &cli, nil
}

// IsRedirectAllowed 判断 redirect_uri 是否在客户端白名单中（完全匹配）。
func IsRedirectAllowed(cli *entity.Client, uri string) bool {
	var list []string
	_ = json.Unmarshal([]byte(cli.RedirectURIs), &list)
	for _, u := range list {
		if u == uri {
			return true
		}
	}
	return false
}

// IsLogoutRedirectAllowed 判断 post_logout_redirect_uri 是否白名单允许。
func IsLogoutRedirectAllowed(cli *entity.Client, uri string) bool {
	var list []string
	_ = json.Unmarshal([]byte(cli.PostLogoutURIs), &list)
	for _, u := range list {
		if u == uri {
			return true
		}
	}
	return false
}

// CheckSecret 校验机密客户端的口令（哈希对比）。
func CheckSecret(ctx context.Context, cli *entity.Client, provided string) (bool, error) {
	if cli.SecretHash == nil || *cli.SecretHash == "" { // public client
		return false, nil
	}
	ok, err := passhash.Verify(provided, *cli.SecretHash)
	return ok, err
}

// secureCompare 常量时间比较，避免时序侧信道。
func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// EnsureClient 以 client_id 为键进行“有则更，无则增”的保存流程。
// - 若提供了明文 secret，会自动生成哈希保存；
// - JSON 字段为空时保存为 "[]"；
// - 返回第一条错误。
func EnsureClient(ctx context.Context, c entity.Client) error {
	// helper used by future CLI; upsert by client_id
	var existing entity.Client
	err := db.G().WithContext(ctx).Where("client_id = ?", c.ClientID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		sanitizeJSONFields(&c)
		// If SecretHash holds plain secret from caller, hash it here
		if c.SecretHash != nil && *c.SecretHash != "" {
			h, _ := passhash.Hash(*c.SecretHash)
			c.SecretHash = &h
		}
		return db.G().WithContext(ctx).Create(&c).Error
	}
	if err != nil {
		return err
	}
	c.ClientID = existing.ClientID
	sanitizeJSONFields(&c)
	// If SecretHash provided, treat as plain and hash
	if c.SecretHash != nil && *c.SecretHash != "" {
		h, _ := passhash.Hash(*c.SecretHash)
		c.SecretHash = &h
	}
	return db.G().WithContext(ctx).Model(&existing).Updates(c).Error
}

// sanitizeJSONFields 规整客户端的 JSON 字段，空值归一化为 "[]"，便于前端处理。
func sanitizeJSONFields(c *entity.Client) {
	if strings.TrimSpace(c.RedirectURIs) == "" {
		c.RedirectURIs = "[]"
	}
	if strings.TrimSpace(c.PostLogoutURIs) == "" {
		c.PostLogoutURIs = "[]"
	}
	if strings.TrimSpace(c.Scopes) == "" {
		c.Scopes = "[]"
	}
}
