package consent

import (
	"context"
	"encoding/json"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	"gorm.io/gorm"
)

// HasConsent 判断用户是否已对指定客户端授权所需的所有 scope，且版本不低于配置版本。
func HasConsent(ctx context.Context, userID uint64, clientID string, scopes []string) (bool, error) {
	var c entity.Consent
	if err := db.G().WithContext(ctx).Where("user_id = ? AND client_id = ?", userID, clientID).First(&c).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	var saved []string
	_ = json.Unmarshal([]byte(c.Scopes), &saved)
	need := map[string]struct{}{}
	for _, s := range scopes {
		need[s] = struct{}{}
	}
	for _, s := range saved {
		delete(need, s)
	}
	if len(need) == 0 && c.Version >= config.C().Consent.Version {
		return true, nil
	}
	return false, nil
}

// Save 保存或更新用户对客户端的授权记录。
func Save(ctx context.Context, userID uint64, clientID string, scopes []string, remember bool) error {
	b, _ := json.Marshal(scopes)
	var c entity.Consent
	err := db.G().WithContext(ctx).Where("user_id = ? AND client_id = ?", userID, clientID).First(&c).Error
	if err == nil {
		c.Scopes = string(b)
		c.Version = config.C().Consent.Version
		c.Remember = remember
		return db.G().WithContext(ctx).Save(&c).Error
	}
	c = entity.Consent{UserID: userID, ClientID: clientID, Scopes: string(b), Version: config.C().Consent.Version, Remember: remember}
	return db.G().WithContext(ctx).Create(&c).Error
}
