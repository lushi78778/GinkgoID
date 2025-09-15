package services

import (
	"context"
	"strings"

	"gorm.io/gorm"

	"ginkgoid/internal/storage"
)

// ConsentService 负责记录并判定用户对客户端的授权同意（按 scope）。
type ConsentService struct{ db *gorm.DB }

func NewConsentService(db *gorm.DB) *ConsentService { return &ConsentService{db: db} }

// HasConsent 若用户已对该客户端授予至少这些 scope，则返回 true。
func (s *ConsentService) HasConsent(ctx context.Context, userID uint64, clientID string, scope string) bool {
	var c storage.Consent
	if err := s.db.WithContext(ctx).Where("user_id = ? AND client_id = ?", userID, clientID).First(&c).Error; err != nil {
		return false
	}
	have := " " + strings.TrimSpace(c.Scope) + " "
	for _, sc := range strings.Fields(scope) {
		if !strings.Contains(have, " "+sc+" ") {
			return false
		}
	}
	return true
}

// Save 保存/更新同意的 scope（并集语义）。
func (s *ConsentService) Save(ctx context.Context, userID uint64, clientID string, scope string) error {
	var c storage.Consent
	tx := s.db.WithContext(ctx)
	if err := tx.Where("user_id = ? AND client_id = ?", userID, clientID).First(&c).Error; err != nil {
		// create new
		c = storage.Consent{UserID: userID, ClientID: clientID, Scope: strings.TrimSpace(scope)}
		return tx.Create(&c).Error
	}
	// merge scopes
	existing := strings.Fields(c.Scope)
	want := strings.Fields(scope)
	m := map[string]bool{}
	for _, s := range existing {
		m[s] = true
	}
	for _, s := range want {
		m[s] = true
	}
	merged := make([]string, 0, len(m))
	for k := range m {
		merged = append(merged, k)
	}
	c.Scope = strings.Join(merged, " ")
	return tx.Save(&c).Error
}

// ListByUser 列出指定用户的授权同意。
func (s *ConsentService) ListByUser(ctx context.Context, userID uint64) ([]storage.Consent, error) {
	var list []storage.Consent
	if err := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

// Revoke 删除用户对某客户端的授权。
func (s *ConsentService) Revoke(ctx context.Context, userID uint64, clientID string) error {
	return s.db.WithContext(ctx).Where("user_id = ? AND client_id = ?", userID, clientID).Delete(&storage.Consent{}).Error
}
