package services

import (
	"context"
	"encoding/json"
	"time"

	"gorm.io/gorm"

	"ginkgoid/internal/storage"
)

// SettingService 提供简单的键值配置存储能力（JSON 格式）。
type SettingService struct {
	db *gorm.DB
}

func NewSettingService(db *gorm.DB) *SettingService { return &SettingService{db: db} }

// GetJSON 读取指定键的 JSON 值，如果不存在则返回 false。
func (s *SettingService) GetJSON(ctx context.Context, key string, out interface{}) (bool, error) {
	var rec storage.Setting
	if err := s.db.WithContext(ctx).Where("key = ?", key).First(&rec).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, nil
		}
		return false, err
	}
	if rec.Value == "" {
		return true, nil
	}
	if out != nil {
		if err := json.Unmarshal([]byte(rec.Value), out); err != nil {
			return true, err
		}
	}
	return true, nil
}

// SetJSON 覆盖指定键的 JSON 值。
func (s *SettingService) SetJSON(ctx context.Context, key string, value interface{}) error {
	var payload []byte
	var err error
	if value != nil {
		payload, err = json.Marshal(value)
		if err != nil {
			return err
		}
	}
	rec := &storage.Setting{
		Key:       key,
		Value:     string(payload),
		UpdatedAt: time.Now(),
	}
	return s.db.WithContext(ctx).Save(rec).Error
}
