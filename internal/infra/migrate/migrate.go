// Package migrate 提供最小化的 AutoMigrate 入口，便于开发环境快速建表。
// 生产环境建议使用版本化迁移工具（如 goose/atlas）。
package migrate

import (
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
)

// AutoMigrate 执行 GORM 的自动迁移，创建或更新核心表结构。
func AutoMigrate() error {
	return db.G().AutoMigrate(
		&entity.User{},
		&entity.Client{},
		&entity.Consent{},
		&entity.AuthCode{},
		&entity.JWKKey{},
		&entity.Session{},
	)
}
