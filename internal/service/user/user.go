package user

import (
	"context"
	"errors"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/infra/logx"
	"ginkgoid/internal/model/entity"
	"ginkgoid/internal/utility/passhash"
	"gorm.io/gorm"
)

// BootstrapAdmin 引导创建或修复管理员账户：
// - 如不存在则创建；
// - 如口令不一致则重置哈希；
// - 如角色非 admin 则修正为 admin。
func BootstrapAdmin(ctx context.Context) error {
	boot := config.C().Admin.Bootstrap
	if boot.Username == "" || boot.Password == "" {
		return nil
	}
	var u entity.User
	err := db.G().WithContext(ctx).Where("username = ?", boot.Username).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		ph, _ := passhash.Hash(boot.Password)
		u = entity.User{Username: boot.Username, PasswordHash: ph, Status: 1, Role: "admin"}
		if err := db.G().WithContext(ctx).Create(&u).Error; err != nil {
			return err
		}
		logx.L().Info("bootstrap admin created")
		return nil
	}
	if err != nil {
		return err
	}
	// ensure password matches config for bootstrap user (dev convenience)
	ok, verr := passhash.Verify(boot.Password, u.PasswordHash)
	if !ok {
		ph, _ := passhash.Hash(boot.Password)
		if err := db.G().WithContext(ctx).Model(&u).Update("password_hash", ph).Error; err != nil {
			return err
		}
		logx.L().Info("bootstrap admin password reset", logx.String("reason", errString(verr)))
		return nil
	}
	// ensure role is admin
	if u.Role != "admin" {
		if err := db.G().WithContext(ctx).Model(&u).Update("role", "admin").Error; err != nil {
			return err
		}
		logx.L().Info("bootstrap admin role set to admin")
		return nil
	}
	return nil
}

// GetByUsername 根据用户名查询启用中的用户。
func GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	var u entity.User
	if err := db.G().WithContext(ctx).Where("username = ? AND status = 1", username).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

// GetByID 根据用户 ID 查询启用中的用户。
func GetByID(ctx context.Context, id uint64) (*entity.User, error) {
	var u entity.User
	if err := db.G().WithContext(ctx).Where("id = ? AND status = 1", id).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
