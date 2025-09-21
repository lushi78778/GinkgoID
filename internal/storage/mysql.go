package storage

import (
	"database/sql"
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"ginkgoid/internal/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
)

// InitMySQL 打开到 MySQL 的 GORM 连接，并通过 AutoMigrate 确保表结构存在。
func InitMySQL(cfg config.Config) (*gorm.DB, error) {
	dsn := cfg.MySQL.DSN()
	gcfg := &gorm.Config{Logger: logger.Default.LogMode(logger.Warn)}
	db, err := gorm.Open(mysql.Open(dsn), gcfg)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}
	// 验证底层连接可用
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("sql db: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("ping mysql: %w", err)
	}

	// 检查 User 表是否已存在，用于后续是否创建初始管理员
	hadUserTable := db.Migrator().HasTable(&User{})

	// 自动迁移数据库结构
	migrateStart := time.Now()
	log.Info("starting auto-migrate")
	if err := autoMigrate(db); err != nil {
		return nil, err
	}
	log.WithField("elapsed", time.Since(migrateStart)).Info("auto-migrate finished")

	// 仅在首次建表时创建初始管理员（可通过配置启用/关闭）
	if !hadUserTable && cfg.Bootstrap.InitialAdmin.Enable {
		ia := cfg.Bootstrap.InitialAdmin
		if ia.Username == "" {
			ia.Username = "admin"
		}
		if ia.Password == "" {
			ia.Password = "123465"
		}
		now := time.Now()
		hash, _ := bcrypt.GenerateFromPassword([]byte(ia.Password), bcrypt.DefaultCost)
		u := &User{Username: ia.Username, Password: string(hash), Email: ia.Email, EmailVerified: false, Name: ia.Name, IsAdmin: true, CreatedAt: now, UpdatedAt: now}
		// 避免潜在重复
		_ = db.Where("username = ?", ia.Username).First(&User{}).Error
		if err := db.Create(u).Error; err != nil {
			// 创建失败不应阻断服务启动，仅打印日志
			// 但 storage 层没有日志依赖，返回错误可能更安全
			// 这里选择返回错误以确保可见
			return nil, fmt.Errorf("create initial admin: %w", err)
		}
	}
	return db, nil
}

// CloseMySQL 关闭底层 sql.DB 连接。
func CloseMySQL(db *gorm.DB) {
	if db == nil {
		return
	}
	var s *sql.DB
	var err error
	s, err = db.DB()
	if err == nil && s != nil {
		_ = s.Close()
	}
}
