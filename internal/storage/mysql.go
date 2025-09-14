package storage

import (
    "database/sql"
    "fmt"

    "gorm.io/driver/mysql"
    "gorm.io/gorm"
    "gorm.io/gorm/logger"

    "ginkgoid/internal/config"
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

    // 自动迁移数据库结构
    if err := autoMigrate(db); err != nil {
        return nil, err
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
