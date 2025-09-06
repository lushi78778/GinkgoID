package db

import (
	"database/sql"
	"fmt"

	"ginkgoid/internal/infra/config"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

var (
	gdb   *gorm.DB
	sqldb *sql.DB
)

// Init 初始化数据库连接（当前仅支持 MySQL）。
func Init(c config.DBCfg) error {
	if c.Driver != "mysql" {
		return fmt.Errorf("only mysql supported for now")
	}
	d, err := gorm.Open(mysql.Open(c.DSN), &gorm.Config{})
	if err != nil {
		return err
	}
	gdb = d
	sqldb, err = gdb.DB()
	if err != nil {
		return err
	}
	return nil
}

// G 返回全局 gorm.DB。
func G() *gorm.DB { return gdb }

// Close 关闭底层 *sql.DB 连接。
func Close() {
	if sqldb != nil {
		_ = sqldb.Close()
	}
}
