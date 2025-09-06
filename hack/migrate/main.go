// 命令行工具：运行 GORM AutoMigrate（开发环境使用）。
package main

import (
	"fmt"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/infra/migrate"
)

// 注意：生产环境请使用版本化迁移（goose/atlas），避免不可控的表结构漂移。
func main() {
	// 加载配置
	if err := config.Load(); err != nil {
		panic(err)
	}
	// 初始化数据库
	if err := db.Init(config.C().DB); err != nil {
		panic(err)
	}
	// 程序退出时关闭数据库连接
	defer db.Close()
	// 执行 GORM 自动迁移
	if err := migrate.AutoMigrate(); err != nil {
		panic(err)
	}
	// 打印成功信息
	fmt.Println("migrations applied (AutoMigrate)")
}
