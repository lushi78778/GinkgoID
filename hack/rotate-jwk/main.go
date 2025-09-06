// 命令行工具：轮换 JWK（RS256 与 ES256），默认灰度窗口 7 天。
package main

import (
	"context"
	"fmt"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/service/jwk"
)

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
	// 轮换 RS256 密钥，设置 7 天的灰度窗口
	if err := jwk.Rotate(context.Background(), "RS256", 7); err != nil {
		panic(err)
	}
	// 轮换 ES256 密钥，设置 7 天的灰度窗口
	if err := jwk.Rotate(context.Background(), "ES256", 7); err != nil {
		panic(err)
	}
	// 打印成功信息
	fmt.Println("jwk rotated with 7-day grace window for RS256 and ES256")
}
