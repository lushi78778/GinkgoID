// 命令行工具：创建或更新一个 OIDC 客户端。
// 用法：
//
//	go run ./hack/create-client <client_id> <name> <redirect_uri> [public|confidential] [secret]
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	svc "ginkgoid/internal/service/client"
)

func main() {
	// 检查命令行参数数量
	if len(os.Args) < 4 {
		fmt.Println("用法: go run ./hack/create-client <client_id> <name> <redirect_uri> [public|confidential] [secret]")
		return
	}
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
	// 解析命令行参数
	clientID := os.Args[1]
	name := os.Args[2]
	redirectURI := os.Args[3]
	mode := "public"
	if len(os.Args) >= 5 {
		mode = os.Args[4]
	}
	var secret *string
	if mode == "confidential" && len(os.Args) >= 6 {
		s := os.Args[5]
		secret = &s
	}
	// 序列化 redirect URIs, post-logout URIs 和 scopes 为 JSON 字符串
	ru, _ := json.Marshal([]string{redirectURI})
	plu, _ := json.Marshal([]string{})
	scopes, _ := json.Marshal([]string{"openid", "profile", "email"})
	// 创建客户端实体
	c := entity.Client{
		ClientID:       clientID,
		Name:           name,
		SecretHash:     nil,
		RedirectURIs:   string(ru),
		PostLogoutURIs: string(plu),
		Scopes:         string(scopes),
		Status:         1,
	}
	if secret != nil && *secret != "" {
		// 确保客户端存在（如果不存在则创建），此时不处理密钥
		if err := svc.EnsureClient(context.Background(), c); err != nil {
			panic(err)
		}
		// 设置密钥，EnsureClient 服务会处理哈希
		c.SecretHash = secret
		if err := svc.EnsureClient(context.Background(), c); err != nil {
			panic(err)
		}
	} else {
		// 创建或更新客户端
		if err := svc.EnsureClient(context.Background(), c); err != nil {
			panic(err)
		}
	}
	fmt.Println("client saved:", clientID)
}
