package cache

import (
	"context"

	"ginkgoid/internal/infra/config"
	"github.com/redis/go-redis/v9"
)

var (
	client *redis.Client
)

// Init 初始化 Redis 客户端（可选）。当未启用时返回 nil。
func Init(c config.RedisCfg) error {
	if !c.Enabled {
		return nil
	}
	client = redis.NewClient(&redis.Options{
		Addr:     c.Addr,
		Password: c.Password,
		DB:       c.DB,
	})
	return client.Ping(context.Background()).Err()
}

// R 返回全局 Redis 客户端（可能为 nil）。
func R() *redis.Client { return client }

// Close 关闭 Redis 客户端。
func Close() {
	if client != nil {
		_ = client.Close()
	}
}
