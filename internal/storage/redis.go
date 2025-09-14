package storage

// Redis 连接初始化：提供带超时的连接与启动时健康检查（PING）。

import (
    "fmt"
    "time"

    "github.com/go-redis/redis/v8"

    "ginkgoid/internal/config"
)

// InitRedis 通过 go-redis v8 连接 Redis，并做一次 Ping 验证。
func InitRedis(cfg config.Config) (*redis.Client, error) {
    rdb := redis.NewClient(&redis.Options{
        Addr:        cfg.Redis.Addr,
        Password:    cfg.Redis.Password,
        DB:          cfg.Redis.DB,
        DialTimeout: 5 * time.Second,
    })
    if err := rdb.Ping(rdb.Context()).Err(); err != nil {
        return nil, fmt.Errorf("redis ping: %w", err)
    }
    return rdb, nil
}
