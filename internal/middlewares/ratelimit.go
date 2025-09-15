package middlewares

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
)

// RateLimit 返回一个使用 Redis INCR+TTL 的限流中间件。
// keyFn 用于构建请求者唯一键（如按 IP 或 client_id）。
func RateLimit(rdb *redis.Client, prefix string, limit int, window time.Duration, keyFn func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := keyFn(c)
		if key == "" {
			c.Next()
			return
		}
		rkey := fmt.Sprintf("rl:%s:%s", prefix, key)
		// 第一次自增时同时设置 TTL 窗口
		cnt, err := rdb.Incr(c, rkey).Result()
		if err == nil && cnt == 1 {
			_ = rdb.Expire(c, rkey, window).Err()
		}
		if err == nil && cnt > int64(limit) {
			c.Header("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
			c.AbortWithStatusJSON(429, gin.H{"error": "rate_limited"})
			return
		}
		c.Next()
	}
}
