package middleware

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"ginkgoid/internal/infra/cache"

	"github.com/gin-gonic/gin"
)

// RateLimit 固定窗口（分钟级）限流，使用 Redis INCR + EXPIRE 实现。
// 过程：每次请求对指定 key 执行 INCR；当值首次出现（返回 1）时设置 60s 过期；
// 之后若超过阈值则返回 429。该方法实现简单，但窗口边界存在“突刺”效应。
func RateLimit(keyFunc func(*gin.Context) string, limit int) gin.HandlerFunc {
	return func(c *gin.Context) {
		r := cache.R()
		if r == nil { // no redis, skip
			c.Next()
			return
		}
		key := keyFunc(c)
		if key == "" {
			c.Next()
			return
		}
		ctx := context.Background()
		cnt, err := r.Incr(ctx, key).Result()
		if err == nil && cnt == 1 {
			r.Expire(ctx, key, time.Minute)
		}
		if err != nil {
			c.Next()
			return
		}
		if cnt > int64(limit) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		c.Next()
	}
}

func RLKeyByIP(prefix string) func(*gin.Context) string {
	return func(c *gin.Context) string {
		return fmt.Sprintf("rl:%s:%s", prefix, c.ClientIP())
	}
}

func RLKeyByClient(prefix string) func(*gin.Context) string {
	return func(c *gin.Context) string {
		cid := c.PostForm("client_id")
		if cid == "" {
			cid = c.Query("client_id")
		}
		if cid == "" {
			cid = "unknown"
		}
		return fmt.Sprintf("rl:%s:%s", prefix, cid)
	}
}

// RateLimitTokenBucket 令牌桶限流（容量/每秒补充速率）。
// 通过 Redis Lua 脚本维护令牌与最近补充时间，具备原子性，不会发生并发竞争。
func RateLimitTokenBucket(keyFunc func(*gin.Context) string, capacity int, refillPerSec float64) gin.HandlerFunc {
	// KEYS[1] = 桶的 key；ARGV = [容量, 每秒补充速率, 当前毫秒时间戳]
	// 返回 1 表示允许，0 表示限流。
	const script = `
local key = KEYS[1]
local cap = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil then tokens = cap ts = now end -- 第一次访问，填满桶
local delta = 0
if now > ts then delta = (now - ts) / 1000.0 * rate end -- 可补充的令牌数
tokens = math.min(cap, tokens + delta)
local allowed = 0
if tokens >= 1 then tokens = tokens - 1 allowed = 1 end -- 消耗 1 个令牌
redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
-- 过期时间：取 max(1s, 两倍“从 0 补满”时长)，避免热点长久占用
redis.call('PEXPIRE', key, math.floor( math.max(1000, (cap / rate) * 2000) ))
return allowed
            `
	return func(c *gin.Context) {
		r := cache.R()
		if r == nil {
			c.Next()
			return
		}
		key := keyFunc(c)
		if key == "" {
			c.Next()
			return
		}
		now := time.Now().UnixMilli() // 统一毫秒时间戳，便于脚本计算
		res, err := r.Eval(context.Background(), script, []string{key}, capacity, refillPerSec, now).Int()
		if err != nil {
			c.Next()
			return
		}
		if res == 0 {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "rate_limited"})
			return
		}
		c.Next()
	}
}

// RLKeyByIPUser 以 IP+用户名 组合生成限流键（用于 /login）。
func RLKeyByIPUser(prefix string) func(*gin.Context) string {
	return func(c *gin.Context) string {
		u := c.PostForm("username")
		if u == "" {
			u = c.Query("username")
		}
		return fmt.Sprintf("rl:%s:%s:%s", prefix, c.ClientIP(), u)
	}
}

// RLKeyByClientIP 以 client_id+IP 组合生成限流键（用于 /token）。
func RLKeyByClientIP(prefix string) func(*gin.Context) string {
	return func(c *gin.Context) string {
		cid := c.PostForm("client_id")
		if cid == "" {
			cid = c.Query("client_id")
		}
		return fmt.Sprintf("rl:%s:%s:%s", prefix, cid, c.ClientIP())
	}
}
