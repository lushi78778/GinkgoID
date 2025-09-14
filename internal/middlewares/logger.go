package middlewares

// 本中间件负责输出结构化访问日志，记录方法、路径、状态码、耗时与客户端 IP。

import (
    "time"

    "github.com/gin-gonic/gin"
    log "github.com/sirupsen/logrus"
)

// RequestLogger 输出结构化的访问日志（方法、路径、状态、耗时、IP）。
func RequestLogger() gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()
        path := c.Request.URL.Path
        c.Next()
        dur := time.Since(start)
        entry := log.WithFields(log.Fields{
            "method": c.Request.Method,
            "path":   path,
            "status": c.Writer.Status(),
            "latency_ms": dur.Milliseconds(),
            "ip": c.ClientIP(),
        })
        if len(c.Errors) > 0 {
            entry.WithField("errors", c.Errors.String()).Warn("request completed with errors")
        } else {
            entry.Info("request completed")
        }
    }
}
