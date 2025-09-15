package metrics

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// 指标定义：
// - http_requests_total：按路径与方法统计请求次数（附带状态码标签）
// - http_request_duration_seconds：按路径与方法统计请求耗时分布
// - tokens_issued_total：已签发令牌数量
var (
	HTTPRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "http_requests_total", Help: "HTTP 请求计数（按路径/方法/状态）"},
		[]string{"path", "method", "status"},
	)
	HTTPLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "http_request_duration_seconds", Help: "HTTP 请求耗时（秒）", Buckets: prometheus.DefBuckets},
		[]string{"path", "method"},
	)
	TokensIssued    = prometheus.NewCounter(prometheus.CounterOpts{Name: "tokens_issued_total", Help: "签发令牌总数"})
	AuthorizeErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{Name: "authorize_errors_total", Help: "Authorize 错误计数（按原因）"},
		[]string{"reason"},
	)
)

func init() {
	prometheus.MustRegister(HTTPRequests, HTTPLatency, TokensIssued, AuthorizeErrors)
}

// Handler 返回记录基础 HTTP 指标的中间件（QPS/耗时）。
func Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		dur := time.Since(start).Seconds()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		HTTPLatency.WithLabelValues(path, c.Request.Method).Observe(dur)
		HTTPRequests.WithLabelValues(path, c.Request.Method, fmt.Sprintf("%d", c.Writer.Status())).Inc()
	}
}

// Exposer 返回标准 Prometheus 暴露处理器。
func Exposer() gin.HandlerFunc { return gin.WrapH(promhttp.Handler()) }
