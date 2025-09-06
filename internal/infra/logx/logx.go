package logx

import (
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var logger *zap.Logger

// Init 初始化全局 zap 日志器（生产配置，JSON 编码）。
func Init() (*zap.Logger, error) {
	var err error
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "json"
	// 人类可读时间（UTC+8）替换默认的 epoch 秒 "ts"
	enc := zap.NewProductionEncoderConfig()
	enc.TimeKey = "time"
	// ISO8601 带毫秒与时区偏移，例如 2025-09-06T10:08:00.123+08:00
	loc, _ := time.LoadLocation("Asia/Shanghai")
	if loc == nil {
		loc = time.FixedZone("UTC+8", 8*3600)
	}
	enc.EncodeTime = func(t time.Time, pa zapcore.PrimitiveArrayEncoder) {
		pa.AppendString(t.In(loc).Format("2006-01-02T15:04:05.000Z07:00"))
	}
	cfg.EncoderConfig = enc
	logger, err = cfg.Build()
	if err != nil {
		return nil, err
	}
	zap.ReplaceGlobals(logger)
	return logger, nil
}

// L 返回全局日志器。
func L() *zap.Logger { return logger }

// 便捷字段构造函数。
func Err(err error) zap.Field       { return zap.Error(err) }
func String(k, v string) zap.Field  { return zap.String(k, v) }
func Int(k string, v int) zap.Field { return zap.Int(k, v) }
