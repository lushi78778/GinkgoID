package logx

import (
	"go.uber.org/zap"
)

var logger *zap.Logger

// Init 初始化全局 zap 日志器（生产配置，JSON 编码）。
func Init() (*zap.Logger, error) {
	var err error
	cfg := zap.NewProductionConfig()
	cfg.Encoding = "json"
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
