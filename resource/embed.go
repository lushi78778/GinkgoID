// Package resource 通过 go:embed 内嵌页面模板与静态资源，避免运行时依赖外部文件。
package resource

import "embed"

// AdminFS 提供统一的只读文件系统访问接口。
//
//go:embed templates/admin/*.html templates/auth/*.html static/admin/js/*.js static/admin/css/*.css static/admin/font/*
var AdminFS embed.FS
