package server

import (
	"net/http"
	"os"
	"strings"

	"ginkgoid/internal/infra/config"
	"github.com/gin-gonic/gin"

	// 仅在启用 Swagger 时需要的依赖
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// SetupSwagger 根据配置启用 Swagger UI 与 OpenAPI 文档路由。
// - 路由前缀来自 server.swagger_ui_path（默认 /swagger）
// - 文档地址来自 server.swagger_doc_url（默认 doc.json）
// - 仅当 server.swagger 为 true 时注册
func SetupSwagger(r *gin.Engine) {
	if !config.C().Server.Swagger {
		return
	}
	uiPath := strings.TrimSpace(config.C().Server.SwaggerUIPath)
	if uiPath == "" {
		uiPath = "/swagger"
	}
	// 统一以 /*any 收尾
	uiPath = strings.TrimRight(uiPath, "/") + "/*any"

	// 文档地址配置（相对/绝对均可）。默认 "doc.json"
	docURL := strings.TrimSpace(config.C().Server.SwaggerDocURL)
	if docURL == "" {
		docURL = "doc.json"
	}
	// 若 docURL 为相对路径（例如 "doc.json" 或 "swagger.yaml"），避免与 /swagger/*any 冲突，
	// 将文档文件挂载到独立前缀（如 "/swagger-spec"）。
	if !strings.HasPrefix(docURL, "http://") && !strings.HasPrefix(docURL, "https://") {
		base := strings.TrimSuffix(uiPath, "/*any")
		specBase := base + "-spec" // e.g. "/swagger-spec"
		rel := strings.TrimLeft(docURL, "/")
		docPath := specBase + "/" + rel
		// 本地文件读取 docs/<rel>
		r.GET(docPath, func(c *gin.Context) {
			file := "docs/" + rel
			// 兼容 swag 默认输出 swagger.json：当请求 doc.json 时优先回传 swagger.json
			if rel == "doc.json" {
				if _, statErr := os.Stat("docs/swagger.json"); statErr == nil {
					file = "docs/swagger.json"
				}
				if _, statErr := os.Stat("docs/swagger.yaml"); statErr == nil && file == "docs/doc.json" {
					// 若不存在 swagger.json 但存在 swagger.yaml，则回退到 yaml
					file = "docs/swagger.yaml"
				}
			}
			b, err := os.ReadFile(file)
			if err != nil {
				c.JSON(http.StatusNotFound, gin.H{"error": "swagger_not_generated", "detail": err.Error()})
				return
			}
			ctype := "application/json; charset=utf-8"
			low := strings.ToLower(file)
			if strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") {
				ctype = "application/yaml; charset=utf-8"
			}
			c.Data(http.StatusOK, ctype, b)
		})
		// 兼容别名：同时暴露 /swagger-spec/doc.json 与 /swagger-spec/swagger.json
		if docPath != specBase+"/doc.json" {
			r.GET(specBase+"/doc.json", func(c *gin.Context) {
				file := "docs/swagger.json"
				if _, err := os.Stat(file); err != nil {
					if _, yerr := os.Stat("docs/swagger.yaml"); yerr == nil {
						file = "docs/swagger.yaml"
					} else {
						c.JSON(http.StatusNotFound, gin.H{"error": "swagger_not_generated"})
						return
					}
				}
				b, _ := os.ReadFile(file)
				ctype := "application/json; charset=utf-8"
				if strings.HasSuffix(strings.ToLower(file), ".yaml") || strings.HasSuffix(strings.ToLower(file), ".yml") {
					ctype = "application/yaml; charset=utf-8"
				}
				c.Data(http.StatusOK, ctype, b)
			})
		}
		if docPath != specBase+"/swagger.json" {
			r.GET(specBase+"/swagger.json", func(c *gin.Context) {
				file := "docs/swagger.json"
				b, err := os.ReadFile(file)
				if err != nil {
					c.JSON(http.StatusNotFound, gin.H{"error": "swagger_not_generated"})
					return
				}
				c.Data(http.StatusOK, "application/json; charset=utf-8", b)
			})
		}
		// 让 UI 用该绝对路径加载文档
		docURL = docPath
	}
	// 使用分组以便为 Swagger UI 设置更宽松的 CSP（允许 inline 脚本与样式）。
	base := strings.TrimSuffix(uiPath, "/*any")
	grp := r.Group(base)
	grp.Use(func(c *gin.Context) {
		// 允许 Swagger UI 的 inline 脚本与样式
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'self'")
		c.Next()
	})
	grp.GET("/*any", ginSwagger.WrapHandler(swaggerFiles.Handler, ginSwagger.URL(docURL)))
	// 便捷：/swagger 重定向至 /swagger/index.html
	r.GET(base, func(c *gin.Context) {
		c.Redirect(http.StatusFound, base+"/index.html")
	})
}
