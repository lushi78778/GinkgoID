// Package randx 提供与安全随机相关的便捷函数。
package randx

import (
	"crypto/rand"
	"encoding/base64"
)

// ID 生成长度为 n 字节的随机串，并以 URL 安全 Base64 编码返回。
// 常用于 session/jti/csrf 等随机标识。
func ID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
