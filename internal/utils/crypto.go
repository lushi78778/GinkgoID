package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
)

// RandString 生成长度为 n 字节的随机字节，并以 base64url 编码为 URL 安全的字符串（无填充）。
func RandString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	// 使用不带填充的 Base64 URL 编码
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandURLSafeString 生成长度为 n 的 URL 安全随机字符串（字符集 [A-Za-z0-9-_]）。
func RandURLSafeString(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	const mask = 63 // 0b111111 覆盖 0..63，和 alphabet 长度匹配
	if n <= 0 {
		return "", nil
	}
	out := make([]byte, n)
	// 每次读取足够的随机字节，按位与 mask 取下标，丢弃越界值以避免偏倚
	buf := make([]byte, n)
	i := 0
	for i < n {
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			idx := int(b & mask)
			if idx < len(alphabet) {
				out[i] = alphabet[idx]
				i++
				if i >= n {
					break
				}
			}
		}
	}
	return string(out), nil
}

// ATHash 计算 OIDC 规范中的 at_hash 值：
// 取 access_token 的 SHA-256 摘要的左半部分，并以 base64url 编码。
func ATHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	half := sum[:len(sum)/2]
	return base64.RawURLEncoding.EncodeToString(half)
}

// CHash 计算当返回授权码时的 c_hash：
// 取 code 的 SHA-256 摘要的左半部分，并以 base64url 编码。
func CHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	half := sum[:len(sum)/2]
	return base64.RawURLEncoding.EncodeToString(half)
}
