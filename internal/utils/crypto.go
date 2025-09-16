package utils

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// deriveKey 从给定的密钥材料派生一个 32 字节密钥（SHA-256）。
func deriveKey(keyMaterial string) []byte {
	h := sha256.Sum256([]byte(keyMaterial))
	return h[:]
}

// EncryptAESGCM 使用 AES-256-GCM 加密明文并返回 hex 编码的 nonce+ciphertext。
// keyMaterial 任意长度，内部会派生为 32 字节密钥。
func EncryptAESGCM(keyMaterial string, plaintext []byte) (string, error) {
	if keyMaterial == "" {
		return "", errors.New("key material empty")
	}
	key := deriveKey(keyMaterial)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(crand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := append(nonce, ct...)
	return hex.EncodeToString(out), nil
}

// DecryptAESGCM 解密由 EncryptAESGCM 生成的 hex 字符串。
func DecryptAESGCM(keyMaterial string, hexData string) ([]byte, error) {
	if keyMaterial == "" {
		return nil, errors.New("key material empty")
	}
	data, err := hex.DecodeString(hexData)
	if err != nil {
		return nil, err
	}
	key := deriveKey(keyMaterial)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	nonce := data[:ns]
	ct := data[ns:]
	return gcm.Open(nil, nonce, ct, nil)
}

// RandString 生成长度为 n 字节的随机字节，并以 base64url 编码为 URL 安全的字符串（无填充）。
func RandString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		return "", err
	}
	// 使用不带填充的 Base64 URL 编码
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RandURLSafeString 生成长度为 n 的 URL 安全随机字符串（字符集 [A-Za-z0-9-_]）。
func RandURLSafeString(n int) (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	const mask = 63 // 0b111111
	if n <= 0 {
		return "", nil
	}
	out := make([]byte, n)
	buf := make([]byte, n)
	i := 0
	for i < n {
		if _, err := io.ReadFull(crand.Reader, buf); err != nil {
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

// ATHash 计算 OIDC 规范中的 at_hash 值：取 access_token 的 SHA-256 摘要的左半部分，并以 base64url 编码。
func ATHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	half := sum[:len(sum)/2]
	return base64.RawURLEncoding.EncodeToString(half)
}

// CHash 计算当返回授权码时的 c_hash：取 code 的 SHA-256 摘要的左半部分，并以 base64url 编码。
func CHash(code string) string {
	sum := sha256.Sum256([]byte(code))
	half := sum[:len(sum)/2]
	return base64.RawURLEncoding.EncodeToString(half)
}
