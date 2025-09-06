package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Encrypt 使用 AES-256-GCM 加密字节数据，密钥由口令通过 argon2id 派生。
// 输出格式：enc-v1:argon2id:<salt_b64url>:<nonce_b64url>:<cipher_b64url>
func Encrypt(passphrase string, plaintext []byte) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	cipher := gcm.Seal(nil, nonce, plaintext, nil)
	return fmt.Sprintf("enc-v1:argon2id:%s:%s:%s",
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(nonce),
		base64.RawURLEncoding.EncodeToString(cipher),
	), nil
}

// Decrypt 按 Encrypt 的输出格式解密并返回明文。
func Decrypt(passphrase, encoded string) ([]byte, error) {
	var version, kdf, saltB64, nonceB64, cipherB64 string
	// Parse parts: enc-v1:argon2id:<salt>:<nonce>:<cipher>
	parts := make([]string, 0)
	cur := ""
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == ':' {
			parts = append(parts, cur)
			cur = ""
		} else {
			cur += string(encoded[i])
		}
	}
	parts = append(parts, cur)
	if len(parts) != 5 {
		return nil, errors.New("invalid enc format")
	}
	version = parts[0]
	kdf = parts[1]
	saltB64 = parts[2]
	nonceB64 = parts[3]
	cipherB64 = parts[4]
	if version != "enc-v1" || kdf != "argon2id" {
		return nil, errors.New("unsupported enc version or kdf")
	}
	salt, err := base64.RawURLEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64)
	if err != nil {
		return nil, err
	}
	cipherBytes, err := base64.RawURLEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, cipherBytes, nil)
}
