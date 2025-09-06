package passhash

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

var defaultParams = Params{
	Memory:      64 * 1024,
	Iterations:  1,
	Parallelism: 4,
	SaltLen:     16,
	KeyLen:      32,
}

// Hash 生成口令的 argon2id 哈希，返回可存储的编码字符串。
func Hash(password string) (string, error) {
	p := defaultParams
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
	return fmt.Sprintf("argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", p.Memory, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify 校验口令与编码哈希是否匹配。
// 支持 URL 安全 Base64 的编码格式：
//
//	argon2id$v=19$m=<mem>,t=<iter>,p=<par>$<salt_b64url>$<key_b64url>
func Verify(password, encoded string) (bool, error) {
	// Expected format:
	// argon2id$v=19$m=65536,t=1,p=4$<salt_b64url>$<key_b64url>
	if !strings.HasPrefix(encoded, "argon2id$") {
		return false, errors.New("invalid hash format")
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 5 {
		return false, errors.New("invalid hash format")
	}
	// parts[0] = "argon2id"
	var version int
	if _, err := fmt.Sscanf(parts[1], "v=%d", &version); err != nil {
		return false, errors.New("invalid hash format")
	}
	var mem, iters, par int
	if _, err := fmt.Sscanf(parts[2], "m=%d,t=%d,p=%d", &mem, &iters, &par); err != nil {
		return false, errors.New("invalid hash format")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return false, err
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}
	// derive
	calc := argon2.IDKey([]byte(password), salt, uint32(iters), uint32(mem), uint8(par), uint32(len(key)))
	// constant-time compare
	if subtle.ConstantTimeCompare(calc, key) == 1 {
		return true, nil
	}
	return false, nil
}
