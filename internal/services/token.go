package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"ginkgoid/internal/config"
	"ginkgoid/internal/storage"
)

// TokenService 负责签发与校验 JWT 访问令牌与 ID Token。
type TokenService struct {
	cfg  config.Config
	keys *KeyService
}

func NewTokenService(cfg config.Config, ks *KeyService) *TokenService {
	return &TokenService{cfg: cfg, keys: ks}
}

// BuildAccessTokenJWT 签发带标准声明的 JWT 访问令牌。
// 参数 subject 已由调用方按 public/pairwise 模式计算。
func (s *TokenService) BuildAccessTokenJWT(clientID string, userID uint64, subject, scope, sid string) (string, time.Time, string, error) {
	now := time.Now()
	exp := now.Add(s.cfg.Token.AccessTokenTTL)
	rec, err := s.keys.ActiveKey(context.Background())
	if err != nil {
		return "", time.Time{}, "", err
	}

	jti := uuid.NewString()
	claims := jwt.MapClaims{
		"iss":       s.cfg.Issuer,
		"sub":       subject,
		"aud":       clientID,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"scope":     scope,
		"sid":       sid,
		"client_id": clientID,
		"uid":       userID,
		"jti":       jti,
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod(rec.Alg), claims)
	token.Header["kid"] = rec.Kid
	signed, err := token.SignedString(signingKeyFromRecord(rec))
	if err != nil {
		return "", time.Time{}, "", err
	}
	return signed, exp, jti, nil
}

// BuildIDToken 签发 ID Token（支持 nonce、acr、at_hash 等可选声明）。
func (s *TokenService) BuildIDToken(clientID, subject, nonce, acr, atHash string, authTime time.Time, extra map[string]interface{}) (string, error) {
	now := time.Now()
	exp := now.Add(s.cfg.Token.AccessTokenTTL) // 与 AT 对齐（也可按需设置更短）
	rec, err := s.keys.ActiveKey(context.Background())
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"iss":       s.cfg.Issuer,
		"sub":       subject,
		"aud":       clientID,
		"iat":       now.Unix(),
		"exp":       exp.Unix(),
		"auth_time": authTime.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if acr != "" {
		claims["acr"] = acr
	}
	if atHash != "" {
		claims["at_hash"] = atHash
	}
	for k, v := range extra {
		// 不覆盖保留字段
		if _, exists := claims[k]; !exists {
			claims[k] = v
		}
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod(rec.Alg), claims)
	token.Header["kid"] = rec.Kid
	signed, err := token.SignedString(signingKeyFromRecord(rec))
	if err != nil {
		return "", err
	}
	return signed, nil
}

// BuildLogoutToken 生成后端通道注销（Back-Channel Logout）所需的 Logout Token（JWT）。
// 包含 iss、（可选）sub、aud（client_id）、iat、events、sid 等声明。
func (s *TokenService) BuildLogoutToken(clientID, subject, sid string) (string, error) {
	now := time.Now()
	rec, err := s.keys.ActiveKey(context.Background())
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{
		"iss": s.cfg.Issuer,
		"aud": clientID,
		"iat": now.Unix(),
		"jti": uuid.NewString(),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
		"sid": sid,
	}
	if subject != "" {
		claims["sub"] = subject
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod(rec.Alg), claims)
	token.Header["kid"] = rec.Kid
	return token.SignedString(signingKeyFromRecord(rec))
}

// signingKeyFromRecord 从数据库记录解析私钥，供 JWT 库签名使用。
func signingKeyFromRecord(rec *storage.JWKKey) interface{} {
	block, _ := pem.Decode([]byte(rec.PrivateKey))
	if block == nil {
		return nil
	}
	switch rec.Kty {
	case "RSA":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			return key
		}
		// Try PKCS8 if needed
		if k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes); err2 == nil {
			if rsaKey, ok := k.(*rsa.PrivateKey); ok {
				return rsaKey
			}
		}
		return nil
	case "EC":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err == nil {
			return key
		}
		if k, err2 := x509.ParsePKCS8PrivateKey(block.Bytes); err2 == nil {
			if ecKey, ok := k.(*ecdsa.PrivateKey); ok {
				return ecKey
			}
		}
		return nil
	default:
		return nil
	}
}

// ParseAndValidateJWT 的完整外部校验（含历史公钥）不在此处实现；
// OP 自签发令牌内部信任，外部验证请使用 JWKS。
var ErrUnsupported = errors.New("unsupported")
