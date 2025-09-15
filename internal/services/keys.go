package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"ginkgoid/internal/config"
	"ginkgoid/internal/storage"
)

// KeyService 管理签名密钥（存于 MySQL）并对外提供 JWKS 公钥集合。
type KeyService struct {
	db  *gorm.DB
	cfg config.Config
}

func NewKeyService(db *gorm.DB, cfg config.Config) *KeyService {
	return &KeyService{db: db, cfg: cfg}
}

// EnsureActiveKey 确保至少存在一把处于激活状态的签名密钥；
// 如无，则按配置（默认 RS256）生成新密钥并入库。
func (s *KeyService) EnsureActiveKey(ctx context.Context) error {
	var count int64
	if err := s.db.WithContext(ctx).Model(&storage.JWKKey{}).Where("active = ?", true).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	// 按配置生成默认密钥；默认 RS256
	alg := strings.ToUpper(s.cfg.Crypto.IDTokenAlg)
	if alg == "ES256" {
		return s.generateAndStoreES256(ctx)
	}
	return s.generateAndStoreRS256(ctx)
}

func (s *KeyService) generateAndStoreRS256(ctx context.Context) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("rsa generate: %w", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(key)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	pubBytes := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})
	kid := fmt.Sprintf("rsa-%d", time.Now().Unix())
	rec := &storage.JWKKey{
		Kid:        kid,
		Alg:        "RS256",
		Kty:        "RSA",
		Use:        "sig",
		PublicKey:  string(pubPem),
		PrivateKey: string(privPem),
		Active:     true,
		CreatedAt:  time.Now(),
	}
	return s.db.WithContext(ctx).Create(rec).Error
}

func (s *KeyService) generateAndStoreES256(ctx context.Context) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("ecdsa generate: %w", err)
	}
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal ec: %w", err)
	}
	privPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal pkix: %w", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	kid := fmt.Sprintf("es256-%d", time.Now().Unix())
	rec := &storage.JWKKey{
		Kid:        kid,
		Alg:        "ES256",
		Kty:        "EC",
		Use:        "sig",
		PublicKey:  string(pubPem),
		PrivateKey: string(privPem),
		Active:     true,
		CreatedAt:  time.Now(),
	}
	return s.db.WithContext(ctx).Create(rec).Error
}

// ActiveKey 返回当前激活的密钥记录。
func (s *KeyService) ActiveKey(ctx context.Context) (*storage.JWKKey, error) {
	var rec storage.JWKKey
	if err := s.db.WithContext(ctx).Where("active = ?", true).Order("id desc").First(&rec).Error; err != nil {
		return nil, err
	}
	return &rec, nil
}

// FindByKid 根据 kid 返回密钥（若存在）。
func (s *KeyService) FindByKid(ctx context.Context, kid string) (*storage.JWKKey, error) {
	var rec storage.JWKKey
	if err := s.db.WithContext(ctx).Where("kid = ?", kid).First(&rec).Error; err != nil {
		return nil, err
	}
	return &rec, nil
}

// AllKeys 返回全部密钥（含历史），用于校验回退场景。
func (s *KeyService) AllKeys(ctx context.Context) ([]storage.JWKKey, error) {
	var list []storage.JWKKey
	if err := s.db.WithContext(ctx).Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

// Rotate 生成一把新激活密钥（RS256/ES256 由配置决定），并将旧密钥置为非激活。
func (s *KeyService) Rotate(ctx context.Context) error {
	// deactivate old
	if err := s.db.WithContext(ctx).Model(&storage.JWKKey{}).Where("active = ?", true).Update("active", false).Error; err != nil {
		return err
	}
	// create new
	alg := strings.ToUpper(s.cfg.Crypto.IDTokenAlg)
	if alg == "ES256" {
		return s.generateAndStoreES256(ctx)
	}
	return s.generateAndStoreRS256(ctx)
}

// JWKS 返回所有公钥（无论是否激活）的 JWK Set JSON。
func (s *KeyService) JWKS(ctx context.Context) ([]byte, error) {
	var keys []storage.JWKKey
	if err := s.db.WithContext(ctx).Find(&keys).Error; err != nil {
		return nil, err
	}
	type jwk struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use,omitempty"`
		Alg string `json:"alg,omitempty"`
		// RSA 公钥参数
		N string `json:"n,omitempty"`
		E string `json:"e,omitempty"`
		// EC 公钥参数
		Crv string `json:"crv,omitempty"`
		X   string `json:"x,omitempty"`
		Y   string `json:"y,omitempty"`
	}
	set := struct {
		Keys []jwk `json:"keys"`
	}{Keys: make([]jwk, 0, len(keys))}

	for _, k := range keys {
		if k.Kty == "RSA" {
			pub, err := parseRSAPublicPEM([]byte(k.PublicKey))
			if err != nil {
				continue
			}
			n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
			e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(pub.E))
			set.Keys = append(set.Keys, jwk{Kty: "RSA", Kid: k.Kid, Use: k.Use, Alg: k.Alg, N: n, E: e})
		} else if k.Kty == "EC" {
			pub, err := parseECPublicPEM([]byte(k.PublicKey))
			if err != nil {
				continue
			}
			x := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
			y := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
			set.Keys = append(set.Keys, jwk{Kty: "EC", Kid: k.Kid, Use: k.Use, Alg: k.Alg, Crv: pub.Params().Name, X: x, Y: y})
		}
	}
	return json.Marshal(set)
}

// 辅助函数：解析 PEM 格式公钥

func parseRSAPublicPEM(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if pk, ok := pub.(*rsa.PublicKey); ok {
			return pk, nil
		}
		return nil, errors.New("not rsa public key")
	default:
		return nil, fmt.Errorf("unexpected pem type: %s", block.Type)
	}
}

func parseECPublicPEM(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if pk, ok := pub.(*ecdsa.PublicKey); ok {
			return pk, nil
		}
		return nil, errors.New("not ec public key")
	default:
		return nil, fmt.Errorf("unexpected pem type: %s", block.Type)
	}
}

// bigIntToBytes 将较小的整型（如 RSA 公钥指数 e）编码为大端字节序（去除前导 0）。
func bigIntToBytes(e int) []byte {
	// 常见 e=65537，即 0x01 00 01
	if e == 0 {
		return []byte{0}
	}
	var buf [8]byte
	i := len(buf)
	for e > 0 {
		i--
		buf[i] = byte(e)
		e >>= 8
	}
	return buf[i:]
}
