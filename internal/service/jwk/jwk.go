package jwk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"time"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	cryptoutil "ginkgoid/internal/utility/crypto"
	"ginkgoid/internal/utility/randx"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	StatusActive  = "active"
	StatusGrace   = "grace"
	StatusRetired = "retired"
)

// EnsureActive 确保每种算法（RS256/ES256）至少存在一把激活状态的密钥。
// 如不存在则自动生成并入库（私钥以口令加密后保存）。
func EnsureActive(ctx context.Context) error {
	for _, alg := range []string{"RS256", "ES256"} {
		var count int64
		if err := db.G().WithContext(ctx).Model(&entity.JWKKey{}).Where("alg = ? AND status = ?", alg, StatusActive).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			if _, err := generateAndStore(ctx, alg, StatusActive, nil, nil); err != nil {
				return err
			}
		}
	}
	return nil
}

// Rotate 轮换指定算法的签名密钥：
// - 将当前激活密钥切换为灰度（设置 not_after）；
// - 生成新的激活密钥；
// - 灰度窗口由 graceDays（天）控制。
func Rotate(ctx context.Context, alg string, graceDays int) error {
	return db.G().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var cur entity.JWKKey
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("alg = ? AND status = ?", alg, StatusActive).First(&cur).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// No active, just generate one
				_, err := generateAndStoreTx(tx, alg, StatusActive, nil, nil)
				return err
			}
			return err
		}
		// Move current to grace with window
		end := time.Now().Add(time.Duration(graceDays) * 24 * time.Hour)
		cur.Status = StatusGrace
		cur.NotAfter = &end
		if err := tx.Save(&cur).Error; err != nil {
			return err
		}
		// New active
		_, err := generateAndStoreTx(tx, alg, StatusActive, nil, nil)
		return err
	})
}

func generateAndStore(ctx context.Context, alg, status string, notBefore, notAfter *time.Time) (*entity.JWKKey, error) {
	var out *entity.JWKKey
	err := db.G().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var err error
		out, err = generateAndStoreTx(tx, alg, status, notBefore, notAfter)
		return err
	})
	return out, err
}

func generateAndStoreTx(tx *gorm.DB, alg, status string, notBefore, notAfter *time.Time) (*entity.JWKKey, error) {
	pass := config.C().Security.JWKEncPassphrase
	kid, _ := randx.ID(16)

	var pubPEM, encPriv string
	var err error
	switch alg {
	case "RS256":
		var key *rsa.PrivateKey
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		// Private PKCS8
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		encPriv, err = cryptoutil.Encrypt(pass, pkcs8)
		if err != nil {
			return nil, err
		}
		// Public PEM
		pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))
	case "ES256":
		var key *ecdsa.PrivateKey
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		encPriv, err = cryptoutil.Encrypt(pass, pkcs8)
		if err != nil {
			return nil, err
		}
		pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, err
		}
		pubPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer}))
	default:
		return nil, errors.New("unsupported alg")
	}

	now := time.Now()
	if notBefore == nil {
		notBefore = &now
	}
	k := &entity.JWKKey{
		KID:       kid,
		Alg:       alg,
		UseKey:    "sig",
		PubPEM:    pubPEM,
		EncPriv:   encPriv,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Status:    status,
	}
	if err := tx.Create(k).Error; err != nil {
		return nil, err
	}
	return k, nil
}

// JWKS 导出当前“激活/灰度”状态的公钥列表（用于客户端验签）。
func JWKS(ctx context.Context) ([]map[string]any, error) {
	var keys []entity.JWKKey
	now := time.Now()
	if err := db.G().WithContext(ctx).
		Where("status in ?", []string{StatusActive, StatusGrace}).
		Where("not_before IS NULL OR not_before <= ?", now).
		Where("not_after IS NULL OR not_after >= ?", now).
		Find(&keys).Error; err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		jwkmap, err := publicJWKFromPEM(k)
		if err != nil {
			continue
		}
		out = append(out, jwkmap)
	}
	return out, nil
}

func publicJWKFromPEM(k entity.JWKKey) (map[string]any, error) {
	block, _ := pem.Decode([]byte(k.PubPEM))
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		n := base64.RawURLEncoding.EncodeToString(pk.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(bigIntToBytes(pk.E))
		return map[string]any{
			"kty": "RSA",
			"kid": k.KID,
			"alg": k.Alg,
			"use": k.UseKey,
			"n":   n,
			"e":   e,
		}, nil
	case *ecdsa.PublicKey:
		x := base64.RawURLEncoding.EncodeToString(pk.X.Bytes())
		y := base64.RawURLEncoding.EncodeToString(pk.Y.Bytes())
		return map[string]any{
			"kty": "EC",
			"kid": k.KID,
			"alg": k.Alg,
			"use": k.UseKey,
			"crv": "P-256",
			"x":   x,
			"y":   y,
		}, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}

func bigIntToBytes(e int) []byte {
	// minimal bytes for exponent (usually 65537 -> 0x010001)
	if e == 0 {
		return []byte{0}
	}
	buf := make([]byte, 0)
	for e > 0 {
		buf = append([]byte{byte(e & 0xff)}, buf...)
		e >>= 8
	}
	return buf
}
