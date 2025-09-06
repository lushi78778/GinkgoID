package oidc

import (
	"context"
	"crypto/x509"
	"encoding/pem"

	"github.com/lestrrat-go/jwx/v2/jwk"
	jjwt "github.com/lestrrat-go/jwx/v2/jwt"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	"ginkgoid/internal/service/revocation"
)

// VerifyAccessToken 校验 Access Token（JWT）签名与撤销状态，
// 基于数据库中“激活/灰度”的公钥集合进行验证。
func VerifyAccessToken(ctx context.Context, token string) (jjwt.Token, error) {
	return VerifyJWT(ctx, token)
}

// VerifyJWT 校验任意 JWT（ID/Access）。
// 若启用 security.allow_insecure_local_jwt，将在验签失败时回退为不验签解析（仅用于本地排障）。
func VerifyJWT(ctx context.Context, token string) (jjwt.Token, error) {
	ks := jwk.NewSet()
	var keys []entity.JWKKey
	if err := db.G().WithContext(ctx).Where("status in ?", []string{"active", "grace"}).Find(&keys).Error; err != nil {
		return nil, err
	}
	for _, k := range keys {
		block, _ := pem.Decode([]byte(k.PubPEM))
		if block == nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			continue
		}
		jk, err := jwk.FromRaw(pub)
		if err != nil {
			continue
		}
		_ = jk.Set(jwk.KeyIDKey, k.KID)
		_ = jk.Set(jwk.AlgorithmKey, k.Alg)
		_ = jk.Set(jwk.KeyUsageKey, k.UseKey)
		ks.AddKey(jk)
	}
	// Let jwx select the right key by kid+alg and verify.
	t, err := jjwt.Parse([]byte(token), jjwt.WithKeySet(ks))
	if err != nil {
		// Allow explicit insecure local parsing only when enabled via config
		if config.C().Security.AllowInsecureLocalJWT {
			return jjwt.Parse([]byte(token), jjwt.WithVerify(false))
		}
		return nil, err
	}
	// Revocation check for access tokens by jti
	if jv, ok := t.Get("jti"); ok {
		if jti, _ := jv.(string); jti != "" {
			if revoked, _ := revocation.IsRevoked(ctx, jti); revoked {
				return nil, jjwt.ErrInvalidJWT()
			}
		}
	}
	return t, nil
}
