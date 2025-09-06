package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	jjwt "github.com/lestrrat-go/jwx/v2/jwt"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	cryptoutil "ginkgoid/internal/utility/crypto"
	"ginkgoid/internal/utility/randx"
)

type TokenPair struct {
	IDToken     string
	AccessToken string
	ExpiresIn   int64
}

// SignTokens 为指定用户/客户端签发 ID Token 与 Access Token（JWT）。
// - 使用当前激活的 JWK（按 alg）进行签名，并设置 kid；
// - ID Token 包含 iss/sub/aud/iat/exp/auth_time/nonce；
// - Access Token 包含 sub/client_id/scope/jti/iat/exp。
func SignTokens(ctx context.Context, userID uint64, clientID string, scope []string, nonce string, authTime int64) (*TokenPair, error) {
	alg := "RS256" // default choose RS256
	// load active key for alg
	var key entity.JWKKey
	if err := db.G().WithContext(ctx).Where("alg = ? AND status = ?", alg, "active").First(&key).Error; err != nil {
		return nil, err
	}
	// decrypt priv
	privDER, err := cryptoutil.Decrypt(config.C().Security.JWKEncPassphrase, key.EncPriv)
	if err != nil {
		return nil, err
	}
	privAny, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return nil, err
	}

	issuer := ensureIssuer()
	idTTL, _ := time.ParseDuration(config.C().OIDC.IDTokenTTL)
	atTTL, _ := time.ParseDuration(config.C().OIDC.AccessTokenTTL)
	now := time.Now()

	// ID Token
	idt := jjwt.New()
	_ = idt.Set(jjwt.IssuerKey, issuer)
	_ = idt.Set(jjwt.SubjectKey, formatSub(userID))
	_ = idt.Set(jjwt.AudienceKey, []string{clientID})
	_ = idt.Set(jjwt.IssuedAtKey, now)
	_ = idt.Set(jjwt.ExpirationKey, now.Add(idTTL))
	_ = idt.Set("auth_time", authTime)
	if nonce != "" {
		_ = idt.Set("nonce", nonce)
	}

	idSigned, err := signJWT(idt, alg, key.KID, privAny)
	if err != nil {
		return nil, err
	}

	// Access Token (JWT)
	att := jjwt.New()
	_ = att.Set(jjwt.IssuerKey, issuer)
	_ = att.Set(jjwt.SubjectKey, formatSub(userID))
	_ = att.Set("client_id", clientID)
	_ = att.Set("scope", scopeString(scope))
	_ = att.Set("jti", randomJTI())
	_ = att.Set(jjwt.IssuedAtKey, now)
	_ = att.Set(jjwt.ExpirationKey, now.Add(atTTL))
	atSigned, err := signJWT(att, alg, key.KID, privAny)
	if err != nil {
		return nil, err
	}

	return &TokenPair{IDToken: idSigned, AccessToken: atSigned, ExpiresIn: int64(atTTL.Seconds())}, nil
}

func signJWT(t jjwt.Token, alg, kid string, priv interface{}) (string, error) {
	hdr := jws.NewHeaders()
	_ = hdr.Set(jws.KeyIDKey, kid)
	switch alg {
	case "RS256":
		rk, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return "", errors.New("invalid rsa key")
		}
		b, err := jjwt.Sign(t, jjwt.WithKey(jwa.RS256, rk, jws.WithProtectedHeaders(hdr)))
		if err != nil {
			return "", err
		}
		return string(b), nil
	case "ES256":
		ek, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return "", errors.New("invalid ec key")
		}
		b, err := jjwt.Sign(t, jjwt.WithKey(jwa.ES256, ek, jws.WithProtectedHeaders(hdr)))
		if err != nil {
			return "", err
		}
		return string(b), nil
	default:
		return "", errors.New("unsupported alg")
	}
}

// ensureIssuer 返回配置的 issuer（必须为完整 URL）。
func ensureIssuer() string { return config.C().OIDC.Issuer }

func formatSub(uid uint64) string { return "u_" + fmtUint(uid) }

func scopeString(scopes []string) string {
	s := ""
	for i, x := range scopes {
		if i > 0 {
			s += " "
		}
		s += x
	}
	return s
}

func randomJTI() string { s, _ := randx.ID(12); return s }

func fmtUint(u uint64) string {
	if u == 0 {
		return "0"
	}
	b := make([]byte, 0, 20)
	for u > 0 {
		d := u % 10
		b = append([]byte{byte('0' + d)}, b...)
		u /= 10
	}
	return string(b)
}
