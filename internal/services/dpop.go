package services

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
)

// CalcJKT 计算 JWK 的 SHA-256 拇指指纹（base64url 无填充）。
func CalcJKT(jwk map[string]any) (string, error) {
	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ExtractDPoPJWK 从 DPoP-Proof 解析公钥 JWK（最简校验）。
func ExtractDPoPJWK(proof string) (map[string]any, error) {
	if proof == "" {
		return nil, errors.New("missing_dpop")
	}
	token, _, err := new(jwt.Parser).ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	m, _ := token.Header["jwk"].(map[string]any)
	if m == nil {
		return nil, errors.New("invalid_dpop_header")
	}
	return m, nil
}

// VerifyDPoPProof 做最小化校验：签名算法、htu/htm 匹配、jwk 可解析。
// 注意：生产应校验 iat、jti 重放、签名有效性等，这里作为占位实现。
func VerifyDPoPProof(proof, htm, htu string) error {
	if proof == "" {
		return errors.New("missing_dpop")
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(proof, claims, func(t *jwt.Token) (interface{}, error) {
		jwkHdr, _ := t.Header["jwk"].(map[string]any)
		if jwkHdr == nil {
			return nil, errors.New("invalid_dpop_header")
		}
		// 仅尝试解析 EC/RSA 公钥（极简实现，仅支持 x5c 或忽略返回 nil 让验证失败）
		if x5c, ok := jwkHdr["x5c"].([]any); ok && len(x5c) > 0 {
			if first, ok2 := x5c[0].(string); ok2 {
				der, derr := base64.StdEncoding.DecodeString(first)
				if derr == nil {
					if cert, cerr := x509.ParseCertificate(der); cerr == nil {
						return cert.PublicKey, nil
					}
				}
			}
		}
		return nil, errors.New("unsupported_jwk")
	}, jwt.WithValidMethods([]string{"ES256", "RS256", "PS256"}))
	if err != nil {
		return err
	}
	if !token.Valid {
		return errors.New("invalid_dpop")
	}
	// htm/htu 软校验
	if v, _ := claims["htm"].(string); v != "" && !strings.EqualFold(v, htm) {
		return errors.New("dpop_htm_mismatch")
	}
	if v, _ := claims["htu"].(string); v != "" && v != htu {
		return errors.New("dpop_htu_mismatch")
	}
	return nil
}
