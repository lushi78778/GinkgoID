package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	jwt "github.com/golang-jwt/jwt/v5"
)

const (
	defaultDPoPReplayWindow = 5 * time.Minute
	defaultDPoPSkew         = time.Minute
)

// ErrDPoPReplay 表示 DPoP Proof 被重复使用。
var ErrDPoPReplay = errors.New("dpop_replay_detected")

// dpopReplayStore 抽象 redis SetNX 能力，便于测试替换。
type dpopReplayStore interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
}

// DPoPVerifier 负责校验 DPoP Proof 并进行 jti 去重。
type DPoPVerifier struct {
	store        dpopReplayStore
	replayWindow time.Duration
	skew         time.Duration
	now          func() time.Time
}

// NewDPoPVerifier 构造 verifier，传入 redis 客户端（或兼容接口）、重放窗口与允许的时间偏移。
func NewDPoPVerifier(store dpopReplayStore, window, skew time.Duration) *DPoPVerifier {
	if window <= 0 {
		window = defaultDPoPReplayWindow
	}
	if skew <= 0 {
		skew = defaultDPoPSkew
	}
	return &DPoPVerifier{
		store:        store,
		replayWindow: window,
		skew:         skew,
		now:          time.Now,
	}
}

// SetClock 仅用于测试，替换内部时间函数。
func (v *DPoPVerifier) SetClock(clock func() time.Time) {
	if clock != nil {
		v.now = clock
	}
}

// SetSkew 调整允许的最大时间偏移（测试或高级配置）。
func (v *DPoPVerifier) SetSkew(skew time.Duration) {
	if skew > 0 {
		v.skew = skew
	}
}

// DPoPResult 返回校验后的关键信息。
type DPoPResult struct {
	Claims jwt.MapClaims
	JKT    string
}

// Verify 校验 proof 的签名、htm/htu/iat/jti 并缓存 jti 防止重放。
func (v *DPoPVerifier) Verify(ctx context.Context, proof, htm, htu string) (*DPoPResult, error) {
	if proof == "" {
		return nil, errors.New("missing_dpop")
	}
	claims := jwt.MapClaims{}
	var jwkHdr map[string]any
	token, err := jwt.ParseWithClaims(proof, claims, func(t *jwt.Token) (interface{}, error) {
		jwkHdr, _ = t.Header["jwk"].(map[string]any)
		if jwkHdr == nil {
			return nil, errors.New("invalid_dpop_header")
		}
		if pubKey, perr := publicKeyFromJWK(jwkHdr); perr == nil {
			return pubKey, nil
		}
		// 尝试解析内嵌证书，若失败则交由 JWT 库判定签名错误
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
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("invalid_dpop")
	}
	// htm/htu 必须与当前请求匹配
	if v, _ := claims["htm"].(string); v != "" && !strings.EqualFold(v, htm) {
		return nil, errors.New("dpop_htm_mismatch")
	}
	if v, _ := claims["htu"].(string); v != "" && v != htu {
		return nil, errors.New("dpop_htu_mismatch")
	}
	// iat 检查：不能过期或过于超前
	now := v.now()
	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		return nil, errors.New("dpop_iat_missing")
	}
	iat := time.Unix(int64(iatFloat), 0)
	if iat.After(now.Add(v.skew)) {
		return nil, errors.New("dpop_iat_in_future")
	}
	if now.Sub(iat) > v.replayWindow+v.skew {
		return nil, errors.New("dpop_iat_too_old")
	}
	// jti 去重
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return nil, errors.New("dpop_jti_missing")
	}
	if v.store != nil {
		key := fmt.Sprintf("dpop:jti:%s", jti)
		set, serr := v.store.SetNX(ctx, key, 1, v.replayWindow).Result()
		if serr != nil {
			return nil, serr
		}
		if !set {
			return nil, ErrDPoPReplay
		}
	}
	jkt, err := CalcJKT(jwkHdr)
	if err != nil {
		return nil, err
	}
	return &DPoPResult{Claims: claims, JKT: jkt}, nil
}

func publicKeyFromJWK(jwk map[string]any) (interface{}, error) {
	kty, _ := jwk["kty"].(string)
	switch kty {
	case "EC":
		crv, _ := jwk["crv"].(string)
		if !strings.EqualFold(crv, "P-256") {
			return nil, errors.New("unsupported_ec_curve")
		}
		xStr, _ := jwk["x"].(string)
		yStr, _ := jwk["y"].(string)
		if xStr == "" || yStr == "" {
			return nil, errors.New("invalid_ec_jwk")
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
		if err != nil {
			return nil, err
		}
		curve := elliptic.P256()
		x := new(big.Int).SetBytes(xBytes)
		y := new(big.Int).SetBytes(yBytes)
		if !curve.IsOnCurve(x, y) {
			return nil, errors.New("point_not_on_curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "RSA":
		nStr, _ := jwk["n"].(string)
		eStr, _ := jwk["e"].(string)
		if nStr == "" || eStr == "" {
			return nil, errors.New("invalid_rsa_jwk")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nBytes)
		var e int
		for _, b := range eBytes {
			e = e<<8 + int(b)
		}
		if e == 0 {
			return nil, errors.New("invalid_rsa_exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	default:
		return nil, errors.New("unsupported_jwk")
	}
}

// CalcJKT 计算 JWK 的 SHA-256 拇指指纹（base64url 无填充）。
func CalcJKT(jwk map[string]any) (string, error) {
	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ExtractDPoPJWK 从 DPoP-Proof 解析公钥 JWK（保留给调用方需要直接访问头部时使用）。
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
