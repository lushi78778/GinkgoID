package services

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

type memoryReplayStore struct {
	seen map[string]struct{}
}

func (m *memoryReplayStore) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
	if m.seen == nil {
		m.seen = make(map[string]struct{})
	}
	if _, exists := m.seen[key]; exists {
		return redis.NewBoolResult(false, nil)
	}
	m.seen[key] = struct{}{}
	return redis.NewBoolResult(true, nil)
}

func TestDPoPVerifierVerifySuccess(t *testing.T) {
	store := &memoryReplayStore{}
	verifier := NewDPoPVerifier(store, 5*time.Minute, time.Minute)
	fixed := time.Unix(1_700_000_000, 0)
	verifier.SetClock(func() time.Time { return fixed })
	proof, jwk := mustBuildDPoPProof(t, "POST", "https://op.example.com/token", fixed, "jti-1")
	res, err := verifier.Verify(context.Background(), proof, "POST", "https://op.example.com/token")
	require.NoError(t, err)
	require.NotNil(t, res)
	expectedJKT, err := CalcJKT(jwk)
	require.NoError(t, err)
	require.Equal(t, expectedJKT, res.JKT)
}

func TestDPoPVerifierDetectsReplay(t *testing.T) {
	store := &memoryReplayStore{}
	verifier := NewDPoPVerifier(store, time.Minute, time.Minute)
	fixed := time.Unix(1_700_000_000, 0)
	verifier.SetClock(func() time.Time { return fixed })
	proof, _ := mustBuildDPoPProof(t, "GET", "https://op.example.com/userinfo", fixed, "replay-jti")
	_, err := verifier.Verify(context.Background(), proof, "GET", "https://op.example.com/userinfo")
	require.NoError(t, err)
	_, err = verifier.Verify(context.Background(), proof, "GET", "https://op.example.com/userinfo")
	require.ErrorIs(t, err, ErrDPoPReplay)
}

func TestDPoPVerifierRejectsOldProof(t *testing.T) {
	store := &memoryReplayStore{}
	verifier := NewDPoPVerifier(store, time.Minute, time.Minute)
	fixed := time.Unix(1_700_000_000, 0)
	verifier.SetClock(func() time.Time { return fixed })
	old := fixed.Add(-3 * time.Minute)
	proof, _ := mustBuildDPoPProof(t, "POST", "https://op.example.com/token", old, "old-jti")
	_, err := verifier.Verify(context.Background(), proof, "POST", "https://op.example.com/token")
	require.Error(t, err)
	require.ErrorContains(t, err, "dpop_iat_too_old")
}

func mustBuildDPoPProof(t *testing.T, method, htu string, iat time.Time, jti string) (string, map[string]any) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwk := jwkFromPublicKey(key.Public().(*ecdsa.PublicKey))
	claims := jwt.MapClaims{
		"htm": method,
		"htu": htu,
		"iat": float64(iat.Unix()),
		"jti": jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed, jwk
}

func jwkFromPublicKey(pub *ecdsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padCoordinate(pub.X, 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padCoordinate(pub.Y, 32)),
	}
}

func padCoordinate(coord *big.Int, size int) []byte {
	b := coord.Bytes()
	if len(b) >= size {
		return b
	}
	res := make([]byte, size)
	copy(res[size-len(b):], b)
	return res
}
