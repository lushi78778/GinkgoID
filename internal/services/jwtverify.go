package services

import (
    "crypto/ecdsa"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "errors"

    jwt "github.com/golang-jwt/jwt/v5"

    "ginkgoid/internal/storage"
)

// VerifyJWT 验证 JWT：优先使用 Header 中的 kid 或当前激活密钥；
// 若失败，则回退遍历所有历史密钥直至成功或判定无效。
func (s *TokenService) VerifyJWT(tokenStr string) (jwt.MapClaims, error) {
    claims := jwt.MapClaims{}
    // 尝试优先使用 kid 对应的公钥，若无则使用当前激活密钥的公钥
    _, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
        if kid, ok := t.Header["kid"].(string); ok && kid != "" {
            if rec, err := s.keys.FindByKid(nil, kid); err == nil { return publicKeyFromRecord(rec), nil }
        }
        if rec, err := s.keys.ActiveKey(nil); err == nil { return publicKeyFromRecord(rec), nil }
        return nil, errors.New("no key")
    })
    if err == nil { return claims, nil }
    // 回退：依次尝试所有密钥（公钥）
    list, lerr := s.keys.AllKeys(nil)
    if lerr != nil { return nil, err }
    for _, k := range list {
        c := jwt.MapClaims{}
        if _, e := jwt.ParseWithClaims(tokenStr, c, func(t *jwt.Token) (interface{}, error) { return publicKeyFromRecord(&k), nil }); e == nil {
            return c, nil
        }
    }
    return nil, errors.New("invalid_token")
}

// publicKeyFromRecord 从数据库记录解析公钥（PEM）。
func publicKeyFromRecord(rec *storage.JWKKey) interface{} {
    if rec == nil || rec.PublicKey == "" { return nil }
    block, _ := pem.Decode([]byte(rec.PublicKey))
    if block == nil { return nil }
    switch rec.Kty {
    case "RSA":
        switch block.Type {
        case "RSA PUBLIC KEY":
            if pk, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil { return pk }
        case "PUBLIC KEY":
            if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
                if pk, ok := pub.(*rsa.PublicKey); ok { return pk }
            }
        }
        return nil
    case "EC":
        if block.Type == "PUBLIC KEY" {
            if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
                if pk, ok := pub.(*ecdsa.PublicKey); ok { return pk }
            }
        }
        return nil
    default:
        return nil
    }
}
