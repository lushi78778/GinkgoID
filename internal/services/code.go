package services

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/go-redis/redis/v8"

    "ginkgoid/internal/config"
    "ginkgoid/internal/utils"
)

// AuthCode 表示存储在 Redis 的授权码上下文。
// 键格式：code:<code>
type AuthCode struct {
    Code        string    `json:"code"`
    ClientID    string    `json:"client_id"`
    UserID      uint64    `json:"user_id"`
    RedirectURI string    `json:"redirect_uri"`
    Scope       string    `json:"scope"`
    Nonce       string    `json:"nonce"`
    SID         string    `json:"sid"`
    CodeChallenge       string `json:"code_challenge"`
    CodeChallengeMethod string `json:"code_challenge_method"` // 取值：S256、plain 或空
    CreatedAt   time.Time `json:"created_at"`
    Used        bool      `json:"used"`
}

type CodeService struct {
    rdb *redis.Client
    cfg config.Config
}

func NewCodeService(rdb *redis.Client, cfg config.Config) *CodeService {
    return &CodeService{rdb: rdb, cfg: cfg}
}

func (s *CodeService) New(ctx context.Context, clientID string, userID uint64, redirectURI, scope, nonce, sid, challenge, method string) (*AuthCode, error) {
    n := s.cfg.Token.CodeLength
    if n <= 0 { n = 32 }
    code, err := utils.RandURLSafeString(n)
    if err != nil { return nil, err }
    ac := &AuthCode{
        Code: code, ClientID: clientID, UserID: userID, RedirectURI: redirectURI, Scope: scope,
        Nonce: nonce, SID: sid, CodeChallenge: challenge, CodeChallengeMethod: method, CreatedAt: time.Now(),
    }
    b, _ := json.Marshal(ac)
    key := fmt.Sprintf("code:%s", code)
    if err := s.rdb.Set(ctx, key, b, s.cfg.Token.CodeTTL).Err(); err != nil {
        return nil, err
    }
    return ac, nil
}

func (s *CodeService) GetAndUse(ctx context.Context, code string) (*AuthCode, error) {
    key := fmt.Sprintf("code:%s", code)
    cmd := s.rdb.Get(ctx, key)
    if err := cmd.Err(); err != nil { return nil, err }
    var ac AuthCode
    if err := json.Unmarshal([]byte(cmd.Val()), &ac); err != nil { return nil, err }
    // 通过删除键来实现一次性使用语义
    _ = s.rdb.Del(ctx, key).Err()
    return &ac, nil
}
