package entity

import (
	"time"
)

// @title       User
// @description 用户实体，记录用户的基础信息与状态。
type User struct {
	ID            uint64    `gorm:"primaryKey;autoIncrement"`     // 用户 ID
	Username      string    `gorm:"uniqueIndex;size:64;not null"` // 用户名（唯一）
	Email         *string   // 邮箱（可空）
	EmailVerified bool      `gorm:"default:false"`        // 邮箱是否已验证
	PasswordHash  string    `gorm:"size:255;not null"`    // 口令哈希（argon2id）
	Status        int8      `gorm:"default:1"`            // 状态：1 启用，0 停用
	Role          string    `gorm:"size:32;default:user"` // 角色：admin/operator/auditor/user
	CreatedAt     time.Time // 创建时间
}

// @title       Client
// @description 客户端实体，存放重定向白名单、scope 等信息。
type Client struct {
	ClientID       string  `gorm:"primaryKey;size:64"` // 客户端 ID
	Name           string  `gorm:"size:128"`           // 名称
	SecretHash     *string // 机密客户端口令哈希（nil 表示公共客户端）
	RedirectURIs   string  `gorm:"type:json"` // 重定向 URI 白名单（JSON 数组）
	PostLogoutURIs string  `gorm:"type:json"` // 登出回跳白名单（JSON 数组）
	Scopes         string  `gorm:"type:json"` // 允许的 scope（JSON 数组）
	Status         int8    `gorm:"default:1"` // 状态：1 启用，0 停用
}

// @title       Consent
// @description 用户对客户端的授权记录（记住授权）。
type Consent struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement"` // 记录 ID
	UserID    uint64    `gorm:"index;not null"`           // 用户 ID
	ClientID  string    `gorm:"index;size:64;not null"`   // 客户端 ID
	Scopes    string    `gorm:"type:json"`                // 授权的 scope 列表（JSON 数组）
	Version   int       // 版本（提升时强制重新同意）
	Remember  bool      // 是否记住
	UpdatedAt time.Time // 更新时间
}

// @title       AuthCode
// @description 授权码存储（仅保存 SHA-256 哈希）。
type AuthCode struct {
	CodeHash      string    `gorm:"primaryKey;size:64"`     // 授权码哈希
	ClientID      string    `gorm:"index;size:64;not null"` // 客户端 ID
	UserID        uint64    `gorm:"index;not null"`         // 用户 ID
	RedirectURI   string    `gorm:"size:512"`               // 回调 URI
	Scope         string    `gorm:"type:json"`              // scope 列表（JSON）
	Nonce         string    `gorm:"size:128"`               // nonce
	CodeChallenge string    `gorm:"size:128"`               // PKCE code_challenge
	Method        string    `gorm:"size:16"`                // PKCE 方法（S256）
	AuthTime      int64     // 认证时间（秒）
	ExpireAt      time.Time `gorm:"index"` // 过期时间
	Used          bool      // 是否已使用
}

// @title       JWKKey
// @description 签名密钥（公钥明文 PEM，私钥密文存储）。
type JWKKey struct {
	KID       string     `gorm:"primaryKey;size:64"` // 密钥 ID
	Alg       string     `gorm:"size:16"`            // 算法（RS256/ES256）
	UseKey    string     `gorm:"size:8"`             // 用途（sig）
	PubPEM    string     `gorm:"type:text"`          // 公钥 PEM
	EncPriv   string     `gorm:"type:text"`          // 加密后的私钥
	NotBefore *time.Time // 生效时间
	NotAfter  *time.Time // 失效时间（灰度窗口）
	Status    string     `gorm:"size:16"` // 状态：active/grace/retired
}

// @title       Session
// @description 会话实体，记录登录信息与有效期。
type Session struct {
	SID       string    `gorm:"primaryKey;size:64"` // 会话 ID
	UserID    uint64    `gorm:"index"`              // 用户 ID
	UA        string    `gorm:"size:255"`           // User-Agent
	IP        string    `gorm:"size:64"`            // 客户端 IP
	CreatedAt time.Time // 创建时间
	ExpireAt  time.Time `gorm:"index"` // 过期时间
	Revoked   bool      // 是否已撤销
}
