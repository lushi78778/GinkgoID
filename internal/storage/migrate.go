package storage

import (
	"time"

	"gorm.io/gorm"
)

// 本文件定义平台使用的所有 GORM 模型，集中管理数据结构。

type User struct {
	ID            uint64 `gorm:"primaryKey;autoIncrement"`
	Username      string `gorm:"size:190;uniqueIndex"`
	Password      string `gorm:"size:255"` // 已哈希的口令
	Email         string `gorm:"size:190;index"`
	EmailVerified bool   `gorm:"index"`
	Name          string `gorm:"size:190"`
	IsAdmin       bool   `gorm:"index"`
	IsDev         bool   `gorm:"index"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Client struct {
	ID                               uint64    `gorm:"primaryKey;autoIncrement"`
	ClientID                         string    `gorm:"size:190;uniqueIndex"`
	SecretHash                       string    `gorm:"size:255"` // hashed secret if any
	Name                             string    `gorm:"size:190"`
	OwnerUserID                      uint64    `gorm:"index"`     // 拥有者用户ID（通过控制台注册时记录）
	RedirectURIs                     string    `gorm:"type:text"` // JSON 数组字符串
	GrantTypes                       string    `gorm:"size:255"`  // 以逗号分隔
	ResponseTypes                    string    `gorm:"size:255"`
	Scope                            string    `gorm:"size:255"`
	TokenEndpointAuthMethod          string    `gorm:"size:64"` // 取值：client_secret_basic 或 none
	SubjectType                      string    `gorm:"size:32"` // 取值：public 或 pairwise
	SectorIdentifierURI              string    `gorm:"size:255"`
	FrontchannelLogoutURI            string    `gorm:"size:255"`
	BackchannelLogoutURI             string    `gorm:"size:255"`
	PostLogoutRedirectURIs           string    `gorm:"type:text"` // JSON 数组字符串
	RegistrationAccessTokenHash      string    `gorm:"size:255"`
	RegistrationAccessTokenExpiresAt time.Time `gorm:"index"`
	Approved                         bool      `gorm:"index"`
	CreatedAt                        time.Time
	UpdatedAt                        time.Time
}

type JWKKey struct {
	ID         uint64 `gorm:"primaryKey;autoIncrement"`
	Kid        string `gorm:"size:190;uniqueIndex"`
	Alg        string `gorm:"size:32"`       // RS256, ES256
	Kty        string `gorm:"size:16"`       // RSA, EC
	Use        string `gorm:"size:16"`       // sig
	PublicKey  string `gorm:"type:longtext"` // 公钥 PEM（或 JWK JSON）
	PrivateKey string `gorm:"type:longtext"` // 私钥 PEM（开发可明文，生产建议加密）
	Active     bool   `gorm:"index"`
	CreatedAt  time.Time
}

// 授权码/令牌主要存于 Redis；此处仅做最小化的审计持久化。
type TokenRecord struct {
	ID        uint64    `gorm:"primaryKey;autoIncrement"`
	Type      string    `gorm:"size:32"` // access | refresh | id
	ClientID  string    `gorm:"size:190;index"`
	UserID    uint64    `gorm:"index"`
	Scope     string    `gorm:"size:255"`
	JTI       string    `gorm:"size:190;uniqueIndex"`
	ExpiresAt time.Time `gorm:"index"`
	Revoked   bool      `gorm:"index"`
	CreatedAt time.Time
}

type LogRecord struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement"`
	Timestamp   time.Time `gorm:"index"`
	Level       string    `gorm:"size:16;index"`
	Event       string    `gorm:"size:64;index"`
	UserID      *uint64   `gorm:"index"`
	ClientID    *string   `gorm:"index"`
	Description string    `gorm:"type:longtext"`
	IPAddress   string    `gorm:"size:64"`
}

// Consent 记录用户对某客户端的授权 scope，便于后续免提示。
type Consent struct {
	ID        uint64 `gorm:"primaryKey;autoIncrement"`
	UserID    uint64 `gorm:"index"`
	ClientID  string `gorm:"size:190;index"`
	Scope     string `gorm:"size:255"` // 以空格分隔的已授权 scope 列表
	CreatedAt time.Time
	UpdatedAt time.Time
}

// autoMigrate 执行数据库自动迁移。
func autoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(&User{}, &Client{}, &JWKKey{}, &TokenRecord{}, &LogRecord{}, &Consent{})
}
