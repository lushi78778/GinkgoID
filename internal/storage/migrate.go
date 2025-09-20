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
	MarketingOptIn bool      `gorm:"index"`
	PendingEmail    string    `gorm:"size:190"`
	MFAEnabled      bool      `gorm:"index"`
	MFASecret       string    `gorm:"size:128"`
	MFARecoveryCodes string   `gorm:"type:text"`
	MFAPendingSecret string   `gorm:"size:128"`
	MFAPendingRecoveryCodes string `gorm:"type:text"`
	MFAEnrolledAt    *time.Time
	MFALastUsedAt    *time.Time
	DeletionRequestedAt *time.Time
	DeletionReason       string `gorm:"size:255"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type Setting struct {
	Key       string    `gorm:"primaryKey;size:190"`
	Value     string    `gorm:"type:longtext"`
	UpdatedAt time.Time
}

type Client struct {
	ID                               uint64     `gorm:"primaryKey;autoIncrement"`
	ClientID                         string     `gorm:"size:190;uniqueIndex"`
	SecretHash                       string     `gorm:"size:255"`  // 客户端密钥哈希
	Name                             string     `gorm:"size:190"`  // 客户端名称
	OwnerUserID                      uint64     `gorm:"index"`     // 拥有者用户ID（通过控制台注册时记录）
	RedirectURIs                     string     `gorm:"type:text"` // JSON 数组字符串
	GrantTypes                       string     `gorm:"size:255"`  // 以逗号分隔
	ResponseTypes                    string     `gorm:"size:255"`
	Scope                            string     `gorm:"size:255"`
	TokenEndpointAuthMethod          string     `gorm:"size:64"` // 取值：client_secret_basic 或 none
	SubjectType                      string     `gorm:"size:32"` // 取值：public 或 pairwise
	SectorIdentifierURI              string     `gorm:"size:255"`
	FrontchannelLogoutURI            string     `gorm:"size:255"`
	BackchannelLogoutURI             string     `gorm:"size:255"`
	PostLogoutRedirectURIs           string     `gorm:"type:text"` // JSON 数组字符串
	RegistrationAccessTokenHash      string     `gorm:"size:255"`
	RegistrationAccessTokenExpiresAt *time.Time `gorm:"index"`
	// 审批流相关字段
	Status       int        `gorm:"index;default:0"` // 审批状态：0=待审批，1=已通过，2=已拒绝
	ApprovedBy   uint64     `gorm:"index"`           // 审批人用户ID
	ApprovedAt   *time.Time // 审批时间（待审为 NULL）
	RejectReason string     `gorm:"size:255"` // 拒绝原因
	Approved     bool       `gorm:"index"`    // 兼容旧逻辑，true=已通过
	Enabled      bool       `gorm:"index"`    // 是否允许使用（审批通过后可单独禁用）
	CreatedAt    time.Time
	UpdatedAt    time.Time
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
	// 扩展字段：请求与会话上下文
	RequestID string `gorm:"size:64;index"`
	SessionID string `gorm:"size:190;index"`
	Method    string `gorm:"size:8"`
	Path      string `gorm:"size:255"`
	Status    int    `gorm:"index"`
	UserAgent string `gorm:"size:255"`
	Outcome   string `gorm:"size:16;index"` // success | failure
	ErrorCode string `gorm:"size:64;index"`
	ExtraJSON string `gorm:"type:longtext"`
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
	if err := db.AutoMigrate(&User{}, &Client{}, &JWKKey{}, &TokenRecord{}, &LogRecord{}, &Consent{}, &Setting{}); err != nil {
		return err
	}
	// 保障字段可空（部分旧库可能保留 NOT NULL 约束）
	// MySQL: 修改 registration_access_token_expires_at 与 approved_at 允许为 NULL
	// 忽略错误以避免不同方言差异导致启动失败
	_ = db.Exec("ALTER TABLE clients MODIFY COLUMN registration_access_token_expires_at DATETIME NULL").Error
	_ = db.Exec("ALTER TABLE clients MODIFY COLUMN approved_at DATETIME NULL").Error
	return nil
}
