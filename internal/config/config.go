package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// Config 保存进程级配置（仅使用配置文件或内置默认值）。
// 字段提供开发友好的默认值；生产环境请在 config.yaml 中覆盖。
type Config struct {
	Env          string
	HTTPAddr     string
	Issuer       string
	Docs         DocsConfig
	Pairwise     PairwiseConfig
	MySQL        MySQLConfig
	Redis        RedisConfig
	CORS         CORSConfig
	Crypto       CryptoConfig
	Token        TokenConfig
	Session      SessionConfig
	Registration RegistrationConfig
	Limits       LimitConfig
	Security     SecurityConfig
	ACR          ACRConfig
	Bootstrap    BootstrapConfig
	DPoP         DPoPConfig
}

// ACRConfig 定义认证上下文（ACR/AMR）相关策略
type ACRConfig struct {
	// 最低可接受的 ACR（如 "urn:op:auth:pwd"、"urn:op:auth:otp"），为空则不强制
	Minimum string
	// 是否建议用户进行多因素（不会强制失败，但会在 UI 提示）
	SuggestMFA bool
}

type PairwiseConfig struct {
	// 开启 pairwise subject 支持；开启后 Discovery 同时报告 public 与 pairwise
	Enable bool
	// 生成 pairwise subject 的全局盐值（需妥善保密）
	Salt string
}

type MySQLConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	Params   string
}

func (m MySQLConfig) DSN() string {
	port := m.Port
	if port == 0 {
		port = 3306
	}
	host := m.Host
	if host == "" {
		host = "127.0.0.1"
	}
	db := m.DBName
	if db == "" {
		db = "ginkgoid"
	}
	params := m.Params
	if params == "" {
		params = "parseTime=true&loc=Local&charset=utf8mb4,utf8"
	}
	// 注意：Password 可能为空（本地无密码开发），生产强烈建议设置强密码
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?%s", m.User, m.Password, host, port, db, params)
}

func (m MySQLConfig) DSNMasked() string {
	masked := m
	if masked.Password != "" {
		masked.Password = "******"
	}
	return masked.DSN()
}

type RedisConfig struct {
	Addr     string
	DB       int
	Password string
}

type CORSConfig struct {
	// 是否为 /userinfo 启用 CORS（跨域）；默认关闭
	EnableUserInfo bool
	// 允许的来源，仅在 EnableUserInfo=true 时生效
	AllowedOrigins []string
}

type CryptoConfig struct {
	// ID Token/访问令牌（JWT）默认签名算法
	// 支持：RS256、ES256
	IDTokenAlg string
	// 可选：用于在本地对私钥字段进行对称加密的密钥（仅开发/自托管场景）
	// 建议为 32 字节的随机字符串；生产建议使用 KMS。若为空则不启用加密。
	KeyEncryptionKey string
}

type TokenConfig struct {
	AccessTokenTTL     time.Duration
	IDTokenTTL         time.Duration
	RefreshTokenTTL    time.Duration
	CodeTTL            time.Duration
	CodeLength         int
	RegistrationPATTTL time.Duration
	RequirePKCES256    bool
}

type DPoPConfig struct {
	ReplayWindow time.Duration
	ClockSkew    time.Duration
}

type RegistrationConfig struct {
	// 是否需要审批：为 true 时新注册客户端默认未批准（不可用于授权）。
	RequireApproval bool
	// 初始访问令牌：若非空，则调用 /register 必须携带此 Bearer 令牌
	InitialAccessToken string
	// 校验 sector_identifier_uri 的 HTTP 超时
	SectorTimeout time.Duration
	// 允许 http://localhost 或 127.0.0.1（开发调试）
	AllowInsecureLocalHTTP bool
}

type SessionConfig struct {
	CookieName     string
	CookieDomain   string
	CookieSecure   bool
	CookieSameSite string // 取值：lax、strict、none
	TTL            time.Duration
}

type LimitConfig struct {
	LoginPerMinute int
	TokenPerMinute int
	// 时间窗口（默认 1m）
	Window time.Duration
}

type DocsConfig struct {
	// 是否启用内置的 API 文档页面（Stoplight Elements）
	Enable bool
	// 文档访问路径（路由），例如 /docs
	Route string
	// OpenAPI 规范文件路径（相对进程工作目录）
	SpecPath string
	// HTML 页面路径（Stoplight Elements 静态文件）
	PagePath string
}

type SecurityConfig struct {
	HSTS struct {
		Enabled           bool
		MaxAgeSeconds     int
		IncludeSubdomains bool
	}
}

// BootstrapConfig 包含一次性初始化数据（仅在首次建表时应用）。
type BootstrapConfig struct {
	InitialAdmin InitialAdminConfig
}

type InitialAdminConfig struct {
	Enable   bool
	Username string
	Password string
	Email    string
	Name     string
}

// Load 生成配置：先使用内置默认值，再用同目录的配置文件（config.yaml/yml/json）覆盖。
// 默认：MySQL 127.0.0.1:3306 用户 root/123456；Redis 127.0.0.1:6379 无密码。
func Load() Config {
	// 仅使用配置文件；代码内提供开发友好的默认值作为兜底。
	// 1) 默认值（本地开发可直接运行）
	cfg := Config{
		Env:          "dev",
		HTTPAddr:     ":8080",
		Issuer:       "",
		Docs:         DocsConfig{Enable: true, Route: "/docs", SpecPath: "docs/swagger.json", PagePath: "web/stoplight.html"},
		Pairwise:     PairwiseConfig{Enable: true, Salt: "dev-pairwise-salt-change-me"},
		MySQL:        MySQLConfig{Host: "127.0.0.1", Port: 3306, User: "root", Password: "123456", DBName: "ginkgoid", Params: "parseTime=true&loc=Local&charset=utf8mb4,utf8"},
		Redis:        RedisConfig{Addr: "127.0.0.1:6379", DB: 0, Password: ""},
		CORS:         CORSConfig{EnableUserInfo: false},
		Crypto:       CryptoConfig{IDTokenAlg: "RS256"},
		Token:        TokenConfig{AccessTokenTTL: time.Hour, IDTokenTTL: 15 * time.Minute, RefreshTokenTTL: 30 * 24 * time.Hour, CodeTTL: 2 * time.Minute, CodeLength: 32, RegistrationPATTTL: 24 * time.Hour, RequirePKCES256: true},
		Session:      SessionConfig{CookieName: "op_session", CookieDomain: "", CookieSecure: false, CookieSameSite: "lax", TTL: 24 * time.Hour},
		Registration: RegistrationConfig{RequireApproval: false, SectorTimeout: 3 * time.Second, AllowInsecureLocalHTTP: true},
		Limits:       LimitConfig{LoginPerMinute: 10, TokenPerMinute: 60, Window: time.Minute},
		Security: func() SecurityConfig {
			var s SecurityConfig
			s.HSTS.Enabled = true
			s.HSTS.MaxAgeSeconds = 31536000
			s.HSTS.IncludeSubdomains = true
			return s
		}(),
		Bootstrap: BootstrapConfig{InitialAdmin: InitialAdminConfig{Enable: true, Username: "admin", Password: "123465", Email: "admin@example.com", Name: "Administrator"}},
		DPoP:      DPoPConfig{ReplayWindow: 5 * time.Minute, ClockSkew: time.Minute},
	}

	// 2) 配置文件覆盖（若存在）
	if path := FirstExisting("config.yaml", "config.yml", "config.json"); path != "" {
		_ = loadFromFile(path, &cfg)
	}

	// 3) 不再从 .env 读取密钥：所有运行时配置应通过 config.yaml 提供。
	//    如需在部署时注入机密，请通过配置管理系统或环境注入到配置文件生成流程中。
	return cfg
}

// note: .env parsing removed to enforce single source of truth (config.yaml).

// 配置文件格式：YAML 或 JSON。仅非零值会覆盖现有字段。
func loadFromFile(path string, cfg *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ext := strings.ToLower(filepath.Ext(path))
	var fm fileModel
	if ext == ".yaml" || ext == ".yml" {
		if err := yaml.Unmarshal(b, &fm); err != nil {
			return err
		}
	} else if ext == ".json" || ext == "" {
		if err := json.Unmarshal(b, &fm); err != nil {
			return err
		}
	} else {
		return errors.New("unsupported config file format")
	}
	fm.apply(cfg)
	return nil
}

// 说明：环境变量优先级逻辑已去除。
// 环境变量覆盖逻辑已移除：仅使用配置文件（若存在）与内置默认值。

// --- 配置文件模型与合并逻辑 ---

type fileModel struct {
	Env          string            `yaml:"env" json:"env"`
	HTTPAddr     string            `yaml:"http_addr" json:"http_addr"`
	Issuer       string            `yaml:"issuer" json:"issuer"`
	Docs         *fileDocs         `yaml:"docs" json:"docs"`
	Pairwise     *filePairwise     `yaml:"pairwise" json:"pairwise"`
	MySQL        *fileMySQL        `yaml:"mysql" json:"mysql"`
	Redis        *fileRedis        `yaml:"redis" json:"redis"`
	CORS         *fileCORS         `yaml:"cors" json:"cors"`
	Crypto       *fileCrypto       `yaml:"crypto" json:"crypto"`
	Token        *fileToken        `yaml:"token" json:"token"`
	Session      *fileSession      `yaml:"session" json:"session"`
	Registration *fileRegistration `yaml:"registration" json:"registration"`
	Limits       *fileLimits       `yaml:"limits" json:"limits"`
	Security     *fileSecurity     `yaml:"security" json:"security"`
	ACR          *fileACR          `yaml:"acr" json:"acr"`
	Bootstrap    *fileBootstrap    `yaml:"bootstrap" json:"bootstrap"`
	DPoP         *fileDPoP         `yaml:"dpop" json:"dpop"`
}

type fileACR struct {
	Minimum    string `yaml:"minimum" json:"minimum"`
	SuggestMFA *bool  `yaml:"suggest_mfa" json:"suggest_mfa"`
}

type filePairwise struct {
	Enable *bool  `yaml:"enable" json:"enable"`
	Salt   string `yaml:"salt" json:"salt"`
}
type fileMySQL struct {
	Host     string `yaml:"host" json:"host"`
	Port     int    `yaml:"port" json:"port"`
	User     string `yaml:"user" json:"user"`
	Password string `yaml:"password" json:"password"`
	DBName   string `yaml:"db" json:"db"`
	Params   string `yaml:"params" json:"params"`
}
type fileRedis struct {
	Addr     string `yaml:"addr" json:"addr"`
	DB       int    `yaml:"db" json:"db"`
	Password string `yaml:"password" json:"password"`
}
type fileCORS struct {
	EnableUserInfo *bool    `yaml:"enable_userinfo" json:"enable_userinfo"`
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"`
}
type fileCrypto struct {
	IDTokenAlg       string `yaml:"id_token_alg" json:"id_token_alg"`
	KeyEncryptionKey string `yaml:"key_encryption_key" json:"key_encryption_key"`
}
type fileToken struct {
	AccessTokenTTL     string `yaml:"access_token_ttl" json:"access_token_ttl"`
	IDTokenTTL         string `yaml:"id_token_ttl" json:"id_token_ttl"`
	RefreshTokenTTL    string `yaml:"refresh_token_ttl" json:"refresh_token_ttl"`
	CodeTTL            string `yaml:"code_ttl" json:"code_ttl"`
	CodeLength         int    `yaml:"code_length" json:"code_length"`
	RegistrationPATTTL string `yaml:"registration_pat_ttl" json:"registration_pat_ttl"`
	RequirePKCES256    *bool  `yaml:"require_pkce_s256" json:"require_pkce_s256"`
}
type fileRegistration struct {
	RequireApproval        *bool  `yaml:"require_approval" json:"require_approval"`
	InitialAccessToken     string `yaml:"initial_access_token" json:"initial_access_token"`
	SectorTimeout          string `yaml:"sector_timeout" json:"sector_timeout"`
	AllowInsecureLocalHTTP *bool  `yaml:"allow_insecure_local_http" json:"allow_insecure_local_http"`
}
type fileSession struct {
	CookieName     string `yaml:"cookie_name" json:"cookie_name"`
	CookieDomain   string `yaml:"cookie_domain" json:"cookie_domain"`
	CookieSecure   *bool  `yaml:"cookie_secure" json:"cookie_secure"`
	CookieSameSite string `yaml:"cookie_samesite" json:"cookie_samesite"`
	TTL            string `yaml:"ttl" json:"ttl"`
}
type fileLimits struct {
	LoginPerMinute int    `yaml:"login_per_minute" json:"login_per_minute"`
	TokenPerMinute int    `yaml:"token_per_minute" json:"token_per_minute"`
	Window         string `yaml:"window" json:"window"`
}
type fileDPoP struct {
	ReplayWindow string `yaml:"replay_window" json:"replay_window"`
	ClockSkew    string `yaml:"clock_skew" json:"clock_skew"`
}
type fileDocs struct {
	Enable   *bool  `yaml:"enable" json:"enable"`
	Route    string `yaml:"route" json:"route"`
	SpecPath string `yaml:"spec_path" json:"spec_path"`
	PagePath string `yaml:"page_path" json:"page_path"`
}
type fileSecurity struct {
	HSTS struct {
		Enabled           *bool `yaml:"enabled" json:"enabled"`
		MaxAge            int   `yaml:"max_age" json:"max_age"`
		IncludeSubdomains *bool `yaml:"include_subdomains" json:"include_subdomains"`
	} `yaml:"hsts" json:"hsts"`
}
type fileBootstrap struct {
	InitialAdmin *fileAdmin `yaml:"initial_admin" json:"initial_admin"`
}
type fileAdmin struct {
	Enable   *bool  `yaml:"enable" json:"enable"`
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
	Email    string `yaml:"email" json:"email"`
	Name     string `yaml:"name" json:"name"`
}

func (fm *fileModel) apply(cfg *Config) {
	if fm.Env != "" {
		cfg.Env = fm.Env
	}
	if fm.HTTPAddr != "" {
		cfg.HTTPAddr = fm.HTTPAddr
	}
	if fm.Issuer != "" {
		cfg.Issuer = fm.Issuer
	}
	if fm.Docs != nil {
		if fm.Docs.Enable != nil {
			cfg.Docs.Enable = *fm.Docs.Enable
		}
		if fm.Docs.Route != "" {
			cfg.Docs.Route = fm.Docs.Route
		}
		if fm.Docs.SpecPath != "" {
			cfg.Docs.SpecPath = fm.Docs.SpecPath
		}
		if fm.Docs.PagePath != "" {
			cfg.Docs.PagePath = fm.Docs.PagePath
		}
	}
	if fm.Pairwise != nil {
		if fm.Pairwise.Enable != nil {
			cfg.Pairwise.Enable = *fm.Pairwise.Enable
		}
		if fm.Pairwise.Salt != "" {
			cfg.Pairwise.Salt = fm.Pairwise.Salt
		}
	}
	if fm.MySQL != nil {
		if fm.MySQL.Host != "" {
			cfg.MySQL.Host = fm.MySQL.Host
		}
		if fm.MySQL.Port != 0 {
			cfg.MySQL.Port = fm.MySQL.Port
		}
		if fm.MySQL.User != "" {
			cfg.MySQL.User = fm.MySQL.User
		}
		if fm.MySQL.Password != "" {
			cfg.MySQL.Password = fm.MySQL.Password
		}
		if fm.MySQL.DBName != "" {
			cfg.MySQL.DBName = fm.MySQL.DBName
		}
		if fm.MySQL.Params != "" {
			cfg.MySQL.Params = fm.MySQL.Params
		}
	}
	if fm.Redis != nil {
		if fm.Redis.Addr != "" {
			cfg.Redis.Addr = fm.Redis.Addr
		}
		if fm.Redis.DB != 0 {
			cfg.Redis.DB = fm.Redis.DB
		}
		if fm.Redis.Password != "" {
			cfg.Redis.Password = fm.Redis.Password
		}
	}
	if fm.CORS != nil {
		if fm.CORS.EnableUserInfo != nil {
			cfg.CORS.EnableUserInfo = *fm.CORS.EnableUserInfo
		}
		if len(fm.CORS.AllowedOrigins) > 0 {
			cfg.CORS.AllowedOrigins = fm.CORS.AllowedOrigins
		}
	}
	if fm.Crypto != nil {
		if fm.Crypto.IDTokenAlg != "" {
			cfg.Crypto.IDTokenAlg = fm.Crypto.IDTokenAlg
		}
		if fm.Crypto.KeyEncryptionKey != "" {
			cfg.Crypto.KeyEncryptionKey = fm.Crypto.KeyEncryptionKey
		}
	}
	if fm.Token != nil {
		if fm.Token.AccessTokenTTL != "" {
			if d, err := time.ParseDuration(fm.Token.AccessTokenTTL); err == nil {
				cfg.Token.AccessTokenTTL = d
			}
		}
		if fm.Token.IDTokenTTL != "" {
			if d, err := time.ParseDuration(fm.Token.IDTokenTTL); err == nil {
				cfg.Token.IDTokenTTL = d
			}
		}
		if fm.Token.RefreshTokenTTL != "" {
			if d, err := time.ParseDuration(fm.Token.RefreshTokenTTL); err == nil {
				cfg.Token.RefreshTokenTTL = d
			}
		}
		if fm.Token.CodeTTL != "" {
			if d, err := time.ParseDuration(fm.Token.CodeTTL); err == nil {
				cfg.Token.CodeTTL = d
			}
		}
		if fm.Token.CodeLength != 0 {
			cfg.Token.CodeLength = fm.Token.CodeLength
		}
		if fm.Token.RegistrationPATTTL != "" {
			if d, err := time.ParseDuration(fm.Token.RegistrationPATTTL); err == nil {
				cfg.Token.RegistrationPATTTL = d
			}
		}
		if fm.Token.RequirePKCES256 != nil {
			cfg.Token.RequirePKCES256 = *fm.Token.RequirePKCES256
		}
	}
	if fm.Registration != nil {
		if fm.Registration.RequireApproval != nil {
			cfg.Registration.RequireApproval = *fm.Registration.RequireApproval
		}
		if fm.Registration.InitialAccessToken != "" {
			cfg.Registration.InitialAccessToken = fm.Registration.InitialAccessToken
		}
		if fm.Registration.SectorTimeout != "" {
			if d, err := time.ParseDuration(fm.Registration.SectorTimeout); err == nil {
				cfg.Registration.SectorTimeout = d
			}
		}
		if fm.Registration.AllowInsecureLocalHTTP != nil {
			cfg.Registration.AllowInsecureLocalHTTP = *fm.Registration.AllowInsecureLocalHTTP
		}
	}
	if fm.Session != nil {
		if fm.Session.CookieName != "" {
			cfg.Session.CookieName = fm.Session.CookieName
		}
		if fm.Session.CookieDomain != "" {
			cfg.Session.CookieDomain = fm.Session.CookieDomain
		}
		if fm.Session.CookieSecure != nil {
			cfg.Session.CookieSecure = *fm.Session.CookieSecure
		}
		if fm.Session.CookieSameSite != "" {
			cfg.Session.CookieSameSite = fm.Session.CookieSameSite
		}
		if fm.Session.TTL != "" {
			if d, err := time.ParseDuration(fm.Session.TTL); err == nil {
				cfg.Session.TTL = d
			}
		}
	}
	if fm.Limits != nil {
		if fm.Limits.LoginPerMinute != 0 {
			cfg.Limits.LoginPerMinute = fm.Limits.LoginPerMinute
		}
		if fm.Limits.TokenPerMinute != 0 {
			cfg.Limits.TokenPerMinute = fm.Limits.TokenPerMinute
		}
		if fm.Limits.Window != "" {
			if d, err := time.ParseDuration(fm.Limits.Window); err == nil {
				cfg.Limits.Window = d
			}
		}
	}
	if fm.DPoP != nil {
		if fm.DPoP.ReplayWindow != "" {
			if d, err := time.ParseDuration(fm.DPoP.ReplayWindow); err == nil {
				cfg.DPoP.ReplayWindow = d
			}
		}
		if fm.DPoP.ClockSkew != "" {
			if d, err := time.ParseDuration(fm.DPoP.ClockSkew); err == nil {
				cfg.DPoP.ClockSkew = d
			}
		}
	}
	if fm.Security != nil {
		if fm.Security.HSTS.Enabled != nil {
			cfg.Security.HSTS.Enabled = *fm.Security.HSTS.Enabled
		}
		if fm.Security.HSTS.MaxAge != 0 {
			cfg.Security.HSTS.MaxAgeSeconds = fm.Security.HSTS.MaxAge
		}
		if fm.Security.HSTS.IncludeSubdomains != nil {
			cfg.Security.HSTS.IncludeSubdomains = *fm.Security.HSTS.IncludeSubdomains
		}
	}
	if fm.ACR != nil {
		if fm.ACR.Minimum != "" {
			cfg.ACR.Minimum = fm.ACR.Minimum
		}
		if fm.ACR.SuggestMFA != nil {
			cfg.ACR.SuggestMFA = *fm.ACR.SuggestMFA
		}
	}
	if fm.Bootstrap != nil && fm.Bootstrap.InitialAdmin != nil {
		ia := fm.Bootstrap.InitialAdmin
		if ia.Enable != nil {
			cfg.Bootstrap.InitialAdmin.Enable = *ia.Enable
		}
		if ia.Username != "" {
			cfg.Bootstrap.InitialAdmin.Username = ia.Username
		}
		if ia.Password != "" {
			cfg.Bootstrap.InitialAdmin.Password = ia.Password
		}
		if ia.Email != "" {
			cfg.Bootstrap.InitialAdmin.Email = ia.Email
		}
		if ia.Name != "" {
			cfg.Bootstrap.InitialAdmin.Name = ia.Name
		}
	}
}

// FirstExisting 按顺序返回第一个存在的文件路径；若都不存在则返回空字符串。
// 注意：该函数用于在多路径间进行容错查找，如配置文件或静态资源位置。
func FirstExisting(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
