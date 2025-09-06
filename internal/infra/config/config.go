package config

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"
)

type ServerCfg struct {
	Addr          string `mapstructure:"addr"`
	PublicBaseURL string `mapstructure:"public_base_url"`
	CookieDomain  string `mapstructure:"cookie_domain"`
	SecureCookies bool   `mapstructure:"secure_cookies"`
	AutoMigrate   bool   `mapstructure:"auto_migrate"`
}

type DBCfg struct {
	Driver string `mapstructure:"driver"`
	DSN    string `mapstructure:"dsn"`
}

type RedisCfg struct {
	Enabled  bool   `mapstructure:"enabled"`
	Addr     string `mapstructure:"addr"`
	DB       int    `mapstructure:"db"`
	Password string `mapstructure:"password"`
}

type OIDCCfg struct {
	Issuer         string   `mapstructure:"issuer"`
	Scopes         []string `mapstructure:"scopes"`
	IDTokenTTL     string   `mapstructure:"id_token_ttl"`
	AccessTokenTTL string   `mapstructure:"access_token_ttl"`
	ForcePKCE      bool     `mapstructure:"force_pkce"`
	ForceNonce     bool     `mapstructure:"force_nonce"`
}

type ConsentCfg struct {
	Version         int  `mapstructure:"version"`
	RememberDefault bool `mapstructure:"remember_default"`
	ExpireDays      int  `mapstructure:"expire_days"`
}

type SecurityCfg struct {
	LoginRatePerMin       int    `mapstructure:"login_rate_per_min"`
	TokenRatePerMin       int    `mapstructure:"token_rate_per_min"`
	PasswordHash          string `mapstructure:"password_hash"`
	HSTS                  bool   `mapstructure:"hsts"`
	LogRetainDays         int    `mapstructure:"log_retain_days"`
	JWKEncPassphrase      string `mapstructure:"jwk_enc_passphrase"`
	MaxSessionsPerUser    int    `mapstructure:"max_sessions_per_user"`
	AllowInsecureLocalJWT bool   `mapstructure:"allow_insecure_local_jwt"`
}

type AdminBootstrap struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type AdminCfg struct {
	Bootstrap  AdminBootstrap `mapstructure:"bootstrap"`
	PrivacyURL string         `mapstructure:"privacy_url"`
	TermsURL   string         `mapstructure:"terms_url"`
}

type Config struct {
	Server   ServerCfg   `mapstructure:"server"`
	DB       DBCfg       `mapstructure:"db"`
	Redis    RedisCfg    `mapstructure:"redis"`
	OIDC     OIDCCfg     `mapstructure:"oidc"`
	Consent  ConsentCfg  `mapstructure:"consent"`
	Security SecurityCfg `mapstructure:"security"`
	Admin    AdminCfg    `mapstructure:"admin"`
}

var cfg Config

// C 返回全局配置的只读指针。
func C() *Config { return &cfg }

// Load 从 manifest/config/config.yaml 读取配置，并支持环境变量覆盖。
// 约定：环境变量前缀为 GINKGOID，`.` 使用 `_` 替换。
func Load() error {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./manifest/config")
	v.AutomaticEnv()
	v.SetEnvPrefix("GINKGOID")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	if err := v.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	return nil
}

// Validate performs basic configuration validation and returns error if critical fields are invalid.
// Validate 对关键配置进行合法性校验，返回第一个发现的错误。
func Validate() error {
	if cfg.Server.Addr == "" {
		return fmt.Errorf("server.addr is required")
	}
	if cfg.OIDC.Issuer == "" {
		return fmt.Errorf("oidc.issuer is required")
	}
	// simple URL check for issuer
	if !(len(cfg.OIDC.Issuer) > 7 && (cfg.OIDC.Issuer[:7] == "http://" || cfg.OIDC.Issuer[:8] == "https://")) {
		return fmt.Errorf("oidc.issuer must be a full URL including scheme (http/https)")
	}
	if cfg.DB.Driver == "" || cfg.DB.DSN == "" {
		return fmt.Errorf("db.driver and db.dsn are required")
	}
	return nil
}
