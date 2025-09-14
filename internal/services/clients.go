package services

import (
    "context"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"

    "net/url"
    "strings"
    "time"

    "github.com/google/uuid"
    "golang.org/x/crypto/bcrypt"
    "gorm.io/gorm"

    "ginkgoid/internal/config"
    "ginkgoid/internal/storage"
)

// ClientService 管理 OIDC 客户端注册与元数据持久化/校验。
type ClientService struct {
    db  *gorm.DB
    cfg config.Config
}

func NewClientService(db *gorm.DB, cfg config.Config) *ClientService { return &ClientService{db: db, cfg: cfg} }

// Register 根据请求创建新客户端；当 token_endpoint_auth_method 为
// "client_secret_basic" 时会生成 client_secret 并仅保存其哈希。
type RegisterRequest struct {
    RedirectURIs []string `json:"redirect_uris"`
    ClientName   string   `json:"client_name"`
    GrantTypes   []string `json:"grant_types"`
    ResponseTypes []string `json:"response_types"`
    ApplicationType string `json:"application_type"`
    TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
    LogoURI string `json:"logo_uri"`
    Scope   string `json:"scope"`
    SubjectType string `json:"subject_type"` // 取值：public 或 pairwise
    SectorIdentifierURI string `json:"sector_identifier_uri"`
    FrontchannelLogoutURI string `json:"frontchannel_logout_uri"`
    BackchannelLogoutURI string `json:"backchannel_logout_uri"`
    PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
}

type RegisterResponse struct {
    ClientID                string   `json:"client_id"`
    ClientSecret            string   `json:"client_secret,omitempty"`
    ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
    ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
    RegistrationAccessToken string   `json:"registration_access_token"`
    RegistrationClientURI   string   `json:"registration_client_uri"`
    TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
    RedirectURIs            []string `json:"redirect_uris"`
    GrantTypes              []string `json:"grant_types"`
}

// Register 执行动态注册的业务逻辑与基本校验，并持久化客户端。
func (s *ClientService) Register(ctx context.Context, baseURL string, req *RegisterRequest) (*RegisterResponse, *storage.Client, error) {
    if len(req.RedirectURIs) == 0 {
        return nil, nil, errors.New("redirect_uris required")
    }
    // 基础校验：redirect_uri 必须是绝对 URL（含 scheme/host）
    for _, ru := range req.RedirectURIs {
        u, err := url.Parse(ru)
        if err != nil || u.Scheme == "" || u.Host == "" {
            return nil, nil, fmt.Errorf("invalid redirect_uri: %s", ru)
        }
    }
    clientID := uuid.NewString()
    secretPlain := ""
    method := req.TokenEndpointAuthMethod
    if method == "" { method = "client_secret_basic" }
    var secretHash string
    if method == "client_secret_basic" {
        secretPlain = uuid.NewString()
        hh, _ := bcrypt.GenerateFromPassword([]byte(secretPlain), bcrypt.DefaultCost)
        secretHash = string(hh)
    }
    grantTypes := req.GrantTypes
    if len(grantTypes) == 0 { grantTypes = []string{"authorization_code"} }
    responseTypes := req.ResponseTypes
    if len(responseTypes) == 0 { responseTypes = []string{"code"} }
    scope := req.Scope
    if scope == "" { scope = "openid profile email" }

    subjectType := req.SubjectType
    if subjectType == "" { subjectType = "public" }

    // 可选：校验 sector_identifier_uri 指向的 JSON 是否覆盖所有 redirect_uris
    if req.SectorIdentifierURI != "" {
        if err := validateSectorIdentifier(s.cfg, req.SectorIdentifierURI, req.RedirectURIs); err != nil {
            return nil, nil, fmt.Errorf("sector_identifier_uri invalid: %w", err)
        }
    }
    // 将 redirect_uris 序列化为 JSON 存库
    ruJSON, _ := json.Marshal(req.RedirectURIs)
    // post_logout_redirect_uris 亦序列化为 JSON 存库
    var plruJSON []byte
    if len(req.PostLogoutRedirectURIs) > 0 {
        plruJSON, _ = json.Marshal(req.PostLogoutRedirectURIs)
    }
    now := time.Now()
    expAt := time.Time{}
    if s.cfg.Token.RegistrationPATTTL > 0 {
        expAt = now.Add(s.cfg.Token.RegistrationPATTTL)
    }
    c := &storage.Client{
        ClientID:   clientID,
        SecretHash: secretHash,
        Name:       req.ClientName,
        RedirectURIs: string(ruJSON),
        GrantTypes: strings.Join(grantTypes, ","),
        ResponseTypes: strings.Join(responseTypes, ","),
        Scope:      scope,
        TokenEndpointAuthMethod: method,
        SubjectType: subjectType,
        SectorIdentifierURI: req.SectorIdentifierURI,
        FrontchannelLogoutURI: req.FrontchannelLogoutURI,
        BackchannelLogoutURI: req.BackchannelLogoutURI,
        PostLogoutRedirectURIs: string(plruJSON),
        RegistrationAccessTokenExpiresAt: expAt,
        Approved:   !s.cfg.Registration.RequireApproval,
        CreatedAt:  now,
        UpdatedAt:  now,
    }
    if err := s.db.WithContext(ctx).Create(c).Error; err != nil {
        return nil, nil, err
    }
    // 生成 registration_access_token（简单高熵随机值）
    sh := sha256.Sum256([]byte(clientID + now.String()))
    regTok := base64.RawURLEncoding.EncodeToString(sh[:])
    // 仅存储散列用于后续校验（不存明文）
    if hh, err := bcrypt.GenerateFromPassword([]byte(regTok), bcrypt.DefaultCost); err == nil {
        c.RegistrationAccessTokenHash = string(hh)
        _ = s.db.WithContext(ctx).Save(c).Error
    }
    resp := &RegisterResponse{
        ClientID: clientID,
        ClientSecret: secretPlain,
        ClientSecretExpiresAt: 0,
        ClientIDIssuedAt: now.Unix(),
        RegistrationAccessToken: regTok,
        RegistrationClientURI: fmt.Sprintf("%s/register?client_id=%s", strings.TrimRight(baseURL, "/"), clientID),
        TokenEndpointAuthMethod: method,
        RedirectURIs: req.RedirectURIs,
        GrantTypes: grantTypes,
    }
    return resp, c, nil
}

// FindByID 根据 client_id 查找已批准的客户端。
func (s *ClientService) FindByID(ctx context.Context, clientID string) (*storage.Client, error) {
    var c storage.Client
    if err := s.db.WithContext(ctx).Where("client_id = ? AND approved = ?", clientID, true).First(&c).Error; err != nil {
        return nil, err
    }
    return &c, nil
}

// findAnyByID 不要求 Approved（用于注册管理）。
func (s *ClientService) findAnyByID(ctx context.Context, clientID string) (*storage.Client, error) {
    var c storage.Client
    if err := s.db.WithContext(ctx).Where("client_id = ?", clientID).First(&c).Error; err != nil {
        return nil, err
    }
    return &c, nil
}

// ValidateSecret 校验客户端凭据（支持 public 客户端 token_endpoint_auth_method=none）。
func (s *ClientService) ValidateSecret(ctx context.Context, clientID, secret string) (bool, *storage.Client, error) {
    c, err := s.FindByID(ctx, clientID)
    if err != nil { return false, nil, err }
    if c.TokenEndpointAuthMethod == "none" {
        return true, c, nil
    }
    if c.SecretHash == "" { return false, c, nil }
    if err := bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret)); err != nil {
        return false, c, nil
    }
    return true, c, nil
}

// ValidateRegistrationToken 校验 registration_access_token 是否有效与未过期。
func (s *ClientService) ValidateRegistrationToken(ctx context.Context, clientID, token string) (bool, *storage.Client, error) {
    c, err := s.findAnyByID(ctx, clientID)
    if err != nil { return false, nil, err }
    if c.RegistrationAccessTokenHash == "" { return false, c, nil }
    if !c.RegistrationAccessTokenExpiresAt.IsZero() && time.Now().After(c.RegistrationAccessTokenExpiresAt) {
        return false, c, nil
    }
    if bcrypt.CompareHashAndPassword([]byte(c.RegistrationAccessTokenHash), []byte(token)) != nil {
        return false, c, nil
    }
    return true, c, nil
}

// Save 保存客户端更改。
func (s *ClientService) Save(ctx context.Context, cl *storage.Client) error {
    return s.db.WithContext(ctx).Save(cl).Error
}

// ValidateSectorIdentifier 包装 sector_identifier_uri 的校验逻辑。
func (s *ClientService) ValidateSectorIdentifier(ctx context.Context, uri string, redirects []string) error {
    return validateSectorIdentifier(s.cfg, uri, redirects)
}
