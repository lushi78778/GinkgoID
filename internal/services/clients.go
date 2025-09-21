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

func NewClientService(db *gorm.DB, cfg config.Config) *ClientService {
	return &ClientService{db: db, cfg: cfg}
}

// DB 返回底层 *gorm.DB，供部分只读查询使用（如管理端列表）。
func (s *ClientService) DB() *gorm.DB { return s.db }

// clientRegistrationPlan captures the normalized result of a registration request.
// It contains the persistent model and the API response derived from the sanitized input.
type clientRegistrationPlan struct {
	model *storage.Client
	resp  *RegisterResponse
}

// Register 根据请求创建新客户端；当 token_endpoint_auth_method 为
// "client_secret_basic" 时会生成 client_secret 并仅保存其哈希。
type RegisterRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ApplicationType         string   `json:"application_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	LogoURI                 string   `json:"logo_uri"`
	Scope                   string   `json:"scope"`
	SubjectType             string   `json:"subject_type"` // 取值：public 或 pairwise
	SectorIdentifierURI     string   `json:"sector_identifier_uri"`
	FrontchannelLogoutURI   string   `json:"frontchannel_logout_uri"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
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
	plan, err := s.prepareRegistrationPlan(ctx, baseURL, req)
	if err != nil {
		return nil, nil, err
	}
	if err := s.db.WithContext(ctx).Create(plan.model).Error; err != nil {
		return nil, nil, err
	}
	return plan.resp, plan.model, nil
}

// prepareRegistrationPlan 负责校验、填充默认值，并生成存储模型及响应体。
func (s *ClientService) prepareRegistrationPlan(_ context.Context, baseURL string, req *RegisterRequest) (*clientRegistrationPlan, error) {
	if len(req.RedirectURIs) == 0 {
		return nil, errors.New("redirect_uris required")
	}
	for _, ru := range req.RedirectURIs {
		u, err := url.Parse(ru)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("invalid redirect_uri: %s", ru)
		}
	}
	clientID := uuid.NewString()
	now := time.Now()
	method := strings.TrimSpace(req.TokenEndpointAuthMethod)
	if method == "" {
		method = "client_secret_basic"
	}
	secretPlain := ""
	secretHash := ""
	if method == "client_secret_basic" {
		secretPlain = uuid.NewString()
		hh, err := bcrypt.GenerateFromPassword([]byte(secretPlain), bcrypt.DefaultCost)
		if err != nil {
			return nil, fmt.Errorf("hash client secret: %w", err)
		}
		secretHash = string(hh)
	}
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}
	scope := req.Scope
	if scope == "" {
		scope = "openid profile email"
	}
	subjectType := req.SubjectType
	if subjectType == "" {
		subjectType = "public"
	}
	if req.SectorIdentifierURI != "" {
		if err := validateSectorIdentifier(s.cfg, req.SectorIdentifierURI, req.RedirectURIs); err != nil {
			return nil, fmt.Errorf("sector_identifier_uri invalid: %w", err)
		}
	}
	ruJSON, err := json.Marshal(req.RedirectURIs)
	if err != nil {
		return nil, fmt.Errorf("marshal redirect_uris: %w", err)
	}
	var plruJSON []byte
	if len(req.PostLogoutRedirectURIs) > 0 {
		plruJSON, err = json.Marshal(req.PostLogoutRedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("marshal post_logout_redirect_uris: %w", err)
		}
	}
	var expAtPtr *time.Time
	if ttl := s.cfg.Token.RegistrationPATTTL; ttl > 0 {
		z := now.Add(ttl)
		expAtPtr = &z
	}
	requireApproval := s.cfg.Registration.RequireApproval
	if s.cfg.Env != "prod" {
		requireApproval = false
	}
	status := 1
	approved := true
	if requireApproval {
		status = 0
		approved = false
	}
	enabled := approved
	regToken, regHash, err := generateRegistrationToken(clientID, now)
	if err != nil {
		return nil, err
	}
	model := &storage.Client{
		ClientID:                         clientID,
		SecretHash:                       secretHash,
		Name:                             req.ClientName,
		RedirectURIs:                     string(ruJSON),
		GrantTypes:                       strings.Join(grantTypes, ","),
		ResponseTypes:                    strings.Join(responseTypes, ","),
		Scope:                            scope,
		TokenEndpointAuthMethod:          method,
		SubjectType:                      subjectType,
		SectorIdentifierURI:              req.SectorIdentifierURI,
		FrontchannelLogoutURI:            req.FrontchannelLogoutURI,
		BackchannelLogoutURI:             req.BackchannelLogoutURI,
		PostLogoutRedirectURIs:           string(plruJSON),
		RegistrationAccessTokenHash:      regHash,
		RegistrationAccessTokenExpiresAt: expAtPtr,
		Status:                           status,
		Approved:                         approved,
		Enabled:                          enabled,
		CreatedAt:                        now,
		UpdatedAt:                        now,
	}
	resp := &RegisterResponse{
		ClientID:                clientID,
		ClientSecret:            secretPlain,
		ClientSecretExpiresAt:   0,
		ClientIDIssuedAt:        now.Unix(),
		RegistrationAccessToken: regToken,
		RegistrationClientURI:   fmt.Sprintf("%s/register?client_id=%s", strings.TrimRight(baseURL, "/"), clientID),
		TokenEndpointAuthMethod: method,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
	}
	return &clientRegistrationPlan{model: model, resp: resp}, nil
}

func generateRegistrationToken(clientID string, now time.Time) (string, string, error) {
	// registration_access_token 设计为一次性高熵随机值；此处使用 clientID+时间戳
	// 的哈希避免引入额外依赖，随后仅返回明文一次，并将哈希存库便于校验。
	sh := sha256.Sum256([]byte(clientID + now.String()))
	pl := base64.RawURLEncoding.EncodeToString(sh[:])
	hh, err := bcrypt.GenerateFromPassword([]byte(pl), bcrypt.DefaultCost)
	if err != nil {
		return "", "", fmt.Errorf("hash registration token: %w", err)
	}
	return pl, string(hh), nil
}

// FindByID 根据 client_id 查找已批准的客户端。
func (s *ClientService) FindByID(ctx context.Context, clientID string) (*storage.Client, error) {
	var c storage.Client
	if err := s.db.WithContext(ctx).Where("client_id = ? AND approved = ? AND enabled = ?", clientID, true, true).First(&c).Error; err != nil {
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
	if err != nil {
		return false, nil, err
	}
	if !c.Enabled {
		return false, c, fmt.Errorf("client_disabled")
	}
	if c.TokenEndpointAuthMethod == "none" {
		return true, c, nil
	}
	if c.SecretHash == "" {
		return false, c, nil
	}
	if err := bcrypt.CompareHashAndPassword([]byte(c.SecretHash), []byte(secret)); err != nil {
		return false, c, nil
	}
	return true, c, nil
}

// ValidateRegistrationToken 校验 registration_access_token 是否有效与未过期。
func (s *ClientService) ValidateRegistrationToken(ctx context.Context, clientID, token string) (bool, *storage.Client, error) {
	c, err := s.findAnyByID(ctx, clientID)
	if err != nil {
		return false, nil, err
	}
	if c.RegistrationAccessTokenHash == "" {
		return false, c, nil
	}
	if c.RegistrationAccessTokenExpiresAt != nil {
		if time.Now().After(*c.RegistrationAccessTokenExpiresAt) {
			return false, c, nil
		}
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

// ListByOwner 返回指定用户拥有的客户端列表。
func (s *ClientService) ListByOwner(ctx context.Context, ownerID uint64) ([]storage.Client, error) {
	var list []storage.Client
	if err := s.db.WithContext(ctx).Where("owner_user_id = ?", ownerID).Order("id desc").Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

func (s *ClientService) Count(ctx context.Context) (int64, error) {
	var total int64
	if err := s.db.WithContext(ctx).Model(&storage.Client{}).Count(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

func (s *ClientService) CountPending(ctx context.Context) (int64, error) {
	var total int64
	if err := s.db.WithContext(ctx).Model(&storage.Client{}).Where("status = ?", 0).Count(&total).Error; err != nil {
		return 0, err
	}
	return total, nil
}

// FindAnyByID 不要求 Approved（对内部管理或拥有者操作开放）。
func (s *ClientService) FindAnyByID(ctx context.Context, clientID string) (*storage.Client, error) {
	return s.findAnyByID(ctx, clientID)
}

// DeleteByID 物理删除客户端记录。
func (s *ClientService) DeleteByID(ctx context.Context, clientID string) error {
	return s.db.WithContext(ctx).Where("client_id = ?", clientID).Delete(&storage.Client{}).Error
}

// ListPending 列出待审批的客户端（Status=0）。
func (s *ClientService) ListPending(ctx context.Context, limit int) ([]storage.Client, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var list []storage.Client
	if err := s.db.WithContext(ctx).Where("status = ? AND approved = ?", 0, false).Order("created_at desc").Limit(limit).Find(&list).Error; err != nil {
		return nil, err
	}
	return list, nil
}

// ApproveClient 审批通过指定客户端（置 Status=1，Approved=true，并记录审批元信息）。
func (s *ClientService) ApproveClient(ctx context.Context, clientID string, adminUserID uint64) error {
	var c storage.Client
	if err := s.db.WithContext(ctx).Where("client_id = ?", clientID).First(&c).Error; err != nil {
		return err
	}
	c.Status = 1
	c.Approved = true
	c.Enabled = true
	c.ApprovedBy = adminUserID
	t := time.Now()
	c.ApprovedAt = &t
	c.RejectReason = ""
	return s.db.WithContext(ctx).Save(&c).Error
}

// RejectClient 审批拒绝指定客户端（置 Status=2，Approved=false，并写入拒绝原因）。
func (s *ClientService) RejectClient(ctx context.Context, clientID string, adminUserID uint64, reason string) error {
	var c storage.Client
	if err := s.db.WithContext(ctx).Where("client_id = ?", clientID).First(&c).Error; err != nil {
		return err
	}
	c.Status = 2
	c.Approved = false
	c.Enabled = false
	c.ApprovedBy = adminUserID
	t := time.Now()
	c.ApprovedAt = &t
	c.RejectReason = reason
	return s.db.WithContext(ctx).Save(&c).Error
}
