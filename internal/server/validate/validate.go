// Package validate 实现对 OIDC 相关请求参数的解析与基础校验。
package validate

import (
	"errors"
	"net/url"
	"strings"
)

// 常见错误码，遵循 OAuth/OIDC 约定的 error 值。
var (
	ErrInvalidRequest          = errors.New("invalid_request")
	ErrUnsupportedResponseType = errors.New("unsupported_response_type")
	ErrInvalidScope            = errors.New("invalid_scope")
	ErrInvalidClient           = errors.New("invalid_client")
	ErrInvalidGrant            = errors.New("invalid_grant")
)

// AuthorizeParams 表示 /authorize 的关键查询参数。
type AuthorizeParams struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// ParseAuthorize 解析并校验 /authorize 查询参数。
// 要求：
// - response_type 必须为 code；
// - client_id/redirect_uri/scope/state 必填；
// - 若 forceNonce/forcePKCE 为真则分别要求 nonce、S256 PKCE；
// - scope 必须包含 openid。
func ParseAuthorize(q url.Values, forceNonce bool, forcePKCE bool) (AuthorizeParams, error) {
	p := AuthorizeParams{
		ResponseType:        q.Get("response_type"),
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
	if p.ResponseType != "code" {
		return p, ErrUnsupportedResponseType
	}
	if p.ClientID == "" || p.RedirectURI == "" || p.Scope == "" || p.State == "" {
		return p, ErrInvalidRequest
	}
	if forceNonce && p.Nonce == "" {
		return p, ErrInvalidRequest
	}
	if forcePKCE && (p.CodeChallenge == "" || strings.ToUpper(p.CodeChallengeMethod) != "S256") {
		return p, ErrInvalidRequest
	}
	// require openid scope
	ok := false
	for _, s := range strings.Fields(p.Scope) {
		if s == "openid" {
			ok = true
			break
		}
	}
	if !ok {
		return p, ErrInvalidScope
	}
	return p, nil
}

// TokenParams 表示 /token 的表单参数。
type TokenParams struct {
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientID     string
	ClientSecret string
}

// ParseTokenForm 解析并校验 /token 的表单参数。
// 要求：grant_type=authorization_code，且 code/redirect_uri/code_verifier 均不为空。
func ParseTokenForm(v url.Values) (TokenParams, error) {
	p := TokenParams{
		GrantType:    v.Get("grant_type"),
		Code:         v.Get("code"),
		RedirectURI:  v.Get("redirect_uri"),
		CodeVerifier: v.Get("code_verifier"),
		ClientID:     v.Get("client_id"),
		ClientSecret: v.Get("client_secret"),
	}
	if p.GrantType != "authorization_code" || p.Code == "" || p.RedirectURI == "" || p.CodeVerifier == "" {
		return p, ErrInvalidRequest
	}
	return p, nil
}
