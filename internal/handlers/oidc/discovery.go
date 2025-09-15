package oidc

// 本包定义 OIDC 相关的响应模型。

// Discovery 表示 OpenID Provider 的元数据文档（Discovery）。
type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`

	RegistrationEndpoint               string `json:"registration_endpoint,omitempty"`
	EndSessionEndpoint                 string `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint                 string `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint              string `json:"introspection_endpoint,omitempty"`
	BackchannelLogoutSupported         *bool  `json:"backchannel_logout_supported,omitempty"`
	BackchannelLogoutSessionSupported  *bool  `json:"backchannel_logout_session_supported,omitempty"`
	FrontchannelLogoutSupported        *bool  `json:"frontchannel_logout_supported,omitempty"`
	FrontchannelLogoutSessionSupported *bool  `json:"frontchannel_logout_session_supported,omitempty"`
	CheckSessionIframe                 string `json:"check_session_iframe,omitempty"`

	AcrValuesSupported           []string `json:"acr_values_supported,omitempty"`
	PromptValuesSupported        []string `json:"prompt_values_supported,omitempty"`
	ClaimsParameterSupported     bool     `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported    bool     `json:"request_parameter_supported,omitempty"`
	RequestURIParameterSupported bool     `json:"request_uri_parameter_supported,omitempty"`
}
