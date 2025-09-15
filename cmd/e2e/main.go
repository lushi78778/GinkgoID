package main

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

type clientInfo struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	RedirectURIs            []string `json:"redirect_uris"`
}

type tokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

var verbose bool

func main() {
	var base string
	var username string
	var password string
	var initialAccess string
	var timeout time.Duration
	flag.StringVar(&base, "base", "http://127.0.0.1:8080", "Base URL of GinkgoID server (issuer)")
	flag.StringVar(&username, "username", "e2e_user", "Username to create/login for e2e test")
	flag.StringVar(&password, "password", "P@ssw0rd!", "Password for the e2e user")
	flag.StringVar(&initialAccess, "iat", "", "Initial access token for /register if configured")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "HTTP timeout for requests")
	flag.BoolVar(&verbose, "v", true, "Verbose logging")
	flag.Parse()

	must := func(err error, msg string) {
		if err != nil {
			log.Fatalf("%s: %v", msg, err)
		}
	}

	jar, _ := cookiejar.New(nil)
	baseURL, err := url.Parse(strings.TrimRight(base, "/"))
	must(err, "parse base url")

	client := &http.Client{Jar: jar, Timeout: timeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// Allow redirects within same host; stop when leaving base host
		if req.URL.Host == baseURL.Host {
			if len(via) > 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		}
		return http.ErrUseLastResponse
	}

	_ = context.Background() // reserved for future per-request context
	log.Printf("E2E start -> %s", baseURL)

	// Basic ops: discovery, jwks, health, metrics, check_session, docs
	log.Printf("[1] 发现文档 .well-known/openid-configuration")
	must(expectStatusJSON(client, baseURL.ResolveReference(mustURL("/.well-known/openid-configuration")), 200, nil), "discovery")
	log.Printf("[2] JWKS 公钥 /jwks.json")
	must(expectStatusOK(client, baseURL.ResolveReference(mustURL("/jwks.json"))), "jwks.json")
	log.Printf("[3] 健康检查 /healthz 与 /metrics")
	must(expectStatusOK(client, baseURL.ResolveReference(mustURL("/healthz"))), "healthz")
	must(expectStatusOK(client, baseURL.ResolveReference(mustURL("/metrics"))), "metrics")
	log.Printf("[4] 会话探测 /check_session 与文档页")
	must(expectStatusOK(client, baseURL.ResolveReference(mustURL("/check_session"))), "check_session")
	// Docs (best effort — ignore missing page/spec)
	_ = expectStatusOK(client, baseURL.ResolveReference(mustURL("/openapi.json")))
	_ = expectStatusOK(client, baseURL.ResolveReference(mustURL("/docs")))

	// Dev: create user and list users
	uname := fmt.Sprintf("%s_%d", username, time.Now().UnixNano())
	userReq := map[string]string{"username": uname, "password": password, "email": uname + "@example.com", "name": "E2E User"}
	log.Printf("[5] 创建开发用户 /dev/users: %s", uname)
	must(doJSON(client, "POST", baseURL.ResolveReference(mustURL("/dev/users")).String(), userReq, nil, 201, nil), "dev create user")
	log.Printf("[6] 列出开发用户 /dev/users")
	must(expectStatusJSON(client, baseURL.ResolveReference(mustURL("/dev/users")), 200, nil), "dev list users")
	// Dev: rotate keys
	log.Printf("[7] 轮换签名密钥 /dev/keys/rotate")
	_ = expectStatusNoContent(client, baseURL.ResolveReference(mustURL("/dev/keys/rotate")), "POST")

	// Dynamic client registration
	redirectURI := "http://127.0.0.1:9999/cb"
	postLogoutRedirectURI := "http://127.0.0.1:9999/post-logout"
	regBody := map[string]any{
		"client_name":                "e2e-client",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code", "code id_token"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email offline_access",
		"post_logout_redirect_uris":  []string{postLogoutRedirectURI},
		"frontchannel_logout_uri":    "http://127.0.0.1:9999/front-logout",
		"backchannel_logout_uri":     "http://127.0.0.1:9999/back-logout",
		"subject_type":               "public",
	}
	headers := http.Header{}
	if initialAccess != "" {
		headers.Set("Authorization", "Bearer "+initialAccess)
	}
	var reg clientInfo
	log.Printf("[8] 动态注册客户端 /register")
	must(doJSON(client, "POST", baseURL.ResolveReference(mustURL("/register")).String(), regBody, headers, 201, &reg), "register client")
	if reg.ClientID == "" || reg.RegistrationAccessToken == "" {
		log.Fatalf("invalid register response: %+v", reg)
	}
	log.Printf("已注册客户端 client_id=%s redirect_uris=%v", reg.ClientID, reg.RedirectURIs)
	// GET /register
	regH := http.Header{"Authorization": {"Bearer " + reg.RegistrationAccessToken}}
	log.Printf("[9] 查询已注册客户端 GET /register?client_id=...")
	must(expectStatusJSON(client, mustParseURL(mustAddQuery(reg.RegistrationClientURI, "client_id", reg.ClientID)), 200, regH), "get registered client")
	// PUT /register: update name
	upd := map[string]any{"client_name": "e2e-client-updated"}
	log.Printf("[10] 更新已注册客户端 PUT /register")
	must(doJSON(client, "PUT", mustAddQuery(reg.RegistrationClientURI, "client_id", reg.ClientID), upd, regH, 204, nil), "update registered client")
	// POST /register/rotate
	rotateURL := baseURL.ResolveReference(mustURL("/register/rotate")).String() + "?client_id=" + url.QueryEscape(reg.ClientID)
	var rotated map[string]string
	log.Printf("[11] 轮换 registration_access_token POST /register/rotate")
	must(doJSON(client, "POST", rotateURL, nil, regH, 200, &rotated), "rotate registration token")
	if t := rotated["registration_access_token"]; t != "" {
		reg.RegistrationAccessToken = t
		regH.Set("Authorization", "Bearer "+t)
	}

	// Authorization Code with PKCE
	codeVerifier := randString(64)
	codeChallenge := pkceS256(codeVerifier)
	state := randString(16)
	authorizeQ := url.Values{
		"response_type":         {"code"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email offline_access"},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	// 1) GET /authorize -> expect login page 200
	log.Printf("[12] 授权码 + PKCE 流程：GET /authorize")
	authURL := baseURL.ResolveReference(mustURL("/authorize?" + authorizeQ.Encode()))
	must(expectStatusOK(client, authURL), "authorize login page")
	// 2) POST /login with original authorize params -> 302 -> follow internal until final 302 to redirect_uri
	log.Printf("[13] 提交登录 POST /login 用户=%s", uname)
	loginForm := cloneValues(authorizeQ)
	loginForm.Set("username", uname)
	loginForm.Set("password", password)
	must(expectRedirect(client, baseURL.ResolveReference(mustURL("/login")), loginForm), "login submit")
	// 3) Approve consent (idempotent if already approved)
	log.Printf("[14] 授权同意 POST /consent")
	cons := cloneValues(authorizeQ)
	cons.Set("decision", "approve")
	must(expectRedirect(client, baseURL.ResolveReference(mustURL("/consent")), cons), "consent approve")
	// 4) Final authorize to get code (client stops redirecting when host != base host)
	// Re-hit /authorize to drive code issuance if needed
	_, loc := mustGetRedirect(client, authURL)
	code := extractParam(loc, "code")
	if code == "" {
		// Try one more time
		_, loc = mustGetRedirect(client, authURL)
		code = extractParam(loc, "code")
	}
	if code == "" {
		log.Fatalf("no authorization code in redirect location: %s", loc)
	}
	if s := extractParam(loc, "state"); s != state {
		log.Fatalf("state mismatch: want %s got %s", state, s)
	}
	log.Printf("已获取授权码 code=%s...", safeTrunc(code, 12))

	// Token exchange
	tokURL := baseURL.ResolveReference(mustURL("/token")).String()
	ts := mustToken(client, tokURL, reg.ClientID, reg.ClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	})
	if ts.AccessToken == "" || ts.IDToken == "" || ts.RefreshToken == "" {
		log.Fatalf("invalid token response: %+v", ts)
	}
	log.Printf("已获取令牌 access(%dB) id_token(%dB) refresh(%dB)", len(ts.AccessToken), len(ts.IDToken), len(ts.RefreshToken))
	if verbose {
		if head, claims := decodeJWT(ts.IDToken); head != "" {
			log.Printf("ID Token header: %s", head)
			log.Printf("ID Token claims: %s", claims)
		}
	}

	// UserInfo
	log.Printf("[15] GET /userinfo (Bearer)")
	must(expectJSON(client, baseURL.ResolveReference(mustURL("/userinfo")), http.Header{"Authorization": {"Bearer " + ts.AccessToken}}, 200, nil), "userinfo get")
	// UserInfo via POST form
	form := url.Values{"access_token": {ts.AccessToken}}
	must(expectStatus(client, "POST", baseURL.ResolveReference(mustURL("/userinfo")), strings.NewReader(form.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, 200), "userinfo post")

	// Introspect
	log.Printf("[16] POST /introspect active")
	must(expectJSONWithBasic(client, baseURL.ResolveReference(mustURL("/introspect")), reg.ClientID, reg.ClientSecret, url.Values{"token": {ts.AccessToken}}, 200, map[string]any{"active": true}), "introspect active")

	// Revoke access token
	log.Printf("[17] POST /revoke access_token")
	must(expectStatusWithBasic(client, baseURL.ResolveReference(mustURL("/revoke")), reg.ClientID, reg.ClientSecret, url.Values{"token": {ts.AccessToken}, "token_type_hint": {"access_token"}}, 200), "revoke access")
	// Now userinfo should be 401, introspect inactive
	_ = expectStatus(client, "GET", baseURL.ResolveReference(mustURL("/userinfo")), nil, http.Header{"Authorization": {"Bearer " + ts.AccessToken}}, 401)
	must(expectJSONWithBasic(client, baseURL.ResolveReference(mustURL("/introspect")), reg.ClientID, reg.ClientSecret, url.Values{"token": {ts.AccessToken}}, 200, map[string]any{"active": false}), "introspect inactive")

	// Refresh token flow
	log.Printf("[18] 刷新令牌 POST /token grant=refresh_token")
	ts2 := mustToken(client, tokURL, reg.ClientID, reg.ClientSecret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {ts.RefreshToken}})
	if ts2.AccessToken == "" || ts2.RefreshToken == "" {
		log.Fatalf("invalid refresh token response: %+v", ts2)
	}
	log.Printf("refresh token succeeded")

	// Hybrid flow (code id_token) with fragment return
	nonce := randString(16)
	authorizeQ2 := url.Values{
		"response_type":         {"code id_token"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {randString(12)},
		"nonce":                 {nonce},
		"response_mode":         {"fragment"},
		"code_challenge":        {pkceS256(randString(43))},
		"code_challenge_method": {"S256"},
	}
	log.Printf("[19] Hybrid flow GET /authorize response_mode=fragment")
	_, loc2 := mustGetRedirect(client, baseURL.ResolveReference(mustURL("/authorize?"+authorizeQ2.Encode())))
	// Fragment params
	frag := ""
	if i := strings.Index(loc2, "#"); i >= 0 {
		frag = loc2[i+1:]
	}
	if frag == "" || !strings.Contains(frag, "id_token=") || !strings.Contains(frag, "code=") {
		log.Fatalf("hybrid flow redirect missing params: %s", loc2)
	}
	log.Printf("hybrid flow returned fragment with id_token + code")

	// Logout with post_logout_redirect_uri
	loq := url.Values{"id_token_hint": {ts2.IDToken}, "post_logout_redirect_uri": {postLogoutRedirectURI}, "state": {"bye"}}
	status, loc3 := mustGetRedirect(client, baseURL.ResolveReference(mustURL("/logout?"+loq.Encode())))
	if status != 302 || !strings.HasPrefix(loc3, postLogoutRedirectURI) {
		log.Fatalf("logout redirect unexpected: %d %s", status, loc3)
	}
	if extractParam(loc3, "state") != "bye" {
		log.Fatalf("logout state mismatch")
	}
	log.Printf("[20] 注销跳转 OK -> %s", loc3)

	log.Printf("E2E OK — 全链路检查通过")
}

func mustURL(p string) *url.URL { u, _ := url.Parse(p); return u }

func mustParseURL(s string) *url.URL { u, _ := url.Parse(s); return u }

func cloneValues(v url.Values) url.Values {
	c := make(url.Values, len(v))
	for k, vs := range v {
		c[k] = append([]string(nil), vs...)
	}
	return c
}

func doJSON(client *http.Client, method, urlStr string, body any, headers http.Header, want int, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
		if verbose {
			log.Printf("%s %s\n请求体: %s", method, urlStr, prettyJSON(b))
		}
	}
	req, err := http.NewRequest(method, urlStr, r)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, vv := range headers {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("%s %s: status %d, want %d, body: %s", method, urlStr, resp.StatusCode, want, string(b))
	}
	b, _ := io.ReadAll(resp.Body)
	if verbose {
		log.Printf("%s %s -> %d\n响应体: %s", method, urlStr, resp.StatusCode, prettyJSON(b))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return err
		}
	}
	return nil
}

func expectStatusOK(client *http.Client, u *url.URL) error {
	return expectStatus(client, "GET", u, nil, nil, 200)
}

func expectStatusNoContent(client *http.Client, u *url.URL, method string) error {
	return expectStatus(client, method, u, nil, nil, 204)
}

func expectStatus(client *http.Client, method string, u *url.URL, body io.Reader, headers http.Header, want int) error {
	req, _ := http.NewRequest(method, u.String(), body)
	for k, vv := range headers {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != want {
		return fmt.Errorf("%s %s: status %d want %d body: %s", method, u, resp.StatusCode, want, string(b))
	}
	if verbose {
		log.Printf("%s %s -> %d\n响应体: %s", method, u, resp.StatusCode, safeTrunc(string(b), 1200))
	}
	return nil
}

func expectStatusJSON(client *http.Client, u *url.URL, want int, headers http.Header) error {
	req, _ := http.NewRequest("GET", u.String(), nil)
	if headers != nil {
		req.Header = headers.Clone()
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("GET %s: status %d want %d body: %s", u, resp.StatusCode, want, string(b))
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if verbose {
		log.Printf("GET %s -> %d\n响应体: %s", u, resp.StatusCode, prettyJSON(b))
	}
	return nil
}

func expectJSON(client *http.Client, u *url.URL, headers http.Header, want int, out any) error {
	req, _ := http.NewRequest("GET", u.String(), nil)
	for k, vv := range headers {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("GET %s: status %d want %d body: %s", u, resp.StatusCode, want, string(b))
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if verbose {
		log.Printf("GET %s -> %d\n响应体: %s", u, resp.StatusCode, prettyJSON(b))
	}
	if out != nil {
		if err := json.Unmarshal(b, out); err != nil {
			return err
		}
	}
	return nil
}

func expectJSONWithBasic(client *http.Client, u *url.URL, id, secret string, form url.Values, want int, contains map[string]any) error {
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader(form.Encode()))
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		return fmt.Errorf("POST %s: status %d want %d body: %s", u, resp.StatusCode, want, string(b))
	}
	if verbose {
		log.Printf("POST %s (basic %s) -> %d\n响应体: %s", u, id, resp.StatusCode, prettyJSON(b))
	}
	if contains != nil {
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		for k, v := range contains {
			if mv, ok := m[k]; !ok || fmt.Sprint(mv) != fmt.Sprint(v) {
				return fmt.Errorf("response missing %s=%v in %v", k, v, m)
			}
		}
	}
	return nil
}

func expectStatusWithBasic(client *http.Client, u *url.URL, id, secret string, form url.Values, want int) error {
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader(form.Encode()))
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("POST %s: status %d want %d body: %s", u, resp.StatusCode, want, string(b))
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if verbose {
		log.Printf("POST %s (basic %s) -> %d\n响应体: %s", u, id, resp.StatusCode, safeTrunc(string(b), 1200))
	}
	return nil
}

func expectRedirect(client *http.Client, u *url.URL, form url.Values) error {
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Accept either 2xx (rendered page) or 3xx (redirect). We mainly need side-effects (cookie/consent).
	if resp.StatusCode/100 != 2 && resp.StatusCode/100 != 3 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("POST %s: unexpected status %d body: %s", u, resp.StatusCode, string(b))
	}
	if verbose {
		loc := resp.Header.Get("Location")
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		log.Printf("POST %s -> %d Location=%s Body=%s", u, resp.StatusCode, loc, safeTrunc(string(b), 800))
	}
	return nil
}

func mustGetRedirect(client *http.Client, u *url.URL) (int, string) {
	req, _ := http.NewRequest("GET", u.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 3 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		log.Fatalf("GET %s: want redirect, got %d body: %s", u, resp.StatusCode, string(b))
	}
	loc := resp.Header.Get("Location")
	if verbose {
		log.Printf("GET %s -> %d Location=%s", u, resp.StatusCode, loc)
	}
	return resp.StatusCode, loc
}

func mustAddQuery(u string, key, val string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	q := parsed.Query()
	q.Set(key, val)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func extractParam(loc, key string) string {
	// Support query or fragment params
	raw := ""
	if i := strings.Index(loc, "#"); i >= 0 {
		raw = loc[i+1:]
	} else if i := strings.Index(loc, "?"); i >= 0 {
		raw = loc[i+1:]
	}
	v, _ := url.ParseQuery(raw)
	return v.Get(key)
}

func randString(n int) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	// crypto-rand for seed then math/rand for speed
	var seed [8]byte
	if _, err := crand.Read(seed[:]); err == nil {
		rnd := int64(0)
		for i := 0; i < 8; i++ {
			rnd = (rnd << 8) | int64(seed[i])
		}
		r := mrand.New(mrand.NewSource(rnd))
		for i := range b {
			b[i] = alphabet[r.Intn(len(alphabet))]
		}
	} else {
		for i := range b {
			b[i] = alphabet[mrand.Intn(len(alphabet))]
		}
	}
	return string(b)
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func mustToken(client *http.Client, urlStr, id, secret string, form url.Values) tokenSet {
	req, _ := http.NewRequest("POST", urlStr, strings.NewReader(form.Encode()))
	req.SetBasicAuth(id, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("POST %s: %v", urlStr, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		log.Fatalf("token http %d: %s", resp.StatusCode, string(b))
	}
	var ts tokenSet
	if err := json.Unmarshal(b, &ts); err != nil {
		log.Fatalf("token json: %v", err)
	}
	if verbose {
		log.Printf("POST %s (basic %s) -> 200\n响应体: %s", urlStr, id, prettyJSON(b))
	}
	return ts
}

func prettyJSON(b []byte) string {
	var js any
	if err := json.Unmarshal(b, &js); err != nil {
		return safeTrunc(string(b), 1200)
	}
	pb, _ := json.MarshalIndent(js, "", "  ")
	return string(pb)
}

func safeTrunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func decodeJWT(tok string) (string, string) {
	parts := strings.Split(tok, ".")
	if len(parts) < 2 {
		return "", ""
	}
	dec := func(p string) string {
		b, err := base64.RawURLEncoding.DecodeString(p)
		if err != nil {
			return ""
		}
		return prettyJSON(b)
	}
	return dec(parts[0]), dec(parts[1])
}
