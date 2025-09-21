package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

	"golang.org/x/net/html"
)

var verbose bool
var baseURL *url.URL

// scenario 封装一次端到端巡检过程中共享的资源。
type scenario struct {
	client        *http.Client
	initialAccess string
}

func banner(title string) {
	log.Printf("\n=== %s ===", title)
}

func step(format string, args ...interface{}) {
	log.Printf(" • "+format, args...)
}

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

func main() {
	var (
		base          string
		username      string
		password      string
		initialAccess string
		timeout       time.Duration
	)

	flag.StringVar(&base, "base", "http://127.0.0.1:8080", "Base URL of GinkgoID server (issuer)")
	flag.StringVar(&username, "username", "e2e_user", "Username prefix to create/login for e2e test")
	flag.StringVar(&password, "password", "P@ssw0rd9", "Password for the e2e user")
	flag.StringVar(&initialAccess, "iat", "", "Initial access token for /register if configured")
	flag.DurationVar(&timeout, "timeout", 20*time.Second, "HTTP timeout for requests")
	flag.BoolVar(&verbose, "v", true, "Verbose logging")
	flag.Parse()

	var err error
	baseURL, err = url.Parse(strings.TrimRight(base, "/"))
	if err != nil {
		log.Fatalf("parse base url: %v", err)
	}

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: timeout}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		if req.URL.Host == baseURL.Host {
			return nil
		}
		// 当跳转到外部 redirect_uri 时，保留 302 供调用方解析 code
		return http.ErrUseLastResponse
	}

	sc := &scenario{client: client, initialAccess: initialAccess}
	sc.run(username, password)
}

func (s *scenario) run(usernamePrefix, password string) {
	must := func(err error, msg string) {
		if err != nil {
			log.Fatalf("%s: %v", msg, err)
		}
	}

	log.Printf("E2E start -> %s", baseURL)

	banner("Bootstrap & Health Checks")
	step("Discover OIDC metadata")
	must(expectStatusJSON(s.client, baseURL.ResolveReference(mustURL("/.well-known/openid-configuration")), 200, nil), "discovery")
	step("Fetch JWKS")
	must(expectStatusOK(s.client, baseURL.ResolveReference(mustURL("/jwks.json"))), "jwks")
	step("Probe /healthz")
	must(expectStatusOK(s.client, baseURL.ResolveReference(mustURL("/healthz"))), "healthz")
	step("Probe /metrics")
	must(expectStatusOK(s.client, baseURL.ResolveReference(mustURL("/metrics"))), "metrics")
	step("Render check_session iframe")
	must(expectStatusOK(s.client, baseURL.ResolveReference(mustURL("/check_session"))), "check_session")
	step("Render Stoplight docs (best effort)")
	_ = expectStatusOK(s.client, baseURL.ResolveReference(mustURL("/docs")))

	banner("Scaffold Test User")
	uname := fmt.Sprintf("%s_%d", usernamePrefix, time.Now().UnixNano())
	email := uname + "@example.com"
	userReq := map[string]string{"username": uname, "password": password, "email": email, "name": "E2E User"}
	step("Create dev user %s", uname)
	must(doJSON(s.client, "POST", baseURL.ResolveReference(mustURL("/dev/users")).String(), userReq, nil, 201, nil), "dev create user")
	step("List dev users")
	must(expectStatusJSON(s.client, baseURL.ResolveReference(mustURL("/dev/users")), 200, nil), "dev list users")
	step("Rotate signing keys (dev helper)")
	_ = expectStatusNoContent(s.client, baseURL.ResolveReference(mustURL("/dev/keys/rotate")), "POST")

	banner("Dynamic Client Registration")
	redirectURI := "http://127.0.0.1:9999/cb"
	postLogoutURI := "http://127.0.0.1:9999/post-logout"
	reg := s.registerClient(redirectURI, postLogoutURI)

	banner("Authorization Code + PKCE Flow")
	tokens, codeVerifier, state := s.runAuthorizeCodePKCE(reg, uname, password, redirectURI)

	banner("Console APIs & Consents")
	step("GET /api/me (expect username %s)", uname)
	var me map[string]any
	must(expectJSON(s.client, baseURL.ResolveReference(mustURL("/api/me")), nil, 200, &me), "api me")
	if got := fmt.Sprint(me["username"]); got != uname {
		log.Fatalf("api/me username mismatch: want %s got %s", uname, got)
	}

	step("GET /api/consents (ensure client has consent)")
	var consents []map[string]any
	must(expectJSON(s.client, baseURL.ResolveReference(mustURL("/api/consents")), nil, 200, &consents), "api consents")
	foundConsent := false
	for _, c := range consents {
		if fmt.Sprint(c["client_id"]) == reg.ClientID {
			foundConsent = true
			break
		}
	}
	if !foundConsent {
		log.Fatalf("consent for client %s not found in /api/consents", reg.ClientID)
	}

	banner("Token Lifecycle & Introspection")
	step("GET /userinfo with Bearer access token")
	must(expectJSON(s.client, baseURL.ResolveReference(mustURL("/userinfo")), http.Header{"Authorization": {"Bearer " + tokens.AccessToken}}, 200, nil), "userinfo bearer")
	form := url.Values{"access_token": {tokens.AccessToken}}
	step("POST /userinfo form exchange")
	must(expectStatus(s.client, "POST", baseURL.ResolveReference(mustURL("/userinfo")), strings.NewReader(form.Encode()), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}, 200), "userinfo form")

	step("POST /introspect (expect active=true)")
	must(expectJSONWithBasic(s.client, baseURL.ResolveReference(mustURL("/introspect")), reg.ClientID, reg.ClientSecret, url.Values{"token": {tokens.AccessToken}}, 200, map[string]any{"active": true}), "introspect active")

	step("POST /revoke access token, expect userinfo 401 afterwards")
	must(expectStatusWithBasic(s.client, baseURL.ResolveReference(mustURL("/revoke")), reg.ClientID, reg.ClientSecret, url.Values{"token": {tokens.AccessToken}, "token_type_hint": {"access_token"}}, 200), "revoke access")
	_ = expectStatus(s.client, "GET", baseURL.ResolveReference(mustURL("/userinfo")), nil, http.Header{"Authorization": {"Bearer " + tokens.AccessToken}}, 401)
	step("POST /introspect again (expect inactive)")
	must(expectJSONWithBasic(s.client, baseURL.ResolveReference(mustURL("/introspect")), reg.ClientID, reg.ClientSecret, url.Values{"token": {tokens.AccessToken}}, 200, map[string]any{"active": false}), "introspect inactive")

	step("POST /token grant=refresh_token")
	tokURL := baseURL.ResolveReference(mustURL("/token")).String()
	refreshed := mustToken(s.client, tokURL, reg.ClientID, reg.ClientSecret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}})
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" {
		log.Fatalf("refresh token response incomplete: %+v", refreshed)
	}

	banner("Hybrid Flow (code id_token)")
	s.runHybridFlow(reg, redirectURI)

	banner("Logout & Completion")
	step("GET /logout with id_token_hint -> %s", postLogoutURI)
	loq := url.Values{"id_token_hint": {refreshed.IDToken}, "post_logout_redirect_uri": {postLogoutURI}, "state": {"bye"}}
	status, loc := mustGetRedirect(s.client, baseURL.ResolveReference(mustURL("/logout?"+loq.Encode())))
	if status != 302 || !strings.HasPrefix(loc, postLogoutURI) {
		log.Fatalf("unexpected logout redirect: %d %s", status, loc)
	}
	if extractParam(loc, "state") != "bye" {
		log.Fatalf("logout state mismatch")
	}

	log.Printf("\nE2E OK — 全链路检查通过 (state=%s, verifier len=%d)\n", state, len(codeVerifier))
}

func (s *scenario) registerClient(redirectURI, postLogoutURI string) clientInfo {
	regBody := map[string]any{
		"client_name":                "e2e-client",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code", "code id_token"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      "openid profile email offline_access",
		"post_logout_redirect_uris":  []string{postLogoutURI},
		"frontchannel_logout_uri":    "http://127.0.0.1:9999/front-logout",
		"backchannel_logout_uri":     "http://127.0.0.1:9999/back-logout",
		"subject_type":               "public",
	}
	headers := http.Header{}
	if s.initialAccess != "" {
		headers.Set("Authorization", "Bearer "+s.initialAccess)
	}
	var reg clientInfo
	step("POST /register (dynamic client)")
	must := func(err error, msg string) {
		if err != nil {
			log.Fatalf("%s: %v", msg, err)
		}
	}
	must(doJSON(s.client, "POST", baseURL.ResolveReference(mustURL("/register")).String(), regBody, headers, 201, &reg), "register client")
	if reg.ClientID == "" || reg.RegistrationAccessToken == "" {
		log.Fatalf("invalid register response: %+v", reg)
	}
	regH := http.Header{"Authorization": {"Bearer " + reg.RegistrationAccessToken}}
	step("GET /register details")
	must(expectStatusJSON(s.client, mustParseURL(mustAddQuery(reg.RegistrationClientURI, "client_id", reg.ClientID)), 200, regH), "get registered client")
	upd := map[string]any{"client_name": "e2e-client-updated"}
	step("PUT /register update name")
	must(doJSON(s.client, "PUT", mustAddQuery(reg.RegistrationClientURI, "client_id", reg.ClientID), upd, regH, 204, nil), "update registered client")
	rotateURL := baseURL.ResolveReference(mustURL("/register/rotate")).String() + "?client_id=" + url.QueryEscape(reg.ClientID)
	step("POST /register/rotate")
	var rotated map[string]string
	must(doJSON(s.client, "POST", rotateURL, nil, regH, 200, &rotated), "rotate registration token")
	if t := rotated["registration_access_token"]; t != "" {
		reg.RegistrationAccessToken = t
	}
	return reg
}

func (s *scenario) runAuthorizeCodePKCE(reg clientInfo, username, password, redirectURI string) (tokenSet, string, string) {
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
	authURL := baseURL.ResolveReference(mustURL("/authorize?" + authorizeQ.Encode()))

	step("GET /authorize to obtain login form")
	status, hidden, body, err := fetchHiddenForm(s.client, authURL)
	if err != nil {
		log.Fatalf("load login form: %v", err)
	}
	if status != 200 {
		log.Fatalf("unexpected status fetching login: %d body=%s", status, safeTrunc(string(body), 600))
	}
	if hidden.Get("csrf_token") == "" {
		log.Fatalf("login form missing csrf token")
	}
	loginForm := cloneValues(hidden)
	loginForm.Set("username", username)
	loginForm.Set("password", password)

	step("POST /login with credentials & CSRF")
	_, _, err = postFormExpect(s.client, baseURL.ResolveReference(mustURL("/login")), loginForm, []int{200, 302})
	if err != nil {
		log.Fatalf("login submit: %v", err)
	}

	step("GET /authorize again for consent page")
	status, hidden, body, err = fetchHiddenForm(s.client, authURL)
	if err != nil {
		log.Fatalf("load consent form: %v", err)
	}
	if status == 200 {
		if hidden.Get("csrf_token") == "" {
			log.Fatalf("consent form missing csrf token")
		}
		consentForm := cloneValues(hidden)
		consentForm.Set("decision", "approve")
		step("POST /consent approve (with CSRF)")
		_, _, err = postFormExpect(s.client, baseURL.ResolveReference(mustURL("/consent")), consentForm, []int{302})
		if err != nil {
			log.Fatalf("consent submit: %v", err)
		}
	} else if status/100 == 3 {
		// 已存在 consentimiento，允许继续
		if verbose {
			log.Printf("consent skipped (status %d)", status)
		}
	} else {
		log.Fatalf("unexpected consent status: %d body=%s", status, safeTrunc(string(body), 600))
	}

	step("GET /authorize final redirect (expect code)")
	status, loc := mustGetRedirect(s.client, authURL)
	if status/100 != 3 {
		log.Fatalf("expected redirect for code, got %d", status)
	}
	code := extractParam(loc, "code")
	if code == "" {
		log.Fatalf("missing authorization code in %s", loc)
	}
	if got := extractParam(loc, "state"); got != state {
		log.Fatalf("state mismatch: want %s got %s", state, got)
	}

	tokURL := baseURL.ResolveReference(mustURL("/token")).String()
	tokens := mustToken(s.client, tokURL, reg.ClientID, reg.ClientSecret, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {codeVerifier},
	})
	if tokens.AccessToken == "" || tokens.IDToken == "" {
		log.Fatalf("invalid token response: %+v", tokens)
	}
	if verbose {
		if head, claims := decodeJWT(tokens.IDToken); head != "" {
			log.Printf("ID Token header: %s", head)
			log.Printf("ID Token claims: %s", claims)
		}
	}
	return tokens, codeVerifier, state
}

func (s *scenario) runHybridFlow(reg clientInfo, redirectURI string) {
	codeVerifier := randString(64)
	authorizeQ2 := url.Values{
		"response_type":         {"code id_token"},
		"client_id":             {reg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {randString(12)},
		"nonce":                 {randString(16)},
		"response_mode":         {"fragment"},
		"code_challenge":        {pkceS256(codeVerifier)},
		"code_challenge_method": {"S256"},
	}
	authURL := baseURL.ResolveReference(mustURL("/authorize?" + authorizeQ2.Encode()))
	step("GET /authorize hybrid response (fragment)")
	_, loc := mustGetRedirect(s.client, authURL)
	frag := ""
	if i := strings.Index(loc, "#"); i >= 0 {
		frag = loc[i+1:]
	}
	if frag == "" || !strings.Contains(frag, "id_token=") || !strings.Contains(frag, "code=") {
		log.Fatalf("hybrid flow redirect missing params: %s", loc)
	}
}

func fetchHiddenForm(client *http.Client, u *url.URL) (int, url.Values, []byte, error) {
	req, _ := http.NewRequest("GET", u.String(), nil)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if verbose {
		log.Printf("GET %s -> %d", u, resp.StatusCode)
	}
	if resp.StatusCode != 200 {
		return resp.StatusCode, nil, body, nil
	}
	inputs, err := parseHiddenInputs(body)
	if err != nil {
		return resp.StatusCode, nil, body, err
	}
	return resp.StatusCode, inputs, body, nil
}

func parseHiddenInputs(body []byte) (url.Values, error) {
	doc, err := html.Parse(bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	var walker func(*html.Node)
	walker = func(n *html.Node) {
		if n.Type == html.ElementNode && strings.EqualFold(n.Data, "input") {
			var name, value, inputType, classAttr string
			for _, attr := range n.Attr {
				switch strings.ToLower(attr.Key) {
				case "name":
					name = attr.Val
				case "value":
					value = attr.Val
				case "type":
					inputType = strings.ToLower(attr.Val)
				case "class":
					classAttr = attr.Val
				}
			}
			if name != "" && (inputType == "hidden" || hasClass(classAttr, "kv")) {
				values.Add(name, value)
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walker(c)
		}
	}
	walker(doc)
	return values, nil
}

func hasClass(classAttr, want string) bool {
	for _, part := range strings.Fields(classAttr) {
		if part == want {
			return true
		}
	}
	return false
}

func postFormExpect(client *http.Client, u *url.URL, form url.Values, want []int) (int, string, error) {
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if len(want) > 0 && !statusAllowed(resp.StatusCode, want) {
		return resp.StatusCode, resp.Header.Get("Location"), fmt.Errorf("POST %s: status %d want %v body: %s", u, resp.StatusCode, want, safeTrunc(string(body), 800))
	}
	if verbose {
		log.Printf("POST %s -> %d Location=%s Body=%s", u, resp.StatusCode, resp.Header.Get("Location"), safeTrunc(string(body), 800))
	}
	return resp.StatusCode, resp.Header.Get("Location"), nil
}

func statusAllowed(status int, want []int) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if status == w {
			return true
		}
	}
	return false
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
	var seed [8]byte
	if _, err := rand.Read(seed[:]); err == nil {
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
