// 命令行工具：本地端到端（authorize → token → userinfo）串联测试。
// 依赖环境变量：BASE_URL/CLIENT_ID/CLIENT_NAME/REDIRECT_URI；若未提供使用默认值。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"ginkgoid/internal/infra/config"
	"ginkgoid/internal/infra/db"
	"ginkgoid/internal/model/entity"
	svcclient "ginkgoid/internal/service/client"
)

func main() {
	base := getenv("BASE_URL", "http://localhost:8080")
	clientID := getenv("CLIENT_ID", "demo")
	name := getenv("CLIENT_NAME", "DemoApp")
	redirect := getenv("REDIRECT_URI", "http://localhost:8081/callback")

	// 确保客户端存在（如不存在则创建为公共客户端）
	must(config.Load())
	must(db.Init(config.C().DB))
	defer db.Close()
	ru, _ := json.Marshal([]string{redirect})
	must(svcclient.EnsureClient(context.Background(), entity.Client{ClientID: clientID, Name: name, RedirectURIs: string(ru), Status: 1}))

	// 准备 PKCE
	verifier := randB64URL(32)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	state := "xyz"
	nonce := "n1"
	authPath := "/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=" + url.QueryEscape(redirect) +
		"&scope=" + url.QueryEscape("openid profile email") +
		"&state=" + url.QueryEscape(state) +
		"&nonce=" + url.QueryEscape(nonce) +
		"&code_challenge=" + url.QueryEscape(challenge) +
		"&code_challenge_method=S256"

	// 使用引导管理员账号完成登录
	loginURL := base + "/login?continue=" + url.QueryEscape(authPath)
	// GET login page
	mustHTTPGet(loginURL)
	// POST credentials
	username := config.C().Admin.Bootstrap.Username
	password := config.C().Admin.Bootstrap.Password
	body := url.Values{}
	body.Set("username", username)
	body.Set("password", password)
	body.Set("continue", authPath)
	resp := mustHTTPPostForm(base+"/login", body)
	fmt.Println("/login status:", resp.Status)
	fmt.Println("/login headers:")
	for k, v := range resp.Header {
		fmt.Println(" ", k, v)
	}
	lb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(lb) > 0 {
		fmt.Println("/login body:", string(lb))
	}
	sid := readSessionCookie(resp)
	if sid == "" {
		die("未获取到会话 Cookie；请检查 cookie_domain/secure_cookies 本地配置")
	}
	// 如登录直接 302 到 /authorize，则跟进一次以建立上下文
	loc := resp.Header.Get("Location")
	code := ""
	if loc != "" {
		ar := mustHTTPGetWithCookieAndAuth(base+loc, sid, "")
		fmt.Println("/authorize status:", ar.Status)
		for k, v := range ar.Header {
			fmt.Println(" ", k, v)
		}
		if l2 := ar.Header.Get("Location"); l2 != "" {
			u2, _ := url.Parse(l2)
			code = u2.Query().Get("code")
		}
	}
	if code == "" {
		// 兜底：直接 POST /consent 完成同意
		cvals := url.Values{}
		cvals.Set("client_id", clientID)
		cvals.Set("redirect_uri", redirect)
		cvals.Set("state", state)
		cvals.Set("nonce", nonce)
		cvals.Set("scope", "openid profile email")
		cvals.Set("code_challenge", challenge)
		cvals.Set("code_challenge_method", "S256")
		cvals.Set("remember", "1")
		cvals.Set("sid", sid)
		code = doConsent(base+"/consent", cvals, sid)
	}
	if code == "" {
		die("failed to get code from authorize/consent redirect")
	}
	fmt.Println("Auth code:", code)

	// 兑换 Token
	tv := url.Values{}
	tv.Set("grant_type", "authorization_code")
	tv.Set("code", code)
	tv.Set("redirect_uri", redirect)
	tv.Set("code_verifier", verifier)
	tv.Set("client_id", clientID)
	r := mustHTTPPostForm(base+"/token", tv)
	tokBody := mustReadAll(r.Body)
	fmt.Println("Token response:", string(tokBody))

	// 解析 access_token 并访问 /userinfo
	var tok map[string]any
	_ = json.Unmarshal(tokBody, &tok)
	at, _ := tok["access_token"].(string)
	if at == "" {
		die("no access_token in response")
	}
	ui := mustHTTPGetWithCookieAndAuth(base+"/userinfo", sid, at)
	fmt.Println("UserInfo:", string(mustReadAll(ui.Body)))
}

func getenv(k, def string) string {
	v := os.Getenv(k)
	if v == "" {
		return def
	}
	return v
}
func die(msg string) { fmt.Fprintln(os.Stderr, msg); os.Exit(1) }
func must(err error) {
	if err != nil {
		die(err.Error())
	}
}

func randB64URL(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		die(err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func mustHTTPGet(u string) *http.Response {
	req, _ := http.NewRequest("GET", u, nil)
	resp, err := http.DefaultClient.Do(req)
	must(err)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func mustHTTPGetWithCookieAndAuth(u, sid, at string) *http.Response {
	req, _ := http.NewRequest("GET", u, nil)
	if sid != "" {
		req.Header.Set("Cookie", "gid_session="+sid)
	}
	if at != "" {
		req.Header.Set("Authorization", "Bearer "+at)
	}
	hc := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	must(err)
	return resp
}

func mustHTTPPostForm(u string, v url.Values) *http.Response {
	req, _ := http.NewRequest("POST", u, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Do not follow redirects so we can read Set-Cookie from 302 response
	hc := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	must(err)
	return resp
}

func mustReadAll(rc io.ReadCloser) []byte {
	defer rc.Close()
	b, err := io.ReadAll(rc)
	must(err)
	return b
}

func readSessionCookie(resp *http.Response) string {
	for _, sc := range resp.Cookies() {
		if sc.Name == "gid_session" && sc.Value != "" {
			return sc.Value
		}
	}
	// fallback: parse raw Set-Cookie header if domain mismatch prevents stdlib from parsing
	for _, raw := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(raw, "gid_session=") {
			semi := strings.IndexByte(raw, ';')
			if semi > 0 {
				return raw[len("gid_session="):semi]
			}
		}
	}
	return ""
}

func doConsent(u string, v url.Values, sid string) string {
	req, _ := http.NewRequest("POST", u, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if sid != "" {
		req.Header.Set("Cookie", "gid_session="+sid)
	}
	// prevent following redirect to external redirect_uri so we can read Location
	hc := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	must(err)
	fmt.Println("/consent status:", resp.Status)
	for k, vv := range resp.Header {
		fmt.Println(" ", k, vv)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u2, _ := url.Parse(loc)
	q := u2.Query()
	return q.Get("code")
}
