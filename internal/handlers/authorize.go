package handlers

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"encoding/json"
	"github.com/gin-gonic/gin"

	"ginkgoid/internal/metrics"
	"ginkgoid/internal/services"
	"ginkgoid/internal/storage"
	"ginkgoid/internal/utils"
)

// @Summary      授权端点（Authorization）
// @Description  实现授权码 + PKCE 及可选 Hybrid 流程
// @Tags         oauth2
// @Produce      html
// @Param        response_type   query string true  "code 或 code id_token"
// @Param        client_id       query string true  "客户端 ID"
// @Param        redirect_uri    query string true  "重定向 URI"
// @Param        scope           query string true  "openid 等空格分隔"
// @Param        state           query string false "状态参数"
// @Param        nonce           query string false "Hybrid 必需"
// @Param        response_mode   query string false "fragment|form_post|query"
// @Param        code_challenge  query string false "PKCE 挑战"
// @Param        code_challenge_method query string false "S256|plain"
// @Param        prompt          query string false "none|login|consent"
// @Param        acr_values      query string false "ACR 要求"
// @Success      302 {string} string "重定向到 redirect_uri"
// @Failure      400 {object} map[string]string
// @Router       /authorize [get]
func (h *Handler) authorize(c *gin.Context) {
	responseType := c.Query("response_type")
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	scope := c.Query("scope")
	state := c.Query("state")
	nonce := c.Query("nonce")
	responseMode := c.Query("response_mode")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	prompt := c.Query("prompt")
	acrValues := c.Query("acr_values")
	rt0 := strings.TrimSpace(responseType)
	if !(rt0 == "code" || rt0 == "code id_token" || rt0 == "id_token code") {
		metrics.AuthorizeErrors.WithLabelValues("unsupported_response_type").Inc()
		cid := clientID
		h.logSvc.Write(c, "WARN", "AUTHORIZE_ERROR", nil, &cid, "unsupported_response_type", c.ClientIP())
		h.redirectError(c, redirectURI, "unsupported_response_type", state)
		return
	}
	if !strings.Contains(" "+scope+" ", " openid ") {
		metrics.AuthorizeErrors.WithLabelValues("invalid_scope").Inc()
		cid := clientID
		h.logSvc.Write(c, "WARN", "AUTHORIZE_ERROR", nil, &cid, "invalid_scope", c.ClientIP())
		h.redirectError(c, redirectURI, "invalid_scope", state)
		return
	}
	cl, err := h.clientSvc.FindByID(c, clientID)
	if err != nil {
		metrics.AuthorizeErrors.WithLabelValues("unauthorized_client").Inc()
		c.JSON(400, gin.H{"error": "unauthorized_client"})
		return
	}
	if !redirectURIMatches(cl, redirectURI) {
		metrics.AuthorizeErrors.WithLabelValues("redirect_uri_mismatch").Inc()
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "redirect_uri mismatch"})
		return
	}
	sid := readSessionCookie(c, h.cfg.Session.CookieName)
	var sess *services.Session
	if sid != "" {
		if s, err := h.sessionSvc.Get(c, sid); err == nil {
			sess = s
		}
	}
	if sess == nil || strings.Contains(prompt, "login") {
		if prompt == "none" {
			metrics.AuthorizeErrors.WithLabelValues("login_required").Inc()
			h.redirectError(c, redirectURI, "login_required", state)
			return
		}
		c.HTML(http.StatusOK, "login.html", gin.H{"params": c.Request.URL.Query(), "csrf": h.issueCSRF(c)})
		return
	}
	if acrValues != "" {
		required := strings.Fields(acrValues)
		ok := false
		for _, r := range required {
			if r == sess.ACR {
				ok = true
				break
			}
		}
		if !ok {
			metrics.AuthorizeErrors.WithLabelValues("acr_unmet").Inc()
			h.redirectError(c, redirectURI, "unmet_authentication_requirements", state)
			return
		}
	}
	if mv := c.Query("max_age"); mv != "" {
		if sec, err := strconv.Atoi(mv); err == nil && sec >= 0 {
			if time.Since(sess.AuthTime) > time.Duration(sec)*time.Second {
				if prompt == "none" {
					metrics.AuthorizeErrors.WithLabelValues("login_required_stale").Inc()
					h.redirectError(c, redirectURI, "login_required", state)
					return
				}
				c.HTML(http.StatusOK, "login.html", gin.H{"params": c.Request.URL.Query(), "csrf": h.issueCSRF(c)})
				return
			}
		}
	}
	approved := c.Query("consent") == "approve"
	prior := h.consentSvc.HasConsent(c, sess.UserID, cl.ClientID, scope)
	needConsent := !prior || strings.Contains(prompt, "consent")
	if !approved && needConsent {
		if prompt == "none" {
			metrics.AuthorizeErrors.WithLabelValues("consent_required").Inc()
			h.redirectError(c, redirectURI, "consent_required", state)
			return
		}
		_, scopes := splitScope(scope)
		c.HTML(http.StatusOK, "consent.html", gin.H{"client_name": cl.Name, "scopes": scopes, "params": c.Request.URL.Query(), "csrf": h.issueCSRF(c)})
		return
	}
	if codeChallenge == "" {
		metrics.AuthorizeErrors.WithLabelValues("pkce_missing").Inc()
		h.redirectError(c, redirectURI, "invalid_request", state)
		return
	}
	if h.cfg.Token.RequirePKCES256 && strings.ToUpper(codeChallengeMethod) != "S256" {
		h.redirectError(c, redirectURI, "invalid_request", state)
		return
	}
	ac, err := h.codeSvc.New(c, cl.ClientID, sess.UserID, redirectURI, scope, nonce, sess.SID, codeChallenge, codeChallengeMethod)
	if err != nil {
		c.String(500, "server_error")
		return
	}
	_ = h.rdb.SAdd(c, "sid:clients:"+sess.SID, cl.ClientID).Err()
	rt := strings.TrimSpace(responseType)
	if rt == "code id_token" || rt == "id_token code" {
		if nonce == "" {
			metrics.AuthorizeErrors.WithLabelValues("nonce_missing").Inc()
			h.redirectError(c, redirectURI, "invalid_request", state)
			return
		}
		ch := utils.CHash(ac.Code)
		extra := map[string]interface{}{"sid": sess.SID, "azp": cl.ClientID, "c_hash": ch}
		if u, err := h.userSvc.FindByID(c, sess.UserID); err == nil {
			if strings.Contains(scope, "profile") {
				if u.Name != "" {
					extra["name"] = u.Name
				}
				if u.Username != "" {
					extra["preferred_username"] = u.Username
				}
				if !u.UpdatedAt.IsZero() {
					extra["updated_at"] = u.UpdatedAt.Unix()
				}
			}
			if strings.Contains(scope, "email") {
				if u.Email != "" {
					extra["email"] = u.Email
				}
				extra["email_verified"] = u.EmailVerified
			}
		}
		idt, err := h.tokenSvc.BuildIDToken(cl.ClientID, h.subjectFor(cl, sess.UserID), nonce, sess.ACR, "", sess.AuthTime, extra)
		if err != nil {
			c.String(500, "server_error")
			return
		}
		mode := responseMode
		if mode == "" {
			mode = "fragment"
		}
		switch mode {
		case "form_post":
			var b strings.Builder
			b.WriteString("<html><body><form method=\"post\" action=\"")
			b.WriteString(redirectURI)
			b.WriteString("\">")
			b.WriteString("<input type=\\\"hidden\\\" name=\\\"code\\\" value=\\\"")
			b.WriteString(ac.Code)
			b.WriteString("\\\"/>")
			if state != "" {
				b.WriteString("<input type=\\\"hidden\\\" name=\\\"state\\\" value=\\\"")
				b.WriteString(state)
				b.WriteString("\\\"/>")
			}
			b.WriteString("<input type=\\\"hidden\\\" name=\\\"id_token\\\" value=\\\"")
			b.WriteString(idt)
			b.WriteString("\\\"/>")
			b.WriteString("<noscript><button type=\\\"submit\\\">Continue</button></noscript></form><script>document.forms[0].submit();</script></body></html>")
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(b.String()))
			return
		case "fragment":
			v := url.Values{}
			v.Set("code", ac.Code)
			if state != "" {
				v.Set("state", state)
			}
			v.Set("id_token", idt)
			c.Redirect(http.StatusFound, redirectURI+"#"+v.Encode())
			return
		default:
			v := url.Values{}
			v.Set("code", ac.Code)
			if state != "" {
				v.Set("state", state)
			}
			v.Set("id_token", idt)
			c.Redirect(http.StatusFound, redirectURI+"#"+v.Encode())
			return
		}
	} else {
		if strings.EqualFold(responseMode, "form_post") {
			var b strings.Builder
			b.WriteString("<html><body><form method=\"post\" action=\"")
			b.WriteString(redirectURI)
			b.WriteString("\">")
			b.WriteString("<input type=\\\"hidden\\\" name=\\\"code\\\" value=\\\"")
			b.WriteString(ac.Code)
			b.WriteString("\\\"/>")
			if state != "" {
				b.WriteString("<input type=\\\"hidden\\\" name=\\\"state\\\" value=\\\"")
				b.WriteString(state)
				b.WriteString("\\\"/>")
			}
			b.WriteString("<noscript><button type=\\\"submit\\\">Continue</button></noscript></form><script>document.forms[0].submit();</script></body></html>")
			c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(b.String()))
			return
		}
		sep := "?"
		if strings.Contains(redirectURI, "?") {
			sep = "&"
		}
		loc := redirectURI + sep + "code=" + ac.Code
		if state != "" {
			loc += "&state=" + urlQueryEscape(state)
		}
		c.Redirect(http.StatusFound, loc)
	}
}

// subjectFor 按 subject_type 与 sector_identifier_uri 规则为指定客户端与用户计算 sub 值。
func (h *Handler) subjectFor(cl *storage.Client, userID uint64) string {
	if !h.cfg.Pairwise.Enable || strings.ToLower(cl.SubjectType) != "pairwise" {
		return strconv.FormatUint(userID, 10)
	}
	sector := sectorHostForClient(cl)
	return utils.PairwiseSub(sector, userID, h.cfg.Pairwise.Salt)
}

func sectorHostForClient(cl *storage.Client) string {
	if cl.SectorIdentifierURI != "" {
		if u, err := url.Parse(cl.SectorIdentifierURI); err == nil {
			return u.Host
		}
	}
	var list []string
	_ = json.Unmarshal([]byte(cl.RedirectURIs), &list)
	if len(list) == 0 {
		return ""
	}
	if u, err := url.Parse(list[0]); err == nil {
		return u.Host
	}
	return ""
}
