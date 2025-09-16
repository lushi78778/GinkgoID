package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ginkgoid/internal/storage"

	"ginkgoid/internal/services"

	"github.com/gin-gonic/gin"
)

// @Summary      注销（RP-Initiated Logout）
// @Description  清理 OP 会话并通知已登录 RP；可选重定向
// @Tags         session-management
// @Produce      html
// @Param        id_token_hint            query string false "RP 提供的 ID Token"
// @Param        post_logout_redirect_uri query string false "注销后重定向 URI"
// @Param        state                    query string false "重定向回传状态"
// @Success      200 {string} string "HTML 或 302 重定向"
// @Router       /logout [get]
func (h *Handler) logout(c *gin.Context) {
	idTokenHint := c.Query("id_token_hint")
	postLogoutRedirectURI := c.Query("post_logout_redirect_uri")
	state := c.Query("state")
	var hintAud, hintSub string
	if idTokenHint != "" {
		if claims, err := h.tokenSvc.VerifyJWT(idTokenHint); err == nil {
			switch v := claims["aud"].(type) {
			case string:
				hintAud = v
			case []any:
				if len(v) > 0 {
					if s, ok := v[0].(string); ok {
						hintAud = s
					}
				}
			}
			if s, ok := claims["sub"].(string); ok {
				hintSub = s
			}
		}
	}
	sid := readSessionCookie(c, h.cfg.Session.CookieName)
	if sid != "" {
		_ = h.sessionSvc.Delete(c, sid)
	}
	if sid != "" {
		go h.notifyBackchannel(c.Request.Context(), sid, hintSub)
	}
	if postLogoutRedirectURI != "" && hintAud != "" {
		if cl, err := h.clientSvc.FindByID(c, hintAud); err == nil && logoutRedirectAllowed(cl, postLogoutRedirectURI) {
			sep := "?"
			if strings.Contains(postLogoutRedirectURI, "?") {
				sep = "&"
			}
			loc := postLogoutRedirectURI
			if state != "" {
				loc = loc + sep + "state=" + urlQueryEscape(state)
			}
			c.Redirect(302, loc)
			return
		}
	}
	ip := c.ClientIP()
	h.logSvc.Write(c, "INFO", "USER_LOGOUT", nil, nil, "logout", ip, services.LogWriteOpts{
		RequestID: c.GetString("request_id"),
		SessionID: sid,
		Method:    c.Request.Method,
		Path:      c.Request.URL.Path,
		Status:    http.StatusOK,
		UserAgent: c.Request.UserAgent(),
		Outcome:   "success",
	})
	urls := []string{}
	if sid != "" {
		ids, _ := h.rdb.SMembers(c, "sid:clients:"+sid).Result()
		for _, cid := range ids {
			if cl, err := h.clientSvc.FindByID(c, cid); err == nil && cl.FrontchannelLogoutURI != "" {
				u := cl.FrontchannelLogoutURI
				sep2 := "?"
				if strings.Contains(u, "?") {
					sep2 = "&"
				}
				u = u + sep2 + "sid=" + urlQueryEscape(sid) + "&iss=" + urlQueryEscape(h.cfg.Issuer)
				urls = append(urls, u)
			}
		}
	}
	c.HTML(http.StatusOK, "frontchannel_logout.html", gin.H{"iframes": urls})
}

func logoutRedirectAllowed(cl *storage.Client, uri string) bool {
	if cl.PostLogoutRedirectURIs == "" {
		return false
	}
	var list []string
	_ = json.Unmarshal([]byte(cl.PostLogoutRedirectURIs), &list)
	for _, v := range list {
		if v == uri {
			return true
		}
	}
	return false
}

func (h *Handler) notifyBackchannel(ctx context.Context, sid string, subject string) {
	ids, err := h.rdb.SMembers(ctx, "sid:clients:"+sid).Result()
	if err != nil || len(ids) == 0 {
		return
	}
	httpc := &http.Client{Timeout: 3 * time.Second}
	for _, cid := range ids {
		cl, err := h.clientSvc.FindByID(ctx, cid)
		if err != nil || cl.BackchannelLogoutURI == "" {
			continue
		}
		lt, err := h.tokenSvc.BuildLogoutToken(cl.ClientID, subject, sid)
		if err != nil {
			continue
		}
		form := url.Values{"logout_token": {lt}}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, cl.BackchannelLogoutURI, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for attempt := 0; attempt < 3; attempt++ {
			resp, err := httpc.Do(req)
			if err == nil && resp != nil && resp.StatusCode/100 == 2 {
				break
			}
			time.Sleep(time.Duration(1<<attempt) * 200 * time.Millisecond)
		}
	}
}
