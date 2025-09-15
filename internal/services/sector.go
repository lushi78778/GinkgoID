package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"ginkgoid/internal/config"
)

// validateSectorIdentifier 拉取该 URI 的 JSON 数组并确保包含所有 redirect_uris。
func validateSectorIdentifier(cfg config.Config, uri string, redirects []string) error {
	// 使用配置的 HTTP 超时，避免卡死注册流程
	timeout := cfg.Registration.SectorTimeout
	if timeout <= 0 {
		timeout = 0
	} // 使用 http 默认超时（无超时）或保持为 0
	httpc := &http.Client{Timeout: timeout}
	// 仅允许 https；在开发模式下可允许本地 http（可通过配置关闭）
	if u, err := url.Parse(uri); err == nil {
		if u.Scheme != "https" {
			allowedLocal := cfg.Registration.AllowInsecureLocalHTTP && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1")
			if !(u.Scheme == "http" && allowedLocal) {
				return fmt.Errorf("sector_identifier_uri must be https (or local http enabled)")
			}
		}
	}
	resp, err := httpc.Get(uri)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var arr []string
	if err := json.Unmarshal(b, &arr); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, u := range arr {
		have[u] = true
	}
	for _, r := range redirects {
		if !have[r] {
			return fmt.Errorf("missing redirect_uri %s", r)
		}
	}
	return nil
}
