package errx

// Code 统一错误码类型。
type Code int

const (
	// OK 成功
	OK Code = 0

	// CSRF 相关错误码（14xx 区段）
	CSRFTokenMissing  Code = 1401
	CSRFTokenInvalid  Code = 1402
	CSRFOriginInvalid Code = 1403

	// 内部错误（15xx 区段）
	CSRFTokenGenFailed Code = 1500
)

var messages = map[Code]string{
	OK:                 "ok",
	CSRFTokenMissing:   "missing_csrf_token",
	CSRFTokenInvalid:   "invalid_csrf_token",
	CSRFOriginInvalid:  "invalid_origin",
	CSRFTokenGenFailed: "csrf_token_generation_failed",
}

// Msg 返回错误码对应的消息（用于前端/日志，后续可接入 i18n）。
func Msg(code Code) string {
	if s, ok := messages[code]; ok {
		return s
	}
	return "error"
}
