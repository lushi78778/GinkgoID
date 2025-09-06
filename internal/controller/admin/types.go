package admin

// —— 通用响应模型 ——

// TableMeta 表格分页元数据。
// swagger:model TableMeta
type TableMeta struct {
	// 记录总数
	// example: 123
	Count int64 `json:"count"`
}

// TableClientsResponse Layui 表格响应（客户端）。
// swagger:model TableClientsResponse
type TableClientsResponse struct {
	// 业务码：0 表示成功
	// example: 0
	Code int `json:"code"`
	// 消息
	// example: ok
	Msg string `json:"msg"`
	// 请求 ID
	// example: 9P8sJ0n2qWfD
	RequestID string `json:"request_id"`
	// 记录总数
	// example: 42
	Count int64 `json:"count"`
	// 数据行
	Data []ClientRow `json:"data"`
}

// TableUsersResponse Layui 表格响应（用户）。
// swagger:model TableUsersResponse
type TableUsersResponse struct {
	Code      int       `json:"code"`
	Msg       string    `json:"msg"`
	RequestID string    `json:"request_id"`
	Count     int64     `json:"count"`
	Data      []UserRow `json:"data"`
}

// TableConsentsResponse Layui 表格响应（同意记录）。
// swagger:model TableConsentsResponse
type TableConsentsResponse struct {
	Code      int          `json:"code"`
	Msg       string       `json:"msg"`
	RequestID string       `json:"request_id"`
	Count     int64        `json:"count"`
	Data      []ConsentRow `json:"data"`
}

// ClientsResponse 非分页列表响应（导出用途）。
// swagger:model ClientsResponse
type ClientsResponse struct {
	Code      int          `json:"code"`
	Msg       string       `json:"msg"`
	RequestID string       `json:"request_id"`
	Data      []ClientItem `json:"data"`
}

// UsersResponse 非分页列表响应（导出用途）。
// swagger:model UsersResponse
type UsersResponse struct {
	Code      int       `json:"code"`
	Msg       string    `json:"msg"`
	RequestID string    `json:"request_id"`
	Data      []UserRow `json:"data"`
}

// ConsentsResponse 非分页列表响应（导出用途）。
// swagger:model ConsentsResponse
type ConsentsResponse struct {
	Code      int          `json:"code"`
	Msg       string       `json:"msg"`
	RequestID string       `json:"request_id"`
	Data      []ConsentRow `json:"data"`
}

// —— 行/元素模型 ——

// ClientRow 列表/表格中的客户端行（精简）。
// swagger:model ClientRow
type ClientRow struct {
	// 客户端 ID
	// example: demo-web
	ClientID string `json:"client_id"`
	// 名称
	// example: Demo Web
	Name string `json:"name"`
	// 状态（1 启用 / 0 停用）
	// example: 1
	Status int8 `json:"status"`
}

// ClientItem 非分页导出时的完整客户端元素。
// swagger:model ClientItem
type ClientItem struct {
	ClientID       string `json:"client_id"`
	Name           string `json:"name"`
	Status         int8   `json:"status"`
	RedirectURIs   string `json:"redirect_uris"`
	PostLogoutURIs string `json:"post_logout_uris"`
	Scopes         string `json:"scopes"`
}

// UserRow 用户行。
// swagger:model UserRow
type UserRow struct {
	// example: 1001
	ID uint64 `json:"id"`
	// example: alice
	Username string `json:"username"`
	// example: alice@example.com
	Email string `json:"email"`
	// example: true
	EmailVerified bool `json:"email_verified"`
	// example: 1
	Status int8 `json:"status"`
	// example: admin
	Role string `json:"role"`
}

// ConsentRow 同意记录行。
// swagger:model ConsentRow
type ConsentRow struct {
	// example: 9001
	ID uint64 `json:"id"`
	// example: 1001
	UserID uint64 `json:"user_id"`
	// example: demo-web
	ClientID string `json:"client_id"`
	// example: ["openid","profile"]
	Scopes string `json:"scopes"`
}

// —— 请求模型 ——

// ClientStatusPatchReq 客户端状态更新请求。
// swagger:model ClientStatusPatchReq
type ClientStatusPatchReq struct {
	// 状态（1 启用 / 0 停用）
	// example: 1
	Status int8 `json:"status"`
}

// CreateUserReq 创建用户请求。
// swagger:model CreateUserReq
type CreateUserReq struct {
	// 用户名
	// example: alice
	Username string `json:"username"`
	// 密码
	// example: Secret123!
	Password string `json:"password"`
	// 邮箱（可选）
	// example: alice@example.com
	Email string `json:"email"`
	// 角色（可选）
	// example: admin
	Role string `json:"role"`
	// 邮箱是否已验证（可选）
	// example: true
	EmailVerified *bool `json:"email_verified"`
}

// PatchUserPasswordReq 重置密码请求。
// swagger:model PatchUserPasswordReq
type PatchUserPasswordReq struct {
	// 新密码
	// example: Secret123!
	Password string `json:"password"`
}

// PatchUserEmailReq 设置邮箱请求。
// swagger:model PatchUserEmailReq
type PatchUserEmailReq struct {
	// 邮箱
	// example: alice@example.com
	Email string `json:"email"`
	// 邮箱是否已验证（可选）
	// example: true
	EmailVerified *bool `json:"email_verified"`
}

// PatchUserRoleReq 设置角色请求。
// swagger:model PatchUserRoleReq
type PatchUserRoleReq struct {
	// 角色
	// example: operator
	Role string `json:"role"`
}

// RevokeAccessReq 撤销 Access Token 请求。
// swagger:model RevokeAccessReq
type RevokeAccessReq struct {
	// Access Token
	// example: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken string `json:"access_token"`
}

// RevokeJTIReq 按 jti 撤销请求。
// swagger:model RevokeJTIReq
type RevokeJTIReq struct {
	// JWT ID
	// example: 3c2e1f8a-9a50-4d9c-9b59-2b3f0baf7a2f
	JTI string `json:"jti"`
	// 过期时间（秒）
	// example: 600
	TTL int `json:"ttl_seconds"`
}
