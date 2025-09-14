package utils

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
)

// PairwiseSub 生成 pairwise 类型的 subject 标识。
// 计算方式参考 OIDC：sub = base64url( HMAC-SHA256( sector_id || "|" || user_id, key=salt ) )。
// 其中 salt 作为 HMAC 密钥，sector_id 与用户 ID 作为消息体，确保同一用户在不同 sector 下的 sub 不同。
func PairwiseSub(sectorID string, userID uint64, salt string) string {
    mac := hmac.New(sha256.New, []byte(salt))
    mac.Write([]byte(fmt.Sprintf("%s|%d", sectorID, userID)))
    sum := mac.Sum(nil)
    return base64.RawURLEncoding.EncodeToString(sum)
}
