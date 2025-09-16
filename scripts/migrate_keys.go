package main

// 示例迁移脚本（演示用）
// 说明：在执行前请先备份数据库并在测试环境演练。

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"

	_ "github.com/go-sql-driver/mysql"

	"ginkgoid/internal/config"
)

// 简单 AES-GCM 加密函数占位（与项目 internal/utils/crypto.go 保持一致）
// 这里只是示例，生产请用项目内工具或把该脚本并入项目代码库以复用 utils。

func deriveKey(pass string) []byte {
	h := sha256.Sum256([]byte(pass))
	return h[:]
}

func main() {
	var dsn string
	var key string
	// 默认 DSN 仅用于本地开发，请在生产显式传入 -dsn 并使用强凭据
	flag.StringVar(&dsn, "dsn", "root:123465@tcp(127.0.0.1:3306)/ginkgoid?parseTime=true", "MySQL DSN")
	flag.StringVar(&key, "key", "", "Key encryption key (optional; if omitted the script will use crypto.key_encryption_key from config.yaml)")
	flag.Parse()
	cfg := config.Load()
	if key == "" {
		key = cfg.Crypto.KeyEncryptionKey
	}
	if key == "" {
		log.Fatal("KEY_ENCRYPTION_KEY must be provided via -key flag or crypto.key_encryption_key in config.yaml")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	// 查询 jwk_keys 表示例字段 id, private_key
	rows, err := db.Query("SELECT id, private_key FROM jwk_keys")
	if err != nil {
		log.Fatalf("query jwk_keys: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var pk sql.NullString
		if err := rows.Scan(&id, &pk); err != nil {
			log.Fatalf("scan: %v", err)
		}
		if !pk.Valid || pk.String == "" {
			continue
		}
		// 简单判断：如果包含 -----BEGIN RSA PRIVATE KEY-----，视为明文 PEM
		if isLikelyPEM(pk.String) {
			fmt.Printf("Encrypting id=%d\n", id)
			enc, err := encryptPlaceholder(key, pk.String)
			if err != nil {
				log.Fatalf("encrypt: %v", err)
			}
			// 更新数据库
			_, err = db.Exec("UPDATE jwk_keys SET private_key=? WHERE id=?", enc, id)
			if err != nil {
				log.Fatalf("update: %v", err)
			}
		}
	}

	if err := rows.Err(); err != nil {
		log.Fatalf("rows: %v", err)
	}

	fmt.Println("migration complete")
}

func isLikelyPEM(s string) bool {
	return (len(s) > 20 && (contains(s, "-----BEGIN") || contains(s, "BEGIN RSA")))
}

func contains(a, b string) bool {
	return len(a) >= len(b) && (stringIndex(a, b) >= 0)
}

func stringIndex(a, b string) int {
	for i := 0; i+len(b) <= len(a); i++ {
		if a[i:i+len(b)] == b {
			return i
		}
	}
	return -1
}

// encryptPlaceholder 模拟加密（生产请使用项目内 AES-GCM 实现）
func encryptPlaceholder(pass, plaintext string) (string, error) {
	k := deriveKey(pass)
	// 这里我们只是把 key + plaintext 做简单处理并返回 hex，演示用途
	b := append(k, []byte(plaintext)...)
	return hex.EncodeToString(b), nil
}
