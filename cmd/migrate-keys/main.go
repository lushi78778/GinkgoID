package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	_ "github.com/go-sql-driver/mysql"

	"ginkgoid/internal/config"
	"ginkgoid/internal/utils"
)

// 简易迁移命令：遍历 jwk_keys 表，将看起来为明文 PEM 的 private_key 字段使用项目内 AES-GCM 加密后写回。
// 用法：go run ./cmd/migrate-keys [-dry-run] [-confirm] [-limit N] [-only-ids 1,2,3]
func main() {
	dryRun := flag.Bool("dry-run", false, "do not write changes, just report")
	confirm := flag.Bool("confirm", false, "skip interactive confirmation prompt")
	limit := flag.Int("limit", 0, "limit the number of keys to process (0 for all)")
	onlyIDs := flag.String("only-ids", "", "comma-separated list of specific key IDs to process")
	flag.Parse()

	cfg := config.Load()
	if cfg.Crypto.KeyEncryptionKey == "" {
		log.Fatal("crypto.key_encryption_key must be set in config.yaml before running migration")
	}
	key := cfg.Crypto.KeyEncryptionKey

	var idFilter map[int64]bool
	if *onlyIDs != "" {
		idFilter = make(map[int64]bool)
		parts := strings.Split(*onlyIDs, ",")
		for _, p := range parts {
			id, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
			if err != nil {
				log.Fatalf("invalid id in -only-ids: %q", p)
			}
			idFilter[id] = true
		}
	}

	db, err := sql.Open("mysql", cfg.MySQL.DSN())
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, private_key FROM jwk_keys")
	if err != nil {
		log.Fatalf("query jwk_keys: %v", err)
	}
	defer rows.Close()

	type upd struct {
		id  int64
		enc string
	}
	updates := make([]upd, 0, 16)

	for rows.Next() {
		var id int64
		var pk sql.NullString
		if err := rows.Scan(&id, &pk); err != nil {
			log.Fatalf("scan: %v", err)
		}

		if idFilter != nil {
			if _, ok := idFilter[id]; !ok {
				continue
			}
		}

		if !pk.Valid || pk.String == "" {
			continue
		}
		if isLikelyPEM(pk.String) {
			fmt.Printf("Found plaintext key id=%d\n", id)
			enc, err := utils.EncryptAESGCM(key, []byte(pk.String))
			if err != nil {
				log.Fatalf("encrypt id=%d: %v", id, err)
			}
			updates = append(updates, upd{id: id, enc: enc})
			if *limit > 0 && len(updates) >= *limit {
				fmt.Printf("Limit of %d reached, stopping scan.\n", *limit)
				break
			}
		}
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("rows: %v", err)
	}

	if len(updates) == 0 {
		fmt.Println("No plaintext keys found to migrate.")
		return
	}

	if *dryRun {
		fmt.Printf("Dry run: %d keys would be encrypted\n", len(updates))
		for _, u := range updates {
			fmt.Printf(" - id=%d\n", u.id)
		}
		return
	}

	if !*confirm {
		fmt.Printf("\nAbout to encrypt %d keys in the database. This is irreversible without a backup.\n", len(updates))
		fmt.Print("Type 'yes' to continue: ")
		var response string
		fmt.Scanln(&response)
		if response != "yes" {
			fmt.Println("Aborted.")
			return
		}
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("begin tx: %v", err)
	}
	for _, u := range updates {
		if _, err := tx.Exec("UPDATE jwk_keys SET private_key=? WHERE id=?", u.enc, u.id); err != nil {
			_ = tx.Rollback()
			log.Fatalf("update id=%d: %v", u.id, err)
		}
	}
	if err := tx.Commit(); err != nil {
		log.Fatalf("commit: %v", err)
	}
	fmt.Printf("migration complete: %d keys encrypted\n", len(updates))
}

func isLikelyPEM(s string) bool {
	return len(s) > 20 && (strings.Contains(s, "-----BEGIN") || strings.Contains(s, "BEGIN RSA"))
}
