// Package store 提供 SQLite 持久化：配置表与账户表。
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // 纯 Go SQLite 驱动，注册为 "sqlite"
)

// Account 对应 accounts 表的一行（不含解密后的 secret）。
type Account struct {
	ID         string
	Issuer     string
	Label      string
	SecretEnc  []byte // AES-GCM 密文（含 iv 前缀）
	Algorithm  string
	Digits     int
	Period     int
	CreatedAt  int64
	UpdatedAt  int64
}

// Config 配置表键名。
const (
	ConfigPasswordHash = "password_hash"
	ConfigKEKSalt      = "kek_salt"
	ConfigVerifier     = "verifier" // 加密后的随机校验值，用于校验主密码派生的 KEK 是否正确
)

// Store 封装数据库句柄。
type Store struct {
	db *sql.DB
}

// Open 打开（或创建）数据库并初始化表结构。
func Open(path string) (*Store, error) {
	// busy_timeout 缓解并发写冲突；foreign_keys 开启外键（虽当前未用，预留）。
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// SQLite 单写者，连接池设 1 写连接避免锁冲突。
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping db: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS config (
  key   TEXT PRIMARY KEY,
  value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  id            TEXT PRIMARY KEY,
  issuer        TEXT NOT NULL DEFAULT '',
  label         TEXT NOT NULL DEFAULT '',
  secret_enc    BLOB NOT NULL,
  algorithm     TEXT NOT NULL DEFAULT 'SHA1',
  digits        INTEGER NOT NULL DEFAULT 6,
  period        INTEGER NOT NULL DEFAULT 30,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_accounts_label ON accounts(label);
`)
	return err
}

// Close 关闭数据库。
func (s *Store) Close() error { return s.db.Close() }

// --- 配置表 ---

// GetConfig 读取配置项。不存在返回空串与 nil error（用 ok 区分）。
func (s *Store) GetConfig(key string) (value []byte, ok bool, err error) {
	var v []byte
	row := s.db.QueryRow(`SELECT value FROM config WHERE key=?`, key)
	if err := row.Scan(&v); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return v, true, nil
}

// SetConfig 写入配置项（覆盖）。
func (s *Store) SetConfig(key string, value []byte) error {
	_, err := s.db.Exec(`INSERT INTO config(key, value) VALUES(?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// IsInitialized 是否已设置主密码。
func (s *Store) IsInitialized() (bool, error) {
	_, ok, err := s.GetConfig(ConfigPasswordHash)
	return ok, err
}

// --- 账户表 ---

// ListAccounts 返回全部账户（按创建时间升序）。
func (s *Store) ListAccounts() ([]*Account, error) {
	rows, err := s.db.Query(`SELECT id, issuer, label, secret_enc, algorithm, digits, period, created_at, updated_at
		FROM accounts ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a := &Account{}
		if err := rows.Scan(&a.ID, &a.Issuer, &a.Label, &a.SecretEnc, &a.Algorithm, &a.Digits, &a.Period, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAccount 按 id 取单个账户。
func (s *Store) GetAccount(id string) (*Account, error) {
	a := &Account{}
	err := s.db.QueryRow(`SELECT id, issuer, label, secret_enc, algorithm, digits, period, created_at, updated_at
		FROM accounts WHERE id=?`, id).
		Scan(&a.ID, &a.Issuer, &a.Label, &a.SecretEnc, &a.Algorithm, &a.Digits, &a.Period, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return a, nil
}

// CreateAccount 新建账户。secretEnc 为已加密的密文。
func (s *Store) CreateAccount(id, issuer, label string, secretEnc []byte, algorithm string, digits, period int) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO accounts(id, issuer, label, secret_enc, algorithm, digits, period, created_at, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?)`, id, issuer, label, secretEnc, algorithm, digits, period, now, now)
	return err
}

// UpdateAccount 更新账户元信息，可选更新 secret（secretEnc 为 nil 表示不改）。
func (s *Store) UpdateAccount(id, issuer, label string, secretEnc []byte, algorithm string, digits, period int) error {
	now := time.Now().Unix()
	if secretEnc != nil {
		_, err := s.db.Exec(`UPDATE accounts SET issuer=?, label=?, secret_enc=?, algorithm=?, digits=?, period=?, updated_at=? WHERE id=?`,
			issuer, label, secretEnc, algorithm, digits, period, now, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE accounts SET issuer=?, label=?, algorithm=?, digits=?, period=?, updated_at=? WHERE id=?`,
		issuer, label, algorithm, digits, period, now, id)
	return err
}

// DeleteAccount 删除账户。
func (s *Store) DeleteAccount(id string) error {
	_, err := s.db.Exec(`DELETE FROM accounts WHERE id=?`, id)
	return err
}
