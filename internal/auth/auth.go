// Package auth 管理主密码校验、KEK 生命周期、JWT 会话与登录限速。
//
// 安全模型：
//   - KEK（由主密码 scrypt 派生）只存内存，服务器重启即失效，需重新登录。
//   - KEK 用于加解密存储中的 secret；登录成功后才注入内存。
//   - JWT 携带会话标识，签名密钥在每次启动时随机生成（重启后旧 token 失效）。
//   - 登录失败做简单计数冷却，缓解暴力破解。
package auth

import (
	"crypto/rand"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 错误定义。
var (
	ErrNotUnlocked = errors.New("vault locked: please login")
	ErrInvalid     = errors.New("invalid")
)

// Vault 管理加密密钥与会话。
type Vault struct {
	mu     sync.RWMutex
	kek    []byte        // 当前内存中的 KEK；nil 表示未解锁
	jwtKey []byte        // JWT 签名密钥，启动时随机
	unlock time.Time     // 最近一次解锁时间

	// 登录限速
	failMu  sync.Mutex
	fails   int
	lockedUntil time.Time
}

// NewVault 创建空保险库，并生成随机 JWT 签名密钥。
func NewVault() (*Vault, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &Vault{jwtKey: key}, nil
}

// Unlock 注入主密码派生的 KEK，标记为已解锁。
func (v *Vault) Unlock(kek []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.kek = kek
	v.unlock = time.Now()
}

// Lock 清除 KEK（登出或长时间空闲）。
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.kek = nil
}

// IsUnlocked 当前是否持有 KEK。
func (v *Vault) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.kek != nil
}

// KEK 返回 KEK 拷贝（未解锁返回错误）。
func (v *Vault) KEK() ([]byte, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.kek == nil {
		return nil, ErrNotUnlocked
	}
	out := make([]byte, len(v.kek))
	copy(out, v.kek)
	return out, nil
}

// --- 登录限速 ---

const (
	maxFails       = 5
	lockoutWindow  = 30 * time.Second // 累计失败超阈值后冷却时长
)

// CheckRateLimit 返回是否允许尝试登录；不允许则返回需等待的时长。
func (v *Vault) CheckRateLimit() (allowed bool, retryAfter time.Duration) {
	v.failMu.Lock()
	defer v.failMu.Unlock()
	if time.Now().Before(v.lockedUntil) {
		return false, time.Until(v.lockedUntil)
	}
	return true, 0
}

// RecordFail 记录一次失败，超阈值触发冷却。
func (v *Vault) RecordFail() {
	v.failMu.Lock()
	defer v.failMu.Unlock()
	v.fails++
	if v.fails >= maxFails {
		v.lockedUntil = time.Now().Add(lockoutWindow)
		v.fails = 0
	}
}

// ResetFails 登录成功，清零计数。
func (v *Vault) ResetFails() {
	v.failMu.Lock()
	defer v.failMu.Unlock()
	v.fails = 0
	v.lockedUntil = time.Time{}
}

// --- JWT ---

const tokenTTL = 24 * time.Hour

// Claims JWT 声明。
type Claims struct {
	Sub string `json:"sub"`
	jwt.RegisteredClaims
}

// IssueToken 签发一个会话 JWT。
func (v *Vault) IssueToken() (string, error) {
	now := time.Now()
	claims := Claims{
		Sub: "user",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(v.jwtKey)
}

// VerifyToken 校验 JWT 并返回声明。
func (v *Vault) VerifyToken(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalid
		}
		return v.jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}
