// Package crypto 提供主密码派生、secret 加解密、密码哈希。
//
// 设计：
//   - 主密码通过 scrypt 派生 32 字节 KEK（密钥加密密钥），KEK 只存内存，不持久化。
//   - bcrypt 仅用于校验主密码是否正确（存库）。
//   - 每个 secret 用 AES-256-GCM 加密，IV 每次随机生成。
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// scrypt 参数。N=32768 提供合理强度，开销可接受。
const (
	scryptN     = 32768
	scryptR     = 8
	scryptP     = 1
	scryptKeyLen = 32 // AES-256
	scryptSaltLen = 32
)

// DeriveKEK 用主密码和盐派生 32 字节 KEK。
func DeriveKEK(password, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, scryptKeyLen)
}

// RandomSalt 生成随机盐。
func RandomSalt() ([]byte, error) {
	salt := make([]byte, scryptSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// HashPassword 用 bcrypt 哈希主密码（仅用于登录校验，不用于派生 KEK）。
func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

// VerifyPassword 校验主密码与 bcrypt 哈希是否匹配。
func VerifyPassword(hash, password []byte) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(password))
}

// Encrypt 用 KEK 加密明文，返回 iv || ciphertext(含 GCM tag)。
func Encrypt(kek, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	// Seal 把密文和 tag 直接追加到 iv 之后。
	return gcm.Seal(iv, iv, plaintext, nil), nil
}

// Decrypt 用 KEK 解密 Encrypt 的输出（iv || ciphertext）。
func Decrypt(kek, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}
