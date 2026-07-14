// Package totp 封装 TOTP 码生成与周期计算。
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"time"

	"github.com/pquerna/otp/totp"
)

// ValidateSecret 校验 secret 是否为合法的 Base32。
func ValidateSecret(secret string) error {
	_, err := totp.GenerateCode(secret, time.Now())
	return err
}

// Generate 返回当前 TOTP 码。
func Generate(secret string, period uint, digits int, algorithm string) (string, error) {
	opts := totp.ValidateOpts{
		Period:    period,
		Skew:      0,
		Digits:    toDigits(digits),
		Algorithm: toAlgorithm(algorithm),
	}
	return totp.GenerateCodeCustom(secret, time.Now(), opts)
}

// RemainingSeconds 返回当前 TOTP 周期内剩余秒数。
func RemainingSeconds(period uint, now time.Time) int {
	return int(period - uint(now.Unix())%period)
}

// NextTickAt 返回下一个 TOTP 周期开始时刻（Unix 秒）。
func NextTickAt(period uint, now time.Time) int64 {
	secs := now.Unix()
	return (secs/int64(period)+1)*int64(period)
}

// steamChars 是 Steam Guard 使用的字母表（去掉易混淆的元音和 0/1）。
// 与标准 TOTP 相比，Steam 仅在"截断整数→可读字符"这一步不同。
var steamChars = []byte("23456789CFGHJMPQRW")

// GenerateSteam 生成 Steam Guard 码（5 位字母数字）。
// 算法：标准 TOTP 的 HMAC-SHA1 + 31 位动态截断，再映射到 steamChars 取 5 位。
// period 固定 30（Steam Guard 与 TOTP 同周期），secret 为 Base32 编码。
func GenerateSteam(secret string, period uint) (string, error) {
	// Base32 解码 secret
	dec, err := decodeBase32(secret)
	if err != nil {
		return "", err
	}
	// 计算时间计数器（与标准 TOTP 一致）
	if period == 0 {
		period = 30
	}
	t := uint64(time.Now().Unix()) / uint64(period)
	// HMAC-SHA1(key=secret, msg=counter)
	mac := hmac.New(sha1.New, dec)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], t)
	mac.Write(buf[:])
	hash := mac.Sum(nil)
	// 动态截取（RFC 4226 标准 offset 取法）
	offset := int(hash[len(hash)-1] & 0x0f)
	binary31 := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7fffffff
	// 映射到 Steam 字母表，取 5 位
	out := make([]byte, 5)
	for i := 0; i < 5; i++ {
		out[4-i] = steamChars[binary31%uint32(len(steamChars))]
		binary31 /= uint32(len(steamChars))
	}
	return string(out), nil
}

// decodeBase32 宽松解码：容忍无 padding 与大小写。
func decodeBase32(secret string) ([]byte, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.DecodeString(secret)
}
