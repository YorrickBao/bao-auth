// Package totp 封装 TOTP 码生成与周期计算。
package totp

import (
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
