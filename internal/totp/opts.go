package totp

import (
	"strings"

	"github.com/pquerna/otp"
)

func toDigits(d int) otp.Digits {
	if d == 8 {
		return otp.DigitsEight
	}
	return otp.DigitsSix
}

func toAlgorithm(a string) otp.Algorithm {
	switch strings.ToUpper(strings.TrimSpace(a)) {
	case "SHA256":
		return otp.AlgorithmSHA256
	case "SHA512":
		return otp.AlgorithmSHA512
	case "MD5":
		return otp.AlgorithmMD5
	default:
		return otp.AlgorithmSHA1
	}
}
