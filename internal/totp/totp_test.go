package totp

import (
	"testing"
)

func TestGenerateSteam(t *testing.T) {
	code, err := GenerateSteam("JBSWY3DPEHPK3PXP", 30)
	if err != nil {
		t.Fatalf("GenerateSteam error: %v", err)
	}
	if len(code) != 5 {
		t.Fatalf("Steam code length = %d, want 5; code=%q", len(code), code)
	}
	// 字符必须都在 steamChars 内
	valid := map[byte]bool{}
	for _, c := range steamChars {
		valid[c] = true
	}
	for i := 0; i < len(code); i++ {
		if !valid[code[i]] {
			t.Fatalf("invalid char %q in steam code %q", code[i], code)
		}
	}
	t.Logf("Steam code: %s", code)
}
