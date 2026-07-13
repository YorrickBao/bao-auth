// Package server 实现 HTTP 路由、鉴权中间件与全部 API handler。
//
// 路由：
//   GET    /api/status           是否已初始化
//   POST   /api/setup            首次设置主密码
//   POST   /api/login            登录
//   POST   /api/logout           登出
//   GET    /api/accounts         列表（返回实时 TOTP 码，不含 secret）
//   POST   /api/accounts         新增
//   PUT    /api/accounts/{id}    编辑
//   DELETE /api/accounts/{id}    删除
//   POST   /api/parse-uri        解析 otpauth:// URI
//   GET    /api/export           导出明文备份（用户主动）
//   POST   /api/import           导入备份文件
package server

import (
	crand "crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"baoauth/internal/auth"
	"baoauth/internal/crypto"
	"baoauth/internal/store"
	mytotp "baoauth/internal/totp"
)

const tokenIssuer = "bao-auth"

// Server 持有所有依赖。
type Server struct {
	store *store.Store
	vault *auth.Vault
}

// New 创建 Server。
func New(s *store.Store, v *auth.Vault) *Server {
	return &Server{store: s, vault: v}
}

// --- 公共响应辅助 ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// --- handler 方法挂在 Server 上，由 Register 挂到 mux ---

// Register 把路由挂到给定的 mux 上。
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/setup", s.handleSetup)
	mux.HandleFunc("/api/login", s.handleLogin)
	// 需要 JWT 的接口
	mux.HandleFunc("/api/logout", s.withAuth(s.handleLogout))
	mux.HandleFunc("/api/accounts", s.withAuth(s.handleAccountsRoot))
	mux.HandleFunc("/api/accounts/", s.withAuth(s.handleAccountItem)) // 带 id 的 PUT/DELETE
	mux.HandleFunc("/api/parse-uri", s.withAuth(s.handleParseURI))
	mux.HandleFunc("/api/export", s.withAuth(s.handleExport))
	mux.HandleFunc("/api/import", s.withAuth(s.handleImport))
}

// --- 中间件 ---

// withAuth 校验 JWT（要求已登录），但不强制 vault 已解锁。
// 解锁状态由各 handler 按需检查（操作 secret 时需要）。
func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := bearerToken(r)
		if tokenStr == "" {
			errJSON(w, http.StatusUnauthorized, "未登录")
			return
		}
		if _, err := s.vault.VerifyToken(tokenStr); err != nil {
			errJSON(w, http.StatusUnauthorized, "会话已过期，请重新登录")
			return
		}
		next(w, r)
	}
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

// --- /api/status ---

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	inited, err := s.store.IsInitialized()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "查询状态失败")
		return
	}
	unlocked := s.vault.IsUnlocked()
	writeJSON(w, http.StatusOK, map[string]any{
		"initialized": inited,
		"unlocked":    unlocked,
	})
}

// --- /api/setup ---

type setupReq struct {
	Password string `json:"password"`
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// 仅未初始化时可用
	if inited, _ := s.store.IsInitialized(); inited {
		errJSON(w, http.StatusConflict, "已初始化，请直接登录")
		return
	}
	var req setupReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	if len(req.Password) < 8 {
		errJSON(w, http.StatusBadRequest, "主密码至少 8 位")
		return
	}

	// 1. bcrypt 哈希主密码（用于登录校验）
	pwHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "密码哈希失败")
		return
	}
	// 2. 生成 scrypt 盐，派生 KEK
	salt, err := crypto.RandomSalt()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "盐生成失败")
		return
	}
	kek, err := crypto.DeriveKEK([]byte(req.Password), salt)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "密钥派生失败")
		return
	}
	// 3. 生成随机 verifier 并用 KEK 加密，用于登录时校验派生的 KEK 是否正确
	verifierPlain := make([]byte, 32)
	if _, err := randRead(verifierPlain); err != nil {
		errJSON(w, http.StatusInternalServerError, "随机数失败")
		return
	}
	verifierEnc, err := crypto.Encrypt(kek, verifierPlain)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "加密失败")
		return
	}
	// 4. 持久化
	if err := s.store.SetConfig(store.ConfigPasswordHash, pwHash); err != nil {
		errJSON(w, http.StatusInternalServerError, "保存密码失败")
		return
	}
	if err := s.store.SetConfig(store.ConfigKEKSalt, salt); err != nil {
		errJSON(w, http.StatusInternalServerError, "保存盐失败")
		return
	}
	if err := s.store.SetConfig(store.ConfigVerifier, verifierEnc); err != nil {
		errJSON(w, http.StatusInternalServerError, "保存校验值失败")
		return
	}
	// 5. 注入 KEK 并签发 token（setup 后直接登录）
	s.vault.Unlock(kek)
	s.vault.ResetFails()
	token, err := s.vault.IssueToken()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "签发令牌失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

// --- /api/login ---

type loginReq struct {
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// 限速
	if ok, retry := s.vault.CheckRateLimit(); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
		errJSON(w, http.StatusTooManyRequests, fmt.Sprintf("尝试过于频繁，请 %d 秒后再试", int(retry.Seconds())+1))
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	pwHash, ok, err := s.store.GetConfig(store.ConfigPasswordHash)
	if err != nil || !ok {
		errJSON(w, http.StatusConflict, "尚未初始化")
		return
	}
	if crypto.VerifyPassword(pwHash, []byte(req.Password)) != nil {
		s.vault.RecordFail()
		errJSON(w, http.StatusUnauthorized, "主密码错误")
		return
	}
	// 密码正确，派生 KEK 并用 verifier 校验一致性
	salt, ok, err := s.store.GetConfig(store.ConfigKEKSalt)
	if err != nil || !ok {
		errJSON(w, http.StatusInternalServerError, "盐缺失")
		return
	}
	kek, err := crypto.DeriveKEK([]byte(req.Password), salt)
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "密钥派生失败")
		return
	}
	verifierEnc, ok, err := s.store.GetConfig(store.ConfigVerifier)
	if err != nil || !ok {
		errJSON(w, http.StatusInternalServerError, "校验值缺失")
		return
	}
	if _, err := crypto.Decrypt(kek, verifierEnc); err != nil {
		// 极少发生：bcrypt 通过但 KEK 解不开（例如配置损坏）
		errJSON(w, http.StatusInternalServerError, "密钥校验失败")
		return
	}
	s.vault.Unlock(kek)
	s.vault.ResetFails()
	token, err := s.vault.IssueToken()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "签发令牌失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token})
}

// --- /api/logout ---

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	s.vault.Lock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- /api/accounts (GET 列表 / POST 新增) ---

type accountReq struct {
	Issuer    string `json:"issuer"`
	Label     string `json:"label"`
	Secret    string `json:"secret"` // 原始 Base32 secret，明文
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

// accountOut 列表/详情返回结构（绝不包含原始 secret）。
type accountOut struct {
	ID        string `json:"id"`
	Issuer    string `json:"issuer"`
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

func (s *Server) handleAccountsRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listAccounts(w, r)
	case http.MethodPost:
		s.createAccount(w, r)
	default:
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) {
	// 列表虽不暴露 secret，但码生成需解密 secret，因此要求已解锁。
	kek, err := s.requireUnlocked(w)
	if err != nil {
		return
	}
	accs, err := s.store.ListAccounts()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "读取账户失败")
		return
	}
	now := time.Now()
	out := make([]map[string]any, 0, len(accs))
	for _, a := range accs {
		entry := map[string]any{
			"id":        a.ID,
			"issuer":    a.Issuer,
			"label":     a.Label,
			"algorithm": a.Algorithm,
			"digits":    a.Digits,
			"period":    a.Period,
		}
		plain, err := crypto.Decrypt(kek, a.SecretEnc)
		if err != nil {
			entry["code"] = ""
			entry["error"] = "解密失败"
		} else {
			code, err := mytotp.Generate(string(plain), uint(a.Period), a.Digits, a.Algorithm)
			if err != nil {
				entry["code"] = ""
				entry["error"] = "生成验证码失败"
			} else {
				entry["code"] = code
				entry["remaining"] = mytotp.RemainingSeconds(uint(a.Period), now)
				entry["next_tick_at"] = mytotp.NextTickAt(uint(a.Period), now)
			}
		}
		out = append(out, entry)
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": out, "now": now.Unix()})
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) {
	kek, err := s.requireUnlocked(w)
	if err != nil {
		return
	}
	var req accountReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req = normalizeAccountReq(req)
	if err := validateSecret(req.Secret); err != nil {
		errJSON(w, http.StatusBadRequest, "secret 无效："+err.Error())
		return
	}
	enc, err := crypto.Encrypt(kek, []byte(req.Secret))
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "加密 secret 失败")
		return
	}
	id := uuid.NewString()
	if err := s.store.CreateAccount(id, req.Issuer, req.Label, enc, req.Algorithm, req.Digits, req.Period); err != nil {
		errJSON(w, http.StatusInternalServerError, "保存账户失败")
		return
	}
	writeJSON(w, http.StatusCreated, accountOut{id, req.Issuer, req.Label, req.Algorithm, req.Digits, req.Period})
}

// --- /api/accounts/{id} (PUT 编辑 / DELETE 删除) ---

func (s *Server) handleAccountItem(w http.ResponseWriter, r *http.Request) {
	// 路径形如 /api/accounts/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/accounts/")
	if id == "" {
		errJSON(w, http.StatusBadRequest, "缺少 id")
		return
	}
	switch r.Method {
	case http.MethodPut:
		s.updateAccount(w, r, id)
	case http.MethodDelete:
		s.deleteAccount(w, r, id)
	default:
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) updateAccount(w http.ResponseWriter, r *http.Request, id string) {
	kek, err := s.requireUnlocked(w)
	if err != nil {
		return
	}
	var req accountReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	req = normalizeAccountReq(req)
	// 若提供新 secret 则加密；否则不更新 secret
	var enc []byte
	if strings.TrimSpace(req.Secret) != "" {
		if err := validateSecret(req.Secret); err != nil {
			errJSON(w, http.StatusBadRequest, "secret 无效："+err.Error())
			return
		}
		enc, err = crypto.Encrypt(kek, []byte(req.Secret))
		if err != nil {
			errJSON(w, http.StatusInternalServerError, "加密 secret 失败")
			return
		}
	}
	if err := s.store.UpdateAccount(id, req.Issuer, req.Label, enc, req.Algorithm, req.Digits, req.Period); err != nil {
		errJSON(w, http.StatusInternalServerError, "更新失败")
		return
	}
	writeJSON(w, http.StatusOK, accountOut{id, req.Issuer, req.Label, req.Algorithm, req.Digits, req.Period})
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request, id string) {
	if err := s.store.DeleteAccount(id); err != nil {
		errJSON(w, http.StatusInternalServerError, "删除失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- /api/parse-uri ---

func (s *Server) handleParseURI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		URI string `json:"uri"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errJSON(w, http.StatusBadRequest, "请求格式错误")
		return
	}
	parsed, err := parseOTPAuth(req.URI)
	if err != nil {
		errJSON(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, parsed)
}

// --- /api/export ---

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	kek, err := s.requireUnlocked(w)
	if err != nil {
		return
	}
	accs, err := s.store.ListAccounts()
	if err != nil {
		errJSON(w, http.StatusInternalServerError, "读取账户失败")
		return
	}
	out := make([]map[string]any, 0, len(accs))
	for _, a := range accs {
		plain, err := crypto.Decrypt(kek, a.SecretEnc)
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"issuer":    a.Issuer,
			"label":     a.Label,
			"secret":    string(plain),
			"algorithm": a.Algorithm,
			"digits":    a.Digits,
			"period":    a.Period,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"exported_at": time.Now().Format(time.RFC3339),
		"app":         tokenIssuer,
		"accounts":    out,
	})
}

// --- /api/import ---

// importEntry 导入文件中单个账户的可选字段。
type importEntry struct {
	Issuer    string `json:"issuer"`
	Label     string `json:"label"`
	Secret    string `json:"secret"`
	Algorithm string `json:"algorithm"`
	Digits    json.Number `json:"digits"`
	Period    json.Number `json:"period"`
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errJSON(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	kek, err := s.requireUnlocked(w)
	if err != nil {
		return
	}

	// 解析请求体。兼容多种 JSON 形态：
	//   {accounts:[...]}  ← 标准导出文件
	//   [{...}, ...]      ← 裸数组
	//   {...}             ← 单个账户
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		errJSON(w, http.StatusBadRequest, "读取请求体失败")
		return
	}
	entries := extractImportEntriesRaw(bodyBytes)
	if len(entries) == 0 {
		errJSON(w, http.StatusBadRequest, "未找到可导入的账户")
		return
	}

	imported, skipped := 0, 0
	skipReason := ""
	for i := range entries {
		e := entries[i]
		// 归一化
		issuer := strings.TrimSpace(e.Issuer)
		label := strings.TrimSpace(e.Label)
		secret := strings.ReplaceAll(strings.TrimSpace(e.Secret), " ", "")
		algo := strings.ToUpper(strings.TrimSpace(e.Algorithm))
		if algo == "" {
			algo = "SHA1"
		}
		digits, _ := e.Digits.Int64()
		if digits == 0 {
			digits = 6
		}
		period, _ := e.Period.Int64()
		if period == 0 {
			period = 30
		}
		// 校验 secret
		if err := validateSecret(secret); err != nil {
			skipped++
			name := issuer
			if name == "" {
				name = label
			}
			if name == "" {
				name = "#" + itoa(imported+skipped)
			}
			skipReason = name + ": " + err.Error()
			continue
		}
		enc, err := crypto.Encrypt(kek, []byte(secret))
		if err != nil {
			skipped++
			continue
		}
		if err := s.store.CreateAccount(uuid.NewString(), issuer, label, enc, algo, int(digits), int(period)); err != nil {
			skipped++
			continue
		}
		imported++
	}
	resp := map[string]any{
		"imported": imported,
		"skipped":  skipped,
	}
	if skipped > 0 {
		resp["skip_reason"] = skipReason
	}
	writeJSON(w, http.StatusOK, resp)
}

// extractImportEntriesRaw 从原始 JSON 字节中提取账户条目，兼容对象与数组。
func extractImportEntriesRaw(b []byte) []*importEntry {
	// 用 json.RawMessage 判断顶层是数组还是对象
	var head json.RawMessage
	if err := json.Unmarshal(b, &head); err != nil {
		return nil
	}
	trimmed := strings.TrimSpace(string(head))
	if strings.HasPrefix(trimmed, "[") {
		var arr []map[string]any
		if err := json.Unmarshal(b, &arr); err != nil {
			return nil
		}
		out := make([]*importEntry, 0, len(arr))
		for _, m := range arr {
			out = append(out, mapToImportEntry(m))
		}
		return out
	}
	// 对象形态
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil
	}
	// 含 accounts 数组（标准导出格式）
	if accsRaw, ok := raw["accounts"]; ok {
		return toImportEntries(accsRaw)
	}
	// 单个账户（有 secret 字段）
	if _, ok := raw["secret"]; ok {
		return []*importEntry{mapToImportEntry(raw)}
	}
	return nil
}

// toImportEntries 把任意层级的值转成导入条目切片。
func toImportEntries(v any) []*importEntry {
	switch t := v.(type) {
	case []any:
		out := make([]*importEntry, 0, len(t))
		for _, item := range t {
			if m, ok := item.(map[string]any); ok {
				out = append(out, mapToImportEntry(m))
			}
		}
		return out
	case map[string]any:
		return []*importEntry{mapToImportEntry(t)}
	}
	return nil
}

// mapToImportEntry 把松散的 map 转成强类型条目（数字可能是 float64 或字符串）。
func mapToImportEntry(m map[string]any) *importEntry {
	e := &importEntry{}
	if v, ok := m["issuer"].(string); ok {
		e.Issuer = v
	}
	if v, ok := m["label"].(string); ok {
		e.Label = v
	}
	if v, ok := m["secret"].(string); ok {
		e.Secret = v
	}
	if v, ok := m["algorithm"].(string); ok {
		e.Algorithm = v
	}
	e.Digits = jsonNumber(m["digits"])
	e.Period = jsonNumber(m["period"])
	return e
}

// jsonNumber 把 interface{} 转成 json.Number（兼容 float64/string/nil）。
func jsonNumber(v any) json.Number {
	switch t := v.(type) {
	case json.Number:
		return t
	case float64:
		return json.Number(strconv.FormatFloat(t, 'f', -1, 64))
	case string:
		return json.Number(t)
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }

// --- 辅助 ---

// requireUnlocked 返回 KEK；若未解锁则写入 401 并返回 error。
func (s *Server) requireUnlocked(w http.ResponseWriter) ([]byte, error) {
	kek, err := s.vault.KEK()
	if err != nil {
		errJSON(w, http.StatusUnauthorized, "保险库未解锁，请登录")
		return nil, err
	}
	return kek, nil
}

func normalizeAccountReq(req accountReq) accountReq {
	req.Issuer = strings.TrimSpace(req.Issuer)
	req.Label = strings.TrimSpace(req.Label)
	req.Secret = strings.ReplaceAll(strings.TrimSpace(req.Secret), " ", "")
	req.Algorithm = strings.ToUpper(strings.TrimSpace(req.Algorithm))
	if req.Algorithm == "" {
		req.Algorithm = "SHA1"
	}
	if req.Digits == 0 {
		req.Digits = 6
	}
	if req.Period == 0 {
		req.Period = 30
	}
	return req
}

// validateSecret 校验 secret 为合法 Base32（能生成码即可）。
func validateSecret(secret string) error {
	if secret == "" {
		return errors.New("secret 不能为空")
	}
	if _, err := totp.GenerateCode(secret, time.Now()); err != nil {
		return fmt.Errorf("不是合法的 Base32 密钥：%w", err)
	}
	return nil
}

// parseOTPAuthURIResult 解析结果。
type parsedURI struct {
	Secret    string `json:"secret"`
	Issuer    string `json:"issuer"`
	Label     string `json:"label"`
	Algorithm string `json:"algorithm"`
	Digits    int    `json:"digits"`
	Period    int    `json:"period"`
}

// parseOTPAuth 解析 otpauth://totp/... URI。
func parseOTPAuth(raw string) (*parsedURI, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return nil, errors.New("不是合法的 otpauth:// URI")
	}
	// pquerna/otp 提供 NewKeyFromURL 解析标准 otpauth URI。
	k, err := otp.NewKeyFromURL(raw)
	if err != nil {
		return nil, fmt.Errorf("解析失败：%w", err)
	}
	p := &parsedURI{
		Secret:    k.Secret(),
		Issuer:    k.Issuer(),
		Label:     k.AccountName(),
		Algorithm: k.Algorithm().String(),
		Digits:    k.Digits().Length(),
		Period:    int(k.Period()),
	}
	if p.Algorithm == "" {
		p.Algorithm = "SHA1"
	}
	if p.Digits == 0 {
		p.Digits = 6
	}
	if p.Period == 0 {
		p.Period = 30
	}
	// 如果 issuer 为空但 label 里含 ":"（如 "GitHub:user"），拆分
	if p.Issuer == "" && strings.Contains(p.Label, ":") {
		parts := strings.SplitN(p.Label, ":", 2)
		p.Issuer = strings.TrimSpace(parts[0])
		p.Label = strings.TrimSpace(parts[1])
	}
	if err := validateSecretBase32(p.Secret); err != nil {
		return nil, err
	}
	return p, nil
}

// validateSecretBase32 仅校验编码格式（不调用 GenerateCode，避免对非标准大小写报错）。
func validateSecretBase32(secret string) error {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if secret == "" {
		return errors.New("secret 为空")
	}
	if _, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret); err != nil {
		return fmt.Errorf("secret 不是合法 Base32：%w", err)
	}
	return nil
}

// randRead 包内可替换的随机数入口（便于测试）。
var randRead = cryptoRandRead

// cryptoRandRead 读取密码学随机数（crypto/rand.Read 的包装，便于 mock）。
func cryptoRandRead(b []byte) (int, error) {
	return crand.Read(b)
}
