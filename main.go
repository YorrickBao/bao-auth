// Command bao-auth 是一个单二进制的 Web 版 TOTP 验证器。
//
// 前端静态文件通过 go:embed 打包进二进制；数据存于本地 SQLite，
// secret 用主密码派生的 KEK 经 AES-256-GCM 加密。部署只需一个可执行文件。
package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"baoauth/internal/auth"
	"baoauth/internal/server"
	"baoauth/internal/store"
)

//go:embed all:public
var publicFS embed.FS

func main() {
	addr := flag.String("addr", "127.0.0.1:3000", "监听地址")
	dataDir := flag.String("data", "./data", "数据目录（存放 SQLite 文件）")
	prefix := flag.String("prefix", "", "URL 路径前缀，用于反代子路径部署（如 /otp）；默认根路径")
	flag.Parse()

	// 规范化前缀：保证以 / 开头，去掉结尾 /（根路径时为空串）
	p := strings.TrimRight(*prefix, "/")
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	// 确保数据目录存在
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("创建数据目录失败: %v", err)
	}
	dbPath := filepath.Join(*dataDir, "bao-auth.db")

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}
	defer st.Close()

	vault, err := auth.NewVault()
	if err != nil {
		log.Fatalf("初始化保险库失败: %v", err)
	}

	mux := http.NewServeMux()
	api := server.New(st, vault, p)
	api.Register(mux)

	// 静态文件：从 embed 取 public/。带前缀时用 StripPrefix 剥前缀。
	pubRoot, err := fs.Sub(publicFS, "public")
	if err != nil {
		log.Fatalf("加载静态资源失败: %v", err)
	}

	// index.html 需动态注入路径前缀（替换 __BASE_PATH__），在启动时读取并替换一次。
	indexHTML, err := fs.ReadFile(pubRoot, "index.html")
	if err != nil {
		log.Fatalf("读取 index.html 失败: %v", err)
	}
	indexHTML = []byte(strings.ReplaceAll(string(indexHTML), `"__BASE_PATH__"`, `"`+p+`"`))

	fileServer := http.FileServer(http.FS(pubRoot))
	// indexHandler 拦截根路径请求返回注入前缀的 index.html，其余交给 FileServer。
	indexHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 归一化：剥掉前缀后判断是否为根或 index.html
		rel := strings.TrimPrefix(r.URL.Path, p)
		if rel == "" || rel == "/" || rel == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(indexHTML)
			return
		}
		fileServer.ServeHTTP(w, r)
	})

	if p == "" {
		mux.Handle("/", indexHandler)
	} else {
		mux.Handle(p+"/", http.StripPrefix(p+"/", indexHandler))
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withLogging(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 优雅关闭
	go func() {
		base := *addr + p
		log.Printf("bao-auth 监听 http://%s (数据: %s)", base, dbPath)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("服务器启动失败: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("正在关闭...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("关闭异常: %v", err)
	}
	log.Println("已退出")
}

// withLogging 简单访问日志中间件。
func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}
