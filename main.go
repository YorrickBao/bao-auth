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
	flag.Parse()

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
	api := server.New(st, vault)
	api.Register(mux)

	// 静态文件：从 embed 取 public/，根路径返回 index.html
	pubRoot, err := fs.Sub(publicFS, "public")
	if err != nil {
		log.Fatalf("加载静态资源失败: %v", err)
	}
	mux.Handle("/", http.FileServer(http.FS(pubRoot)))

	srv := &http.Server{
		Addr:              *addr,
		Handler:           withLogging(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// 优雅关闭
	go func() {
		log.Printf("bao-auth 监听 http://%s (数据: %s)", *addr, dbPath)
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
