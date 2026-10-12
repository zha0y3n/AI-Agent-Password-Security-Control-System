// Command mock-upstream 启动受保护的 Mock Git / Mock DB 服务。
// 期望的 Credential 通过 MOCK_GIT_TOKEN / MOCK_DB_TOKEN 配置，需与录入 Broker Vault 的值一致。
package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
)

func main() {
	addr := os.Getenv("MOCK_ADDR")
	if addr == "" {
		addr = ":9090"
	}
	gitToken, dbToken := os.Getenv("MOCK_GIT_TOKEN"), os.Getenv("MOCK_DB_TOKEN")
	if gitToken == "" || dbToken == "" {
		slog.Error("MOCK_GIT_TOKEN and MOCK_DB_TOKEN are required")
		os.Exit(1)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           upstream.NewMock(gitToken, dbToken).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	slog.Info("mock upstream listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("mock upstream exited", "error", err.Error())
		os.Exit(1)
	}
}
