// Command mock-upstream 启动受保护的 Mock Git / Mock DB 服务。
// 期望的 Credential 通过 MOCK_GIT_TOKEN / MOCK_DB_TOKEN 配置，需与录入 Broker Vault 的值一致。
package main

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/config"
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
	mock := upstream.NewMock(gitToken, dbToken)
	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 5 * time.Second,
	}
	// 可选 TLS：MOCK_TLS_CERT_FILE + MOCK_TLS_KEY_FILE；再设置 MOCK_TLS_CLIENT_CA_FILE 时，
	// Git / DB 接口只接受该 CA 签发的客户端证书（模拟“上游只接受来自 Broker 的连接”）。
	certFile, keyFile, caFile := os.Getenv("MOCK_TLS_CERT_FILE"), os.Getenv("MOCK_TLS_KEY_FILE"), os.Getenv("MOCK_TLS_CLIENT_CA_FILE")
	if (certFile == "") != (keyFile == "") || (caFile != "" && certFile == "") {
		slog.Error("MOCK_TLS_CERT_FILE and MOCK_TLS_KEY_FILE must be set together; MOCK_TLS_CLIENT_CA_FILE requires both")
		os.Exit(1)
	}
	if certFile != "" {
		// VerifyClientCertIfGiven：实验接口仍可无证书访问，受保护接口在 Mock.auth 中强制要求证书。
		tlsCfg, err := config.ServerTLSConfig(certFile, keyFile, caFile, tls.VerifyClientCertIfGiven)
		if err != nil {
			slog.Error("mock upstream TLS", "error", err.Error())
			os.Exit(1)
		}
		srv.TLSConfig = tlsCfg
		mock.RequireClientCert = caFile != ""
	}
	srv.Handler = mock.Handler()
	slog.Info("mock upstream listening", "addr", addr, "tls", certFile != "", "require_client_cert", mock.RequireClientCert)
	var err error
	if srv.TLSConfig != nil {
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil {
		slog.Error("mock upstream exited", "error", err.Error())
		os.Exit(1)
	}
}
