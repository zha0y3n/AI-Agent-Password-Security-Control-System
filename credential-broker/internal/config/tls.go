package config

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// TLSEnabled 表示是否以 HTTPS 监听。
func (c *Config) TLSEnabled() bool { return c.TLSCertFile != "" }

// ServerTLS 构造 Broker 的 TLS 配置；未启用 TLS 时返回 nil。
// 证书、私钥或客户端 CA 任一无法加载都返回错误（启动 fail closed）。
//
// 这是标准 TLS（最低 1.2），用于保护 A 的 BROKER_LIVE 状态查询等传输通道；
// 协议层的签名与摘要仍是 SM2 / SM3，与传输层无关。
func (c *Config) ServerTLS() (*tls.Config, error) {
	if !c.TLSEnabled() {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load BROKER_TLS_CERT_FILE / BROKER_TLS_KEY_FILE: %w", err)
	}
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if c.TLSClientCAFile != "" {
		pem, err := os.ReadFile(c.TLSClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read BROKER_TLS_CLIENT_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("BROKER_TLS_CLIENT_CA_FILE contains no PEM certificates")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}
