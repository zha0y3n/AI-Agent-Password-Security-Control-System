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
	clientAuth := tls.NoClientCert
	if c.TLSClientCAFile != "" {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	return ServerTLSConfig(c.TLSCertFile, c.TLSKeyFile, c.TLSClientCAFile, clientAuth)
}

// UpstreamTLS 构造 Broker 调用上游时的 TLS 配置；未配置任何上游 TLS 项时返回 nil（使用系统信任库）。
func (c *Config) UpstreamTLS() (*tls.Config, error) {
	if c.UpstreamCAFile == "" && c.UpstreamClientCertFile == "" {
		return nil, nil
	}
	return ClientTLSConfig(c.UpstreamCAFile, c.UpstreamClientCertFile, c.UpstreamClientKeyFile)
}

// ServerTLSConfig 加载服务端证书；clientCAFile 非空时按 clientAuth 校验客户端证书。
func ServerTLSConfig(certFile, keyFile, clientCAFile string, clientAuth tls.ClientAuthType) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate / key: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}}
	if clientCAFile != "" {
		if cfg.ClientCAs, err = loadPool(clientCAFile); err != nil {
			return nil, err
		}
		cfg.ClientAuth = clientAuth
	}
	return cfg, nil
}

// ClientTLSConfig 构造客户端 TLS 配置：caFile 非空时只信任该 CA；certFile / keyFile 为出示的客户端证书。
func ClientTLSConfig(caFile, certFile, keyFile string) (*tls.Config, error) {
	if (certFile == "") != (keyFile == "") {
		return nil, errors.New("client certificate and key must be set together")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := loadPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate / key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}

func loadPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s contains no PEM certificates", path)
	}
	return pool, nil
}
