// Package config 从环境变量加载 Broker 配置。密钥类配置只来自环境 / 文件，不写入代码与日志。
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
)

// Config 是 Broker 配置。
type Config struct {
	BrokerID       string
	Addr           string
	DBPath         string
	SigningKeyFile string // Receipt 签名私钥（对外公布为 RECEIPT_SIGNING）
	// CheckpointKeyFile 是审计检查点的签名私钥。A 的公钥模型中 RECEIPT_SIGNING 只用于回执，
	// 检查点因此使用独立密钥，两者不得是同一文件。
	CheckpointKeyFile string
	VaultKey          []byte // K_V，16 字节
	AdminToken        string
	ChallengeTTL      time.Duration
	CheckpointEvery   int
	UpstreamURL       string
	UpstreamTimeout   time.Duration
	LogLevel          string

	// Receipt 签名密钥的标识与有效期（对外公布为 A 格式的 PublicKeyRecord）。
	KeyID       string
	KeyValidity time.Duration
	// RetiredKeysPath 是以前的 Receipt 签名公钥（A 的 KeyRegistryDocument 格式），可选。
	RetiredKeysPath string

	// 执行接口：可信 AA 的 issuer 与 AA / Agent 公钥表（A 的 public-keys.json 格式）。
	// 两者都未配置时 POST /v1/execute 返回 503（fail closed）。
	TrustedIssuer   string
	KeyRegistryPath string
	ClockSkew       time.Duration

	// EnableReset 开放 POST /v1/admin/reset，只用于开发 / 实验环境。
	EnableReset bool

	// 传输层：证书与私钥同时设置时 Broker 以 HTTPS 监听；再设置 TLSClientCAFile 时
	// 要求并校验客户端证书（mTLS）。都未设置时为明文 HTTP（仅限本机 / 容器内演示）。
	TLSCertFile     string
	TLSKeyFile      string
	TLSClientCAFile string
}

// Load 读取并校验配置。
func Load() (*Config, error) {
	c := &Config{
		BrokerID:          env("BROKER_ID", "broker-01"),
		Addr:              env("BROKER_ADDR", ":8080"),
		DBPath:            env("BROKER_DB_PATH", "data/broker.db"),
		SigningKeyFile:    env("BROKER_SIGNING_KEY_FILE", "data/broker-sm2.key"),
		CheckpointKeyFile: env("BROKER_CHECKPOINT_KEY_FILE", "data/broker-checkpoint-sm2.key"),
		AdminToken:        os.Getenv("BROKER_ADMIN_TOKEN"),
		UpstreamURL:       env("BROKER_UPSTREAM_URL", "http://127.0.0.1:9090"),
		LogLevel:          env("BROKER_LOG_LEVEL", "info"),
		KeyID:             env("BROKER_KEY_ID", "broker-key-01"),
		RetiredKeysPath:   os.Getenv("BROKER_RETIRED_KEYS"),

		TrustedIssuer:   os.Getenv("BROKER_TRUSTED_ISSUER"),
		KeyRegistryPath: os.Getenv("BROKER_KEY_REGISTRY"),

		TLSCertFile:     os.Getenv("BROKER_TLS_CERT_FILE"),
		TLSKeyFile:      os.Getenv("BROKER_TLS_KEY_FILE"),
		TLSClientCAFile: os.Getenv("BROKER_TLS_CLIENT_CA_FILE"),
	}
	var err error
	if c.VaultKey, err = hex.DecodeString(os.Getenv("BROKER_VAULT_KEY")); err != nil || len(c.VaultKey) != crypto.SM4KeySize {
		return nil, fmt.Errorf("BROKER_VAULT_KEY must be %d hex characters (e.g. openssl rand -hex 16)", crypto.SM4KeySize*2)
	}
	if len(c.AdminToken) < 16 {
		return nil, fmt.Errorf("BROKER_ADMIN_TOKEN must be at least 16 characters")
	}
	if c.ChallengeTTL, err = duration("BROKER_CHALLENGE_TTL", 60*time.Second); err != nil {
		return nil, err
	}
	if c.UpstreamTimeout, err = duration("BROKER_UPSTREAM_TIMEOUT", 10*time.Second); err != nil {
		return nil, err
	}
	if c.CheckpointEvery, err = integer("BROKER_CHECKPOINT_EVERY", 100); err != nil {
		return nil, err
	}
	if c.KeyValidity, err = duration("BROKER_KEY_VALIDITY", 365*24*time.Hour); err != nil {
		return nil, err
	}
	if c.ClockSkew, err = duration("BROKER_CLOCK_SKEW", 5*time.Second); err != nil {
		return nil, err
	}
	if filepath.Clean(c.CheckpointKeyFile) == filepath.Clean(c.SigningKeyFile) {
		return nil, fmt.Errorf("BROKER_CHECKPOINT_KEY_FILE must differ from BROKER_SIGNING_KEY_FILE")
	}
	if (c.TrustedIssuer == "") != (c.KeyRegistryPath == "") {
		return nil, fmt.Errorf("BROKER_TRUSTED_ISSUER and BROKER_KEY_REGISTRY must be set together")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return nil, fmt.Errorf("BROKER_TLS_CERT_FILE and BROKER_TLS_KEY_FILE must be set together")
	}
	if c.TLSClientCAFile != "" && c.TLSCertFile == "" {
		return nil, fmt.Errorf("BROKER_TLS_CLIENT_CA_FILE requires BROKER_TLS_CERT_FILE and BROKER_TLS_KEY_FILE")
	}
	switch v := os.Getenv("BROKER_ENABLE_RESET"); v {
	case "", "0", "false":
	case "1", "true":
		c.EnableReset = true
	default:
		return nil, fmt.Errorf("BROKER_ENABLE_RESET: invalid boolean %q", v)
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func duration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: invalid duration %q", key, v)
	}
	return d, nil
}

func integer(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: invalid integer %q", key, v)
	}
	return n, nil
}
