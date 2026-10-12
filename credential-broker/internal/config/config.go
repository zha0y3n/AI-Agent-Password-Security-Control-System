// Package config 从环境变量加载 Broker 配置。密钥类配置只来自环境 / 文件，不写入代码与日志。
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
)

// Config 是 Broker 配置。
type Config struct {
	BrokerID        string
	Addr            string
	DBPath          string
	SigningKeyFile  string
	VaultKey        []byte // K_V，16 字节
	AdminToken      string
	ChallengeTTL    time.Duration
	CheckpointEvery int
	UpstreamURL     string
	UpstreamTimeout time.Duration
	LogLevel        string
}

// Load 读取并校验配置。
func Load() (*Config, error) {
	c := &Config{
		BrokerID:       env("BROKER_ID", "broker-01"),
		Addr:           env("BROKER_ADDR", ":8080"),
		DBPath:         env("BROKER_DB_PATH", "data/broker.db"),
		SigningKeyFile: env("BROKER_SIGNING_KEY_FILE", "data/broker-sm2.key"),
		AdminToken:     os.Getenv("BROKER_ADMIN_TOKEN"),
		UpstreamURL:    env("BROKER_UPSTREAM_URL", "http://127.0.0.1:9090"),
		LogLevel:       env("BROKER_LOG_LEVEL", "info"),
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
