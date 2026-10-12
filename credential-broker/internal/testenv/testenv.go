// Package testenv 为各模块测试搭建隔离的 Broker 依赖（临时 SQLite、Vault、审计、Credential 服务）。
package testenv

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/vault"
)

// Env 聚合测试所需依赖。
type Env struct {
	DB          *repository.DB
	Vault       *vault.Vault
	Signer      *crypto.SM2Signer
	Auditor     *evidence.Auditor
	Credentials *credential.Service
}

// New 创建一套全新的依赖，测试结束自动清理。
func New(t testing.TB) *Env {
	t.Helper()
	db, err := repository.Open(filepath.Join(t.TempDir(), "broker.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	v, err := vault.New(bytes.Repeat([]byte{0x5a}, crypto.SM4KeySize))
	if err != nil {
		t.Fatal(err)
	}
	signer, err := crypto.GenerateSM2Signer()
	if err != nil {
		t.Fatal(err)
	}
	a := evidence.NewAuditor(db, signer, 0)
	return &Env{DB: db, Vault: v, Signer: signer, Auditor: a, Credentials: credential.NewService(db, v, a)}
}
