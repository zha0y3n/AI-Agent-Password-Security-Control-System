package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/api"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/logging"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
)

const adminToken = "test-admin-token-0123456789"
const plaintext = "ghp_PLAINTEXT_MARKER"

type client struct {
	t   *testing.T
	url string
}

func (c client) do(method, path, token string, body any) (int, string) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rd = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, c.url+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func setup(t *testing.T) (client, *bytes.Buffer) {
	env := testenv.New(t)
	var logs bytes.Buffer
	srv := &api.Server{
		BrokerID:         "broker-01",
		AdminToken:       adminToken,
		Credentials:      env.Credentials,
		Challenges:       challenge.NewService(env.DB, time.Minute, "broker-01"),
		Auditor:          env.Auditor,
		Signer:           env.Signer,
		CheckpointSigner: env.CheckpointSigner,
		Metrics:          metrics.New(),
		Log:              logging.New(&logs, "debug"),
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return client{t: t, url: ts.URL}, &logs
}

func TestCredentialAdminFlow(t *testing.T) {
	c, logs := setup(t)
	create := map[string]string{"credential_id": "git-prod", "provider": "github", "secret": plaintext}

	if code, _ := c.do("POST", "/v1/credentials", "", create); code != 401 {
		t.Fatalf("no admin token: %d", code)
	}
	if code, _ := c.do("POST", "/v1/credentials", "wrong-token-wrong-token", create); code != 401 {
		t.Fatalf("wrong admin token: %d", code)
	}
	code, body := c.do("POST", "/v1/credentials", adminToken, create)
	if code != 201 || !strings.Contains(body, `"credential_epoch":1`) {
		t.Fatalf("create: %d %s", code, body)
	}
	if code, _ := c.do("POST", "/v1/credentials", adminToken, create); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	if code, _ := c.do("POST", "/v1/credentials", adminToken, map[string]string{"credential_id": "x", "provider": "p", "secret": "s", "extra": "1"}); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}

	code, body = c.do("POST", "/v1/credentials/git-prod/rotate", adminToken, map[string]string{"secret": plaintext + "2"})
	if code != 200 || !strings.Contains(body, `"credential_epoch":2`) {
		t.Fatalf("rotate: %d %s", code, body)
	}
	code, body = c.do("POST", "/v1/credentials/git-prod/disable", adminToken, nil)
	if code != 200 || !strings.Contains(body, `"DISABLED"`) {
		t.Fatalf("disable: %d %s", code, body)
	}
	if code, _ := c.do("POST", "/v1/credentials/git-prod/disable", adminToken, nil); code != 409 {
		t.Fatalf("disable twice: %d", code)
	}
	if code, _ := c.do("POST", "/v1/credentials/git-prod/explode", adminToken, nil); code != 409 {
		t.Fatalf("unknown action: %d", code)
	}
	if code, _ := c.do("POST", "/v1/credentials/missing/revoke", adminToken, nil); code != 404 {
		t.Fatalf("missing: %d", code)
	}

	code, body = c.do("GET", "/v1/credentials/git-prod/status", "", nil)
	if code != 200 || !strings.Contains(body, `"credential_epoch":3`) || !strings.Contains(body, `"DISABLED"`) {
		t.Fatalf("status: %d %s", code, body)
	}

	// 任何响应、审计导出、日志中都不得出现明文
	_, audit := c.do("GET", "/v1/audit", "", nil)
	for name, s := range map[string]string{"status": body, "audit": audit, "logs": logs.String()} {
		if strings.Contains(s, "PLAINTEXT_MARKER") {
			t.Fatalf("plaintext leaked via %s", name)
		}
	}
}

func TestAuditExportVerifiesWithPublishedKey(t *testing.T) {
	c, _ := setup(t)
	c.do("POST", "/v1/credentials", adminToken, map[string]string{"credential_id": "c1", "provider": "p", "secret": "s"})
	c.do("POST", "/v1/credentials/c1/revoke", adminToken, nil)
	if code, _ := c.do("POST", "/v1/audit/checkpoints", "", nil); code != 401 {
		t.Fatalf("checkpoint without admin: %d", code)
	}
	if code, _ := c.do("POST", "/v1/audit/checkpoints", adminToken, nil); code != 201 {
		t.Fatalf("checkpoint: %d", code)
	}

	var recs struct{ Records []evidence.Record }
	var cps struct{ Checkpoints []evidence.Checkpoint }
	var key struct {
		PublicKey     string `json:"public_key"`
		CheckpointKey struct {
			PublicKey string `json:"public_key"`
		} `json:"checkpoint_key"`
	}
	_, b := c.do("GET", "/v1/audit?from=1&limit=1000", "", nil)
	json.Unmarshal([]byte(b), &recs)
	_, b = c.do("GET", "/v1/audit/checkpoints", "", nil)
	json.Unmarshal([]byte(b), &cps)
	_, b = c.do("GET", "/v1/broker/public-key", "", nil)
	json.Unmarshal([]byte(b), &key)

	if key.CheckpointKey.PublicKey == "" || key.CheckpointKey.PublicKey == key.PublicKey {
		t.Fatal("checkpoint key must be published and differ from the receipt key")
	}
	pub, err := crypto.ParseSM2PublicKeyHex(key.CheckpointKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	receiptPub, err := crypto.ParseSM2PublicKeyHex(key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs.Records) != 2 || len(cps.Checkpoints) != 1 {
		t.Fatalf("records=%d checkpoints=%d", len(recs.Records), len(cps.Checkpoints))
	}
	if err := evidence.VerifyChain(recs.Records, cps.Checkpoints, pub); err != nil {
		t.Fatal(err)
	}
	// Receipt 密钥不签检查点：用它验证必须失败。
	if err := evidence.VerifyChain(recs.Records, cps.Checkpoints, receiptPub); err == nil {
		t.Fatal("checkpoint verified with the receipt key")
	}
	if code, _ := c.do("GET", "/v1/audit?limit=5000", "", nil); code != 400 {
		t.Fatalf("limit bound: %d", code)
	}
}

func TestChallengeAndHealth(t *testing.T) {
	c, _ := setup(t)
	code, body := c.do("POST", "/v1/challenge", "", map[string]string{"agent_id": "agent-01"})
	if code != 201 || !strings.Contains(body, `"challenge"`) {
		t.Fatalf("challenge: %d %s", code, body)
	}
	if code, _ := c.do("POST", "/v1/challenge", "", map[string]string{}); code != 400 {
		t.Fatalf("empty agent: %d", code)
	}
	if code, body := c.do("GET", "/health", "", nil); code != 200 || !strings.Contains(body, "broker-01") {
		t.Fatalf("health: %d %s", code, body)
	}
	if code, _ := c.do("GET", "/v1/metrics", "", nil); code != 200 {
		t.Fatalf("metrics: %d", code)
	}
}
