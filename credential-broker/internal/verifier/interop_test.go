package verifier_test

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/execution"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

// TestInteropWithPythonAA 用 A 的真实 Python 代码签发的 bundle 走完整 Broker 执行路径。
// 由 `make interop` 生成数据并设置 BROKER_TEST_A_INTEROP_DIR；未设置时跳过。
func TestInteropWithPythonAA(t *testing.T) {
	dir := os.Getenv("BROKER_TEST_A_INTEROP_DIR")
	if dir == "" {
		t.Skip("BROKER_TEST_A_INTEROP_DIR not set (run `make interop`)")
	}
	reg, err := protocol.LoadKeyRegistry(filepath.Join(dir, "public-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	metaRaw, err := os.ReadFile(filepath.Join(dir, "interop.json"))
	if err != nil {
		t.Fatal(err)
	}
	metaVal, err := canonical.Parse(metaRaw)
	if err != nil {
		t.Fatal(err)
	}
	meta := metaVal.(map[string]any)
	parsed, perr := protocol.ParseExecutionBundle(raw)
	if perr != nil {
		t.Fatalf("Go rejected A's bundle at schema level: %v", perr)
	}
	capb := parsed.Capability.Body

	env := testenv.New(t)
	// A 的可信任务库把 epoch 写死为 17（尚待 A/B 对齐）；这里把测试 Credential 轮换到同一 epoch。
	info, err := env.Credentials.Create(ctx, capb.CredentialID, "github", secret.Secret("git-token"))
	if err != nil {
		t.Fatal(err)
	}
	for info.Epoch < capb.CredentialEpoch {
		if info, err = env.Credentials.Rotate(ctx, capb.CredentialID, secret.Secret("git-token")); err != nil {
			t.Fatal(err)
		}
	}
	// 预置 A 侧使用的 Challenge（生产中由 POST /v1/challenge 签发）。
	if _, err := env.DB.ExecContext(ctx,
		`INSERT INTO challenges(challenge, agent_id, audience, expires_at, used, created_at) VALUES (?, ?, ?, ?, 0, ?)`,
		meta["challenge"], meta["agent_id"], capb.Audience, time.Now().Add(time.Minute).Unix(), time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	mock := upstream.NewMock("git-token", "db-token")
	srv := httptest.NewServer(mock.Handler())
	t.Cleanup(srv.Close)
	client := upstream.NewClient(srv.URL, 5*time.Second)
	m := metrics.New()
	exec := &execution.Executor{
		Pipeline: verifier.New(m, verifier.Steps(verifier.Config{
			BrokerID: capb.Audience, TrustedIssuer: meta["issuer_id"].(string), Keys: reg,
			Challenges: challenge.NewService(env.DB, time.Minute, capb.Audience),
		})...),
		Store: capability.NewStore(env.DB, env.Auditor), Credentials: env.Credentials,
		Upstream: client, Audit: env.Auditor, Metrics: m,
	}
	run := func(body []byte) *execution.Outcome {
		out, err := exec.Execute(ctx, &verifier.Input{Body: body, Now: time.Now()})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 篡改：把请求路径改成同仓库的另一个文件（先跑，不消耗 Challenge）。
	tampered := []byte(strings.Replace(string(raw), "/files/README.md", "/files/secret.txt", 1))
	if d := run(tampered).Decision; d.Allowed || d.Code != protocol.CodeRequestHash {
		t.Fatalf("tampered A bundle: %+v", d)
	}

	out := run(raw)
	if !out.Decision.Allowed || !out.CredentialLoaded || out.Result.Status != 200 ||
		!strings.Contains(string(out.Result.Body), "course-project") {
		t.Fatalf("A bundle not executed: %+v", out.Decision)
	}
	if d := run(raw).Decision; d.Allowed || d.Code != errcode.ChallengeUsed {
		t.Fatalf("replayed A bundle: %+v", d)
	}
	if client.Calls() != 1 {
		t.Fatalf("upstream calls = %d", client.Calls())
	}
}
