package execution_test

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/execution"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

var ctx = context.Background()

type harness struct {
	env      *testenv.Env
	mock     *upstream.Mock
	client   *upstream.Client
	executor *execution.Executor
	laterRan atomic.Bool
}

// newHarness 用桩步骤搭建执行器。reject 非空时第一个步骤拒绝。
func newHarness(t *testing.T, reject string) *harness {
	t.Helper()
	env := testenv.New(t)
	if _, err := env.Credentials.Create(ctx, "git-prod", "github", secret.Secret("git-token")); err != nil {
		t.Fatal(err)
	}
	mock := upstream.NewMock("git-token", "db-token")
	srv := httptest.NewServer(mock.Handler())
	t.Cleanup(srv.Close)
	h := &harness{env: env, mock: mock, client: upstream.NewClient(srv.URL, 5*time.Second)}

	stubSignature := verifier.StepFunc{StepName: "capability_signature", Fn: func(_ context.Context, in *verifier.Input) *verifier.Denial {
		if reject != "" {
			return &verifier.Denial{Code: reject, Reason: "stub rejection"}
		}
		return nil
	}}
	stubPlan := verifier.StepFunc{StepName: "request_binding", Fn: func(_ context.Context, in *verifier.Input) *verifier.Denial {
		h.laterRan.Store(true)
		in.Plan = &verifier.Plan{
			Claim: capability.Claim{CapID: string(in.Body), RequestHash: "h-" + string(in.Body), CredentialID: "git-prod", CredentialEpoch: 1},
			Call: upstream.Call{Service: "git", Operation: "write_file", Resource: "repo-A",
				Args: map[string]string{"path": "out.txt", "content": "x"}, CapID: string(in.Body), RequestHash: "h-" + string(in.Body)},
		}
		return nil
	}}
	m := metrics.New()
	h.executor = &execution.Executor{
		Pipeline:    verifier.New(m, stubSignature, stubPlan),
		Store:       capability.NewStore(env.DB, env.Auditor),
		Credentials: env.Credentials,
		Upstream:    h.client,
		Audit:       env.Auditor,
		Metrics:     m,
	}
	return h
}

func (h *harness) run(t *testing.T, capID string) *execution.Outcome {
	t.Helper()
	out, err := h.executor.Execute(ctx, &verifier.Input{Body: []byte(capID)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDeniedRequestNeverTouchesCredential(t *testing.T) {
	h := newHarness(t, "CAPABILITY_SIGNATURE_INVALID")
	opensBefore := h.env.Vault.Opens()
	out := h.run(t, "cap-1")

	if out.Decision.Allowed || out.Decision.FailedStep != "capability_signature" || out.CredentialLoaded {
		t.Fatalf("unexpected: %+v", out)
	}
	if h.laterRan.Load() {
		t.Error("later steps ran after rejection")
	}
	if h.env.Vault.Opens() != opensBefore || h.client.Calls() != 0 || h.mock.Stats().SideEffects != 0 {
		t.Fatalf("rejected request reached vault/upstream: opens=%d calls=%d", h.env.Vault.Opens()-opensBefore, h.client.Calls())
	}
}

func TestAllowedRequestExecutesExactlyOnce(t *testing.T) {
	h := newHarness(t, "")
	out := h.run(t, "cap-ok")
	if !out.Decision.Allowed || !out.CredentialLoaded || out.Result.Status != 200 || out.Replayed {
		t.Fatalf("unexpected: %+v", out)
	}
	// 重放同一 Capability：返回旧结果，不再读取 Credential、不再产生副作用
	opens := h.env.Vault.Opens()
	again := h.run(t, "cap-ok")
	if !again.Replayed || again.CredentialLoaded || again.Result.Status != 200 {
		t.Fatalf("replay: %+v", again)
	}
	if h.env.Vault.Opens() != opens || h.mock.Stats().ByCapability["cap-ok"] != 1 {
		t.Fatal("replay produced new credential use or side effect")
	}
	if len(out.Decision.Steps) != 2 {
		t.Fatalf("steps: %+v", out.Decision.Steps)
	}
}

func TestConcurrentReplayOneSideEffect(t *testing.T) {
	h := newHarness(t, "")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); h.run(t, "cap-race") }()
	}
	wg.Wait()
	if n := h.mock.Stats().ByCapability["cap-race"]; n != 1 {
		t.Fatalf("side effects = %d, want 1", n)
	}
}

func TestRevokedCredentialDeniedBeforeDecrypt(t *testing.T) {
	h := newHarness(t, "")
	if _, err := h.env.Credentials.Apply(ctx, "git-prod", credential.ActionRevoke); err != nil {
		t.Fatal(err)
	}
	opens := h.env.Vault.Opens()
	out := h.run(t, "cap-rev")
	if out.Decision.Allowed || out.Decision.Code != errcode.CredentialInactive || out.CredentialLoaded {
		t.Fatalf("unexpected: %+v", out)
	}
	if h.env.Vault.Opens() != opens || h.client.Calls() != 0 {
		t.Fatal("revoked credential was decrypted or used")
	}
}

func TestDecisionsAreAudited(t *testing.T) {
	h := newHarness(t, "")
	h.run(t, "cap-a")
	h.env.Credentials.Apply(ctx, "git-prod", credential.ActionDisable)
	h.run(t, "cap-b")

	rs, _ := h.env.Auditor.Records(ctx, 1, 100)
	types := map[string]int{}
	for _, r := range rs {
		for _, typ := range []string{"capability.consume", "capability.complete", "execute.deny"} {
			if strings.Contains(r.Entry, `"type":"`+typ+`"`) {
				types[typ]++
			}
		}
	}
	if types["capability.consume"] != 1 || types["capability.complete"] != 1 || types["execute.deny"] != 1 {
		t.Fatalf("audit types: %v", types)
	}
	cps, _ := h.env.Auditor.Checkpoints(ctx)
	if err := evidence.VerifyChain(rs, cps, h.env.CheckpointSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
}
