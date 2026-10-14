package api_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/api"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/execution"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/logging"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/receipt"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

const gitToken = "ghp_GIT_TOKEN_MARKER"

// execEnv 是带执行接口的完整 Broker（真实流水线、Vault、Mock 上游、回执）。
type execEnv struct {
	client
	aa, agent *crypto.SM2Signer
	mock      *upstream.Mock
	logs      *bytes.Buffer
}

func setupExec(t *testing.T, enableReset bool) *execEnv {
	t.Helper()
	env := testenv.New(t)
	e := &execEnv{logs: &bytes.Buffer{}}
	var err error
	if e.aa, err = crypto.GenerateSM2Signer(); err != nil {
		t.Fatal(err)
	}
	if e.agent, err = crypto.GenerateSM2Signer(); err != nil {
		t.Fatal(err)
	}
	record := func(keyID, subject, purpose string, s *crypto.SM2Signer) map[string]any {
		pemKey, _ := crypto.MarshalSM2PublicKeyPEM(s.PublicKey())
		return map[string]any{"key_id": keyID, "subject_id": subject, "purpose": purpose, "algorithm": "SM2",
			"status": "ACTIVE", "public_key_pem": pemKey, "not_before": int64(0), "not_after": time.Now().Add(time.Hour).Unix()}
	}
	doc, _ := canonical.Marshal(map[string]any{"protocol_version": "1.0", "keys": []any{
		record("aa-key-01", "aa-01", protocol.KeyPurposeCapability, e.aa),
		record("agent-key-01", "agent-01", protocol.KeyPurposeHolderProof, e.agent),
	}})
	keys, err := protocol.ParseKeyRegistry(doc)
	if err != nil {
		t.Fatal(err)
	}

	e.mock = upstream.NewMock(gitToken, "db-token")
	up := httptest.NewServer(e.mock.Handler())
	t.Cleanup(up.Close)

	m := metrics.New()
	challenges := challenge.NewService(env.DB, time.Minute, "broker-01")
	store := capability.NewStore(env.DB, env.Auditor)
	now := time.Now().Unix()
	srv := &api.Server{
		BrokerID: "broker-01", AdminToken: adminToken,
		Credentials: env.Credentials, Challenges: challenges, Auditor: env.Auditor, Signer: env.Signer,
		Metrics: m, Log: logging.New(e.logs, "debug"),
		KeyID: "broker-key-01", KeyNotBefore: now - 60, KeyNotAfter: now + 3600,
		Capabilities: store,
		Executor: &execution.Executor{
			Pipeline: verifier.New(m, verifier.Steps(verifier.Config{
				BrokerID: "broker-01", TrustedIssuer: "aa-01", Keys: keys, Challenges: challenges,
			})...),
			Store: store, Credentials: env.Credentials, Audit: env.Auditor, Metrics: m,
			Upstream: upstream.NewClient(up.URL, 5*time.Second),
			Receipts: &receipt.Issuer{BrokerID: "broker-01", KeyID: "broker-key-01", Signer: env.Signer},
		},
	}
	if enableReset {
		srv.ResetDB = env.DB
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	e.client = client{t: t, url: ts.URL}
	return e
}

func (e *execEnv) post(path string, raw []byte) (int, string) {
	e.t.Helper()
	resp, err := http.Post(e.url+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// bundle 走 Agent 的完整流程：向 Broker 申请 Challenge，用 AA 签 Capability，用 Agent 签 Holder Proof。
func (e *execEnv) bundle(epoch int64) []byte {
	e.t.Helper()
	code, body := e.do("POST", "/v1/challenge", "", map[string]string{"agent_id": "agent-01"})
	if code != 201 {
		e.t.Fatalf("challenge: %d %s", code, body)
	}
	var ch challenge.Challenge
	json.Unmarshal([]byte(body), &ch)

	rnd := func() string { b := make([]byte, 16); rand.Read(b); return hex.EncodeToString(b) }
	req := &protocol.AgentRequest{
		ProtocolVersion: "1.0", RequestID: "req-" + rnd(), AgentID: "agent-01", AgentKeyID: "agent-key-01",
		TaskID: "task-demo-001", Service: "git", Resource: "repo/course-project", Operation: "read_file",
		Method: "GET", Path: "/repos/course-project/files/README.md", Query: map[string]any{}, CredentialID: "github-prod",
	}
	reqHash, _ := protocol.RequestHash(req)
	now := time.Now().Unix()
	cb := &protocol.CapabilityBody{
		ProtocolVersion: "1.0", CapabilityID: "cap_" + rnd(), Issuer: "aa-01", IssuerKeyID: "aa-key-01",
		Audience: "broker-01", AgentID: req.AgentID, AgentKeyID: req.AgentKeyID, TaskID: req.TaskID,
		Service: req.Service, Resource: req.Resource, Operation: req.Operation, RequestHash: reqHash,
		CredentialID: req.CredentialID, CredentialEpoch: epoch,
		IssuedAt: now, ExpiresAt: now + 60, TTLSeconds: 60, Nonce: rnd(), OneTime: true,
	}
	capSig, _ := protocol.Sign(e.aa, "aa-key-01", protocol.PurposeCapability, cb)
	cap := &protocol.SignedCapability{Body: cb, Signature: capSig}
	capHash, _ := protocol.CapabilityHash(cap)
	pb := &protocol.HolderProofBody{
		ProtocolVersion: "1.0", ProofID: "proof_" + rnd(), CapabilityID: cb.CapabilityID, CapabilityHash: capHash,
		AgentID: req.AgentID, AgentKeyID: req.AgentKeyID, Audience: "broker-01", RequestHash: reqHash,
		Challenge: ch.Challenge, IssuedAt: now, ExpiresAt: now + 30,
	}
	proofSig, _ := protocol.Sign(e.agent, "agent-key-01", protocol.PurposeHolderProof, pb)
	raw, err := protocol.Canonical(&protocol.ExecutionBundle{Request: req, Capability: cap,
		HolderProof: &protocol.HolderProof{Body: pb, Signature: proofSig}})
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

type executeResponse struct {
	Decision struct {
		Allowed    bool   `json:"allowed"`
		FailedStep string `json:"failed_step"`
		Code       string `json:"code"`
	} `json:"decision"`
	Replayed       bool            `json:"replayed"`
	ResultEnvelope json.RawMessage `json:"result_envelope"`
	Receipt        json.RawMessage `json:"receipt"`
}

func TestExecuteOverHTTP(t *testing.T) {
	e := setupExec(t, false)
	code, body := e.do("POST", "/v1/credentials", adminToken,
		map[string]string{"credential_id": "github-prod", "provider": "github", "secret": gitToken})
	if code != 201 {
		t.Fatalf("create credential: %d %s", code, body)
	}

	raw := e.bundle(1)
	code, body = e.post("/v1/execute", raw)
	var out executeResponse
	json.Unmarshal([]byte(body), &out)
	if code != 200 || !out.Decision.Allowed || !strings.Contains(string(out.ResultEnvelope), "course-project") {
		t.Fatalf("execute: %d %s", code, body)
	}

	// Agent / C 的视角：只用公开接口拿到的公钥记录复核回执。
	_, regBody := e.do("GET", "/v1/broker/key-registry", "", nil)
	reg, err := protocol.ParseKeyRegistry([]byte(regBody))
	if err != nil {
		t.Fatalf("published key registry is not in A's format: %v\n%s", err, regBody)
	}
	r, perr := protocol.ParseSignedReceipt(out.Receipt)
	if perr != nil {
		t.Fatal(perr)
	}
	pub, perr := reg.Lookup(r.Body.BrokerKeyID, protocol.KeyPurposeReceipt, r.Body.BrokerID, r.Body.ExecutedAt)
	if perr != nil {
		t.Fatal(perr)
	}
	if perr := protocol.VerifySignature(pub, protocol.PurposeReceipt, r.Body, r.Signature); perr != nil {
		t.Fatal(perr)
	}
	if r.Body.Outcome != receipt.OutcomeSuccess || r.Body.ResultHash != crypto.SM3Hex(out.ResultEnvelope) {
		t.Fatalf("receipt: %+v", r.Body)
	}

	// 原样重放 -> 403 CHALLENGE_USED，仍有 DENIED 回执。
	code, body = e.post("/v1/execute", raw)
	out = executeResponse{}
	json.Unmarshal([]byte(body), &out)
	if code != 403 || out.Decision.Code != "CHALLENGE_USED" || !strings.Contains(string(out.Receipt), `"DENIED"`) {
		t.Fatalf("replay: %d %s", code, body)
	}
	// 非规范 JSON -> 400，无回执。
	if code, body := e.post("/v1/execute", []byte(`{"request":1.5}`)); code != 400 || strings.Contains(body, `"receipt"`) {
		t.Fatalf("garbage: %d %s", code, body)
	}
	// 旧 Epoch -> 403。
	if code, body := e.post("/v1/execute", e.bundle(7)); code != 403 || !strings.Contains(body, "CREDENTIAL_EPOCH_MISMATCH") {
		t.Fatalf("old epoch: %d %s", code, body)
	}

	// Capability 状态（管理员）
	if code, _ := e.do("GET", "/v1/capabilities/"+r.Body.CapabilityID, "", nil); code != 401 {
		t.Fatalf("capability status without admin: %d", code)
	}
	code, body = e.do("GET", "/v1/capabilities/"+r.Body.CapabilityID, adminToken, nil)
	if code != 200 || !strings.Contains(body, `"CONSUMED"`) {
		t.Fatalf("capability status: %d %s", code, body)
	}
	if code, _ := e.do("GET", "/v1/capabilities/cap_never_seen", adminToken, nil); code != 404 {
		t.Fatalf("unknown capability: %d", code)
	}

	// 审计链复核、副作用统计
	code, body = e.do("GET", "/v1/audit/verify", "", nil)
	if code != 200 || !strings.Contains(body, `"valid":true`) {
		t.Fatalf("audit verify: %d %s", code, body)
	}
	if got := e.mock.Stats().Calls["git"]; got != 1 {
		t.Fatalf("upstream git calls = %d", got)
	}

	_, audit := e.do("GET", "/v1/audit?limit=1000", "", nil)
	for name, s := range map[string]string{"audit": audit, "logs": e.logs.String(), "response": body} {
		if strings.Contains(s, "GIT_TOKEN_MARKER") {
			t.Fatalf("credential leaked via %s", name)
		}
	}
}

func TestExecuteDisabled(t *testing.T) {
	c, _ := setup(t)
	code, body := c.do("POST", "/v1/execute", "", map[string]string{})
	if code != 503 || !strings.Contains(body, "EXECUTION_DISABLED") {
		t.Fatalf("execute without registry: %d %s", code, body)
	}
}

func TestAdminReset(t *testing.T) {
	c, _ := setup(t)
	if code, body := c.do("POST", "/v1/admin/reset", adminToken, nil); code != 403 || !strings.Contains(body, "RESET_DISABLED") {
		t.Fatalf("reset while disabled: %d %s", code, body)
	}

	e := setupExec(t, true)
	e.do("POST", "/v1/credentials", adminToken, map[string]string{"credential_id": "github-prod", "provider": "github", "secret": gitToken})
	if code, _ := e.post("/v1/execute", e.bundle(1)); code != 200 {
		t.Fatalf("execute: %d", code)
	}
	if code, _ := e.do("POST", "/v1/admin/reset", "", nil); code != 401 {
		t.Fatalf("reset without admin: %d", code)
	}
	if code, _ := e.do("POST", "/v1/admin/reset", adminToken, nil); code != 200 {
		t.Fatalf("reset: %d", code)
	}
	if code, _ := e.do("GET", "/v1/credentials/github-prod/status", "", nil); code != 404 {
		t.Fatalf("credential survived reset: %d", code)
	}
	if _, body := e.do("GET", "/v1/audit/verify", "", nil); !strings.Contains(body, `"entries":0`) {
		t.Fatalf("audit after reset: %s", body)
	}
	// 重置后可以重新录入并执行，审计链从 seq=1 重新开始且可复核。
	e.do("POST", "/v1/credentials", adminToken, map[string]string{"credential_id": "github-prod", "provider": "github", "secret": gitToken})
	if code, body := e.post("/v1/execute", e.bundle(1)); code != 200 {
		t.Fatalf("execute after reset: %d %s", code, body)
	}
	if _, body := e.do("GET", "/v1/audit/verify", "", nil); !strings.Contains(body, `"valid":true`) {
		t.Fatalf("audit after reset: %s", body)
	}
}
