package verifier_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/execution"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

var ctx = context.Background()

const (
	brokerID = "broker-01"
	issuerID = "aa-01"
	aaKeyID  = "aa-key-01"
	agentID  = "agent-01"
	agentKey = "agent-key-01"
	credID   = "github-prod"
)

type fixture struct {
	t          *testing.T
	env        *testenv.Env
	aa, agent  *crypto.SM2Signer
	challenges *challenge.Service
	mock       *upstream.Mock
	client     *upstream.Client
	exec       *execution.Executor
	now        time.Time
	epoch      int64
}

type keyOpt func(rec map[string]any)

// newFixture 搭建真实的 Broker 执行路径：真实流水线 + 原子消费 + Vault + Mock 上游。
// agentKeyOpts 可修改 Agent 公钥记录（如设为 REVOKED）。
func newFixture(t *testing.T, agentKeyOpts ...keyOpt) *fixture {
	t.Helper()
	env := testenv.New(t)
	info, err := env.Credentials.Create(ctx, credID, "github", secret.Secret("git-token"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, env: env, now: time.Now(), epoch: info.Epoch}
	if f.aa, err = crypto.GenerateSM2Signer(); err != nil {
		t.Fatal(err)
	}
	if f.agent, err = crypto.GenerateSM2Signer(); err != nil {
		t.Fatal(err)
	}
	agentRec := f.keyRecord(agentKey, agentID, protocol.KeyPurposeHolderProof, f.agent)
	for _, opt := range agentKeyOpts {
		opt(agentRec)
	}
	doc, _ := canonical.Marshal(map[string]any{
		"protocol_version": "1.0",
		"keys":             []any{f.keyRecord(aaKeyID, issuerID, protocol.KeyPurposeCapability, f.aa), agentRec},
	})
	reg, err := protocol.ParseKeyRegistry(doc)
	if err != nil {
		t.Fatal(err)
	}

	f.mock = upstream.NewMock("git-token", "db-token")
	srv := httptest.NewServer(f.mock.Handler())
	t.Cleanup(srv.Close)
	f.client = upstream.NewClient(srv.URL, 5*time.Second)
	f.challenges = challenge.NewService(env.DB, time.Minute, brokerID)

	m := metrics.New()
	f.exec = &execution.Executor{
		Pipeline: verifier.New(m, verifier.Steps(verifier.Config{
			BrokerID: brokerID, TrustedIssuer: issuerID, Keys: reg, Challenges: f.challenges,
		})...),
		Store:       capability.NewStore(env.DB, env.Auditor),
		Credentials: env.Credentials,
		Upstream:    f.client,
		Audit:       env.Auditor,
		Metrics:     m,
	}
	return f
}

func (f *fixture) keyRecord(keyID, subject, purpose string, s *crypto.SM2Signer) map[string]any {
	pemKey, err := crypto.MarshalSM2PublicKeyPEM(s.PublicKey())
	if err != nil {
		f.t.Fatal(err)
	}
	return map[string]any{
		"key_id": keyID, "subject_id": subject, "purpose": purpose, "algorithm": "SM2",
		"status": "ACTIVE", "public_key_pem": pemKey,
		"not_before": int64(0), "not_after": f.now.Add(365 * 24 * time.Hour).Unix(),
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// request 返回 A 的 demo 请求：读取 course-project 的 README.md。
func (f *fixture) request() *protocol.AgentRequest {
	return &protocol.AgentRequest{
		ProtocolVersion: "1.0", RequestID: "req-" + randHex(4),
		AgentID: agentID, AgentKeyID: agentKey, TaskID: "task-demo-001",
		Service: "git", Resource: "repo/course-project", Operation: "read_file",
		Method: "GET", Path: "/repos/course-project/files/README.md",
		Query: map[string]any{}, Body: nil, CredentialID: credID,
	}
}

func (f *fixture) capability(req *protocol.AgentRequest, mutate ...func(*protocol.CapabilityBody)) *protocol.SignedCapability {
	f.t.Helper()
	h, err := protocol.RequestHash(req)
	if err != nil {
		f.t.Fatal(err)
	}
	now := f.now.Unix()
	body := &protocol.CapabilityBody{
		ProtocolVersion: "1.0", CapabilityID: "cap_" + randHex(16),
		Issuer: issuerID, IssuerKeyID: aaKeyID, Audience: brokerID,
		AgentID: req.AgentID, AgentKeyID: req.AgentKeyID, TaskID: req.TaskID,
		Service: req.Service, Resource: req.Resource, Operation: req.Operation,
		RequestHash: h, CredentialID: req.CredentialID, CredentialEpoch: f.epoch,
		IssuedAt: now, ExpiresAt: now + 60, TTLSeconds: 60, Nonce: randHex(16), OneTime: true,
	}
	for _, m := range mutate {
		m(body)
	}
	sig, err := protocol.Sign(f.aa, body.IssuerKeyID, protocol.PurposeCapability, body)
	if err != nil {
		f.t.Fatal(err)
	}
	return &protocol.SignedCapability{Body: body, Signature: sig}
}

func (f *fixture) challenge() string {
	f.t.Helper()
	c, err := f.challenges.Issue(ctx, agentID)
	if err != nil {
		f.t.Fatal(err)
	}
	return c.Challenge
}

func (f *fixture) proof(cap *protocol.SignedCapability, req *protocol.AgentRequest, chal string, signer *crypto.SM2Signer,
	mutate ...func(*protocol.HolderProofBody)) *protocol.HolderProof {
	f.t.Helper()
	capHash, _ := protocol.CapabilityHash(cap)
	reqHash, _ := protocol.RequestHash(req)
	now := f.now.Unix()
	body := &protocol.HolderProofBody{
		ProtocolVersion: "1.0", ProofID: "proof_" + randHex(16),
		CapabilityID: cap.Body.CapabilityID, CapabilityHash: capHash,
		AgentID: cap.Body.AgentID, AgentKeyID: cap.Body.AgentKeyID, Audience: cap.Body.Audience,
		RequestHash: reqHash, Challenge: chal, IssuedAt: now, ExpiresAt: now + 30,
	}
	for _, m := range mutate {
		m(body)
	}
	if signer == nil {
		signer = f.agent
	}
	sig, err := protocol.Sign(signer, body.AgentKeyID, protocol.PurposeHolderProof, body)
	if err != nil {
		f.t.Fatal(err)
	}
	return &protocol.HolderProof{Body: body, Signature: sig}
}

func bundle(t *testing.T, req *protocol.AgentRequest, cap *protocol.SignedCapability, proof *protocol.HolderProof) []byte {
	t.Helper()
	raw, err := protocol.Canonical(&protocol.ExecutionBundle{Request: req, Capability: cap, HolderProof: proof})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *fixture) run(body []byte) *execution.Outcome {
	f.t.Helper()
	out, err := f.exec.Execute(ctx, &verifier.Input{Body: body, Now: f.now})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

// valid 返回一组完全合法的 request / capability / proof。
func (f *fixture) valid() (*protocol.AgentRequest, *protocol.SignedCapability, *protocol.HolderProof) {
	req := f.request()
	cap := f.capability(req)
	return req, cap, f.proof(cap, req, f.challenge(), nil)
}

func TestExecuteSuccess(t *testing.T) {
	f := newFixture(t)
	req, cap, proof := f.valid()
	out := f.run(bundle(t, req, cap, proof))
	if !out.Decision.Allowed || !out.CredentialLoaded || out.Result == nil || out.Result.Status != 200 {
		t.Fatalf("expected success, got %+v", out.Decision)
	}
	if !strings.Contains(string(out.Result.Body), "course-project") {
		t.Fatalf("unexpected upstream body: %s", out.Result.Body)
	}
	if got := len(out.Decision.Steps); got != 7 {
		t.Fatalf("ran %d steps, want 7", got)
	}
	if st, _ := f.exec.Store.State(ctx, cap.Body.CapabilityID); st != capability.StateConsumed {
		t.Fatalf("capability state = %s", st)
	}
}

// 每类拒绝都必须停在预期步骤，不读取 Credential、不调用上游。
func TestExecuteDenials(t *testing.T) {
	type build func(f *fixture) []byte
	attacker, _ := crypto.GenerateSM2Signer()

	cases := []struct {
		name, step, code string
		build            build
	}{
		{"canonical_garbage", "schema", protocol.CodeCanonicalization, func(f *fixture) []byte {
			return []byte(`{"request":1.5}`)
		}},
		{"schema_unknown_field", "schema", protocol.CodeSchema, func(f *fixture) []byte {
			req, cap, proof := f.valid()
			v := (&protocol.ExecutionBundle{Request: req, Capability: cap, HolderProof: proof}).Value()
			v["task_context"] = map[string]any{"trusted": true}
			raw, _ := canonical.Marshal(v)
			return raw
		}},
		{"untrusted_issuer", "capability_signature", protocol.CodeUntrustedIssuer, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req, func(b *protocol.CapabilityBody) { b.Issuer = "aa-evil" })
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"signature_key_mismatch", "capability_signature", protocol.CodeSignatureKeyMismatch, func(f *fixture) []byte {
			req, cap, proof := f.valid()
			cap.Signature.KeyID = "aa-key-02"
			return bundle(f.t, req, cap, proof)
		}},
		{"unknown_issuer_key", "capability_signature", protocol.CodeUnknownKey, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req, func(b *protocol.CapabilityBody) { b.IssuerKeyID = "aa-key-99" })
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"tampered_capability", "capability_signature", protocol.CodeInvalidSignature, func(f *fixture) []byte {
			req, cap, _ := f.valid()
			cap.Body.CredentialEpoch++ // 签名后篡改
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"capability_signed_by_agent", "capability_signature", protocol.CodeInvalidSignature, func(f *fixture) []byte {
			req, cap, _ := f.valid()
			cap.Signature, _ = protocol.Sign(f.agent, aaKeyID, protocol.PurposeCapability, cap.Body)
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"capability_expired", "capability_validity", protocol.CodeCapabilityExpired, func(f *fixture) []byte {
			req := f.request()
			now := f.now.Unix()
			cap := f.capability(req, func(b *protocol.CapabilityBody) { b.IssuedAt, b.ExpiresAt = now-120, now-60 })
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"capability_not_yet_valid", "capability_validity", protocol.CodeCapabilityNotYetValid, func(f *fixture) []byte {
			req := f.request()
			now := f.now.Unix()
			cap := f.capability(req, func(b *protocol.CapabilityBody) { b.IssuedAt, b.ExpiresAt = now+60, now+120 })
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"capability_wrong_audience", "capability_validity", protocol.CodeAudienceMismatch, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req, func(b *protocol.CapabilityBody) { b.Audience = "broker-99" })
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"request_wrong_resource", "request_binding", protocol.CodeRequestBinding, func(f *fixture) []byte {
			req, cap, _ := f.valid()
			req.Resource, req.Path = "repo/private-repo", "/repos/private-repo/files/secret.txt"
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"request_hash_path_only", "request_binding", protocol.CodeRequestHash, func(f *fixture) []byte {
			req, cap, _ := f.valid()
			req.Path = "/repos/course-project/files/keys.txt"
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"proof_wrong_holder", "holder_proof", protocol.CodeInvalidSignature, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req)
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), attacker))
		}},
		{"proof_signed_by_aa", "holder_proof", protocol.CodeInvalidSignature, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req)
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), f.aa))
		}},
		{"proof_wrong_audience", "holder_proof", protocol.CodeAudienceMismatch, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req)
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil,
				func(b *protocol.HolderProofBody) { b.Audience = "broker-99" }))
		}},
		{"proof_expired", "holder_proof", protocol.CodeProofExpired, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req)
			now := f.now.Unix()
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil,
				func(b *protocol.HolderProofBody) { b.IssuedAt, b.ExpiresAt = now-40, now-10 }))
		}},
		{"proof_wrong_capability_hash", "holder_proof", protocol.CodeHolderBinding, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req)
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil,
				func(b *protocol.HolderProofBody) { b.CapabilityHash = strings.Repeat("0", 64) }))
		}},
		{"proof_for_other_capability", "holder_proof", protocol.CodeHolderBinding, func(f *fixture) []byte {
			req := f.request()
			cap, other := f.capability(req), f.capability(req)
			return bundle(f.t, req, cap, f.proof(other, req, f.challenge(), nil))
		}},
		{"unsupported_operation", "execution_plan", errcode.UnsupportedOperation, func(f *fixture) []byte {
			req := f.request()
			req.Operation, req.Method = "delete_file", "DELETE"
			cap := f.capability(req)
			return bundle(f.t, req, cap, f.proof(cap, req, f.challenge(), nil))
		}},
		{"challenge_not_issued", "challenge", errcode.ChallengeUnknown, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req)
			return bundle(f.t, req, cap, f.proof(cap, req, randHex(32), nil))
		}},
		{"challenge_for_other_agent", "challenge", errcode.ChallengeWrongAgent, func(f *fixture) []byte {
			req := f.request()
			cap := f.capability(req)
			c, _ := f.challenges.Issue(ctx, "agent-02")
			return bundle(f.t, req, cap, f.proof(cap, req, c.Challenge, nil))
		}},
		{"credential_revoked", "atomic_consume", errcode.CredentialInactive, func(f *fixture) []byte {
			req, cap, proof := f.valid()
			if _, err := f.env.Credentials.Apply(ctx, credID, credential.ActionRevoke); err != nil {
				f.t.Fatal(err)
			}
			return bundle(f.t, req, cap, proof)
		}},
		{"credential_old_epoch", "atomic_consume", errcode.CredentialEpochMismatch, func(f *fixture) []byte {
			req, cap, proof := f.valid()
			if _, err := f.env.Credentials.Rotate(ctx, credID, secret.Secret("git-token-2")); err != nil {
				f.t.Fatal(err)
			}
			return bundle(f.t, req, cap, proof)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			out := f.run(c.build(f))
			d := out.Decision
			if d.Allowed || d.FailedStep != c.step || d.Code != c.code {
				t.Fatalf("got allowed=%v step=%q code=%q (%s), want step=%q code=%q",
					d.Allowed, d.FailedStep, d.Code, d.Reason, c.step, c.code)
			}
			if out.CredentialLoaded || f.client.Calls() != 0 {
				t.Fatalf("denied request touched credential=%v upstream calls=%d", out.CredentialLoaded, f.client.Calls())
			}
		})
	}
}

func TestExecuteRevokedAgentKey(t *testing.T) {
	f := newFixture(t, func(rec map[string]any) { rec["status"] = "REVOKED" })
	req, cap, proof := f.valid()
	d := f.run(bundle(t, req, cap, proof)).Decision
	if d.Allowed || d.FailedStep != "holder_proof" || d.Code != protocol.CodeKeyRevoked {
		t.Fatalf("got %+v", d)
	}
}

// 静态可判定的拒绝不应消耗 Challenge：同一 Challenge 之后仍可正常使用。
func TestRejectedRequestDoesNotBurnChallenge(t *testing.T) {
	f := newFixture(t)
	chal := f.challenge()
	req := f.request()
	cap := f.capability(req)
	bad := f.proof(cap, req, chal, nil, func(b *protocol.HolderProofBody) { b.Audience = "broker-99" })
	if d := f.run(bundle(t, req, cap, bad)).Decision; d.Allowed {
		t.Fatal("bad proof accepted")
	}
	if d := f.run(bundle(t, req, cap, f.proof(cap, req, chal, nil))).Decision; !d.Allowed {
		t.Fatalf("challenge was burnt by a rejected request: %+v", d)
	}
}

// 原样重放整个 bundle：Challenge 已用，拒绝；上游只被调用一次。
func TestReplaySameBundle(t *testing.T) {
	f := newFixture(t)
	req, cap, proof := f.valid()
	body := bundle(t, req, cap, proof)
	if d := f.run(body).Decision; !d.Allowed {
		t.Fatalf("first: %+v", d)
	}
	d := f.run(body).Decision
	if d.Allowed || d.FailedStep != "challenge" || d.Code != errcode.ChallengeUsed {
		t.Fatalf("replay: %+v", d)
	}
	if f.client.Calls() != 1 {
		t.Fatalf("upstream calls = %d", f.client.Calls())
	}
}

// 同一 Capability + 新 Challenge 的再次提交：幂等返回旧结果，不产生新上游调用。
func TestReplaySameCapabilityNewChallenge(t *testing.T) {
	f := newFixture(t)
	req, cap, proof := f.valid()
	first := f.run(bundle(t, req, cap, proof))
	second := f.run(bundle(t, req, cap, f.proof(cap, req, f.challenge(), nil)))
	if !second.Decision.Allowed || !second.Replayed || second.CredentialLoaded {
		t.Fatalf("second: %+v replayed=%v loaded=%v", second.Decision, second.Replayed, second.CredentialLoaded)
	}
	if string(second.Result.Body) != string(first.Result.Body) || f.client.Calls() != 1 {
		t.Fatalf("idempotent replay mismatch: calls=%d", f.client.Calls())
	}
}

// 并发重放同一写 Capability（每个请求各自持有合法 Challenge）：实际副作用恰好一次。
func TestConcurrentReplayWriteSideEffectOnce(t *testing.T) {
	f := newFixture(t)
	req := f.request()
	req.Operation, req.Method, req.Body = "write_file", "PUT", map[string]any{"content": "hello"}
	req.Path = "/repos/course-project/files/out.txt"
	cap := f.capability(req)

	const n = 20
	bodies := make([][]byte, n)
	for i := range bodies {
		bodies[i] = bundle(t, req, cap, f.proof(cap, req, f.challenge(), nil))
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	for _, b := range bodies {
		wg.Add(1)
		go func(b []byte) {
			defer wg.Done()
			out, err := f.exec.Execute(ctx, &verifier.Input{Body: b, Now: f.now})
			if err != nil {
				t.Error(err)
				return
			}
			if out.CredentialLoaded {
				won.Add(1)
			}
		}(b)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("credential loaded %d times", won.Load())
	}
	if got := f.mock.Stats().ByCapability[cap.Body.CapabilityID]; got != 1 {
		t.Fatalf("side effects for capability = %d", got)
	}
}
