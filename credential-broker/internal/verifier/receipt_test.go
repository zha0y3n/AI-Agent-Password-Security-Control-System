package verifier_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/execution"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/receipt"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
)

// verifyReceipt 按 Agent / C 的视角复核回执：严格解析、Broker 签名、result_hash 与 envelope 一致、envelope 是规范字节。
func (f *fixture) verifyReceipt(out *execution.Outcome) (*protocol.SignedReceipt, map[string]any) {
	f.t.Helper()
	if out.Receipt == nil || out.ResultEnvelope == nil {
		f.t.Fatalf("no receipt issued (decision %+v)", out.Decision)
	}
	r, perr := protocol.ParseSignedReceipt(out.Receipt)
	if perr != nil {
		f.t.Fatalf("receipt does not match A's schema: %v", perr)
	}
	if r.Body.BrokerID != brokerID || r.Body.BrokerKeyID != brokerKey || r.Signature.KeyID != brokerKey {
		f.t.Fatalf("receipt broker identity: %+v", r.Body)
	}
	if perr := protocol.VerifySignature(f.broker.PublicKey(), protocol.PurposeReceipt, r.Body, r.Signature); perr != nil {
		f.t.Fatalf("receipt signature: %v", perr)
	}
	if got := crypto.SM3Hex(out.ResultEnvelope); got != r.Body.ResultHash {
		f.t.Fatalf("result_hash %s != SM3(envelope) %s", r.Body.ResultHash, got)
	}
	v, err := canonical.Parse(out.ResultEnvelope)
	if err != nil {
		f.t.Fatal(err)
	}
	if again, _ := canonical.Marshal(v); !bytes.Equal(again, out.ResultEnvelope) {
		f.t.Fatal("result_envelope is not canonical")
	}
	env := v.(map[string]any)
	if env["capability_id"] != r.Body.CapabilityID || env["request_hash"] != r.Body.RequestHash || env["outcome"] != r.Body.Outcome {
		f.t.Fatalf("envelope does not match receipt: %v", env)
	}
	return r, env
}

func TestReceiptOnSuccess(t *testing.T) {
	f := newFixture(t)
	req, cap, proof := f.valid()
	out := f.run(bundle(t, req, cap, proof))
	r, env := f.verifyReceipt(out)
	b := r.Body
	if b.Outcome != receipt.OutcomeSuccess || b.CapabilityID != cap.Body.CapabilityID || b.RequestHash != cap.Body.RequestHash ||
		b.CredentialID != credID || b.CredentialEpoch != f.epoch {
		t.Fatalf("receipt body: %+v", b)
	}
	if env["code"] != nil || env["upstream_status"] != int64(200) {
		t.Fatalf("envelope: %v", env)
	}
	if body, _ := env["upstream_body"].(map[string]any); body["repo"] != "course-project" {
		t.Fatalf("envelope upstream_body: %v", env["upstream_body"])
	}
	if strings.Contains(string(out.Receipt)+string(out.ResultEnvelope), "git-token") {
		t.Fatal("credential leaked into receipt")
	}
}

// 幂等重放返回字节相同的回执，而不是重新签一张。
func TestReceiptReplayIsIdentical(t *testing.T) {
	f := newFixture(t)
	req, cap, proof := f.valid()
	first := f.run(bundle(t, req, cap, proof))
	second := f.run(bundle(t, req, cap, f.proof(cap, req, f.challenge(), nil)))
	if !second.Replayed || !bytes.Equal(first.Receipt, second.Receipt) || !bytes.Equal(first.ResultEnvelope, second.ResultEnvelope) {
		t.Fatalf("replayed receipt differs:\n%s\n%s", first.Receipt, second.Receipt)
	}
}

// 原样重放（Challenge 已用）得到 DENIED 回执，且不覆盖原 SUCCESS 结果。
func TestReceiptOnChallengeReplay(t *testing.T) {
	f := newFixture(t)
	req, cap, proof := f.valid()
	body := bundle(t, req, cap, proof)
	first := f.run(body)
	second := f.run(body)
	r, env := f.verifyReceipt(second)
	if r.Body.Outcome != receipt.OutcomeDenied || env["code"] != errcode.ChallengeUsed {
		t.Fatalf("replay receipt: %s %v", r.Body.Outcome, env)
	}
	if first1, _ := protocol.ParseSignedReceipt(first.Receipt); first1.Body.ReceiptID == r.Body.ReceiptID {
		t.Fatal("receipt id reused")
	}
	if st, _ := f.exec.Store.State(ctx, cap.Body.CapabilityID); st != capability.StateConsumed {
		t.Fatalf("capability state = %s", st)
	}
}

// 上游已处理但返回 4xx：回执 outcome=ERROR，Capability 记为 CONSUMED（不可再执行）。
func TestReceiptOnUpstreamRejection(t *testing.T) {
	f := newFixture(t)
	req := f.request()
	req.Path = "/repos/course-project/files/missing.md"
	cap := f.capability(req)
	out := f.run(bundle(t, req, cap, f.proof(cap, req, f.challenge(), nil)))
	if !out.Decision.Allowed {
		t.Fatalf("decision: %+v", out.Decision)
	}
	r, env := f.verifyReceipt(out)
	if r.Body.Outcome != receipt.OutcomeError || env["code"] != errcode.UpstreamRejected || env["upstream_status"] != int64(404) {
		t.Fatalf("receipt: %s %v", r.Body.Outcome, env)
	}
	if st, _ := f.exec.Store.State(ctx, cap.Body.CapabilityID); st != capability.StateConsumed {
		t.Fatalf("capability state = %s", st)
	}
}

// 上游不可达：回执 outcome=ERROR，Capability -> FAILED，之后的提交被拒绝。
func TestReceiptOnUpstreamFailure(t *testing.T) {
	f := newFixture(t)
	f.exec.Upstream = upstream.NewClient("http://127.0.0.1:1", time.Second)
	req, cap, proof := f.valid()
	out := f.run(bundle(t, req, cap, proof))
	r, env := f.verifyReceipt(out)
	if out.Decision.Allowed || r.Body.Outcome != receipt.OutcomeError || env["code"] != errcode.UpstreamError {
		t.Fatalf("receipt: %+v %s %v", out.Decision, r.Body.Outcome, env)
	}
	if st, _ := f.exec.Store.State(ctx, cap.Body.CapabilityID); st != capability.StateFailed {
		t.Fatalf("capability state = %s", st)
	}
	again := f.run(bundle(t, req, cap, f.proof(cap, req, f.challenge(), nil)))
	if again.Decision.Code != errcode.CapabilityFailed {
		t.Fatalf("retry after failure: %+v", again.Decision)
	}
}
