// Package execution 串联 Broker 的可信执行路径：
//
//	校验流水线 -> Atomic Consume -> Vault 解密 -> 上游调用 -> Receipt -> 记录结果
//
// 任何拒绝都发生在 Credential 读取之前；Credential 明文只在本包内短暂存在并在调用后清零。
package execution

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/receipt"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

// Outcome 是一次执行的结果，可直接作为 API 响应的一部分。
//
// ResultEnvelope / Receipt 是规范字节（ZTCANON-JSON-v1），原样返回给调用方：
// 调用方用 SM3(ResultEnvelope) 比对 Receipt.body.result_hash，再用 Broker 公钥验签。
type Outcome struct {
	Decision         verifier.Decision  `json:"decision"`
	CredentialLoaded bool               `json:"credential_loaded"`
	Replayed         bool               `json:"replayed"`
	Result           *upstream.Response `json:"result,omitempty"`
	ResultEnvelope   json.RawMessage    `json:"result_envelope,omitempty"`
	Receipt          json.RawMessage    `json:"receipt,omitempty"`
}

// stored 是 CONSUMED 时保存的结果，幂等重放时原样返回（同一张回执）。
type stored struct {
	Result         *upstream.Response `json:"result"`
	ResultEnvelope json.RawMessage    `json:"result_envelope,omitempty"`
	Receipt        json.RawMessage    `json:"receipt,omitempty"`
}

// Executor 是 Broker 的可信执行点。
type Executor struct {
	Pipeline    *verifier.Pipeline
	Store       *capability.Store
	Credentials *credential.Service
	Upstream    *upstream.Client
	Audit       *evidence.Auditor
	Metrics     *metrics.Recorder
	// Receipts 为 nil 时不签发回执（仅用于不关心回执的单元测试）。
	Receipts *receipt.Issuer
}

// Execute 执行一次请求。返回的 error 仅表示内部故障；业务拒绝体现在 Outcome.Decision 中。
func (e *Executor) Execute(ctx context.Context, in *verifier.Input) (*Outcome, error) {
	start := time.Now()
	defer e.Metrics.Since(metrics.StageTotal, start)
	if in.Now.IsZero() {
		in.Now = start
	}

	out := &Outcome{Decision: e.Pipeline.Run(ctx, in)}
	if out.Decision.Allowed && in.Plan == nil {
		// fail closed：流水线未产出执行计划时绝不继续
		out.Decision = deny(out.Decision, "plan", errcode.Internal, "verification produced no execution plan")
	}
	if !out.Decision.Allowed {
		return e.denied(ctx, in, out)
	}
	plan := in.Plan

	t := time.Now()
	res, err := e.Store.Consume(ctx, plan.Claim)
	e.Metrics.Since(metrics.StageConsume, t)
	if err != nil {
		code, ok := consumeErrCode(err)
		if !ok {
			return nil, err
		}
		out.Decision = deny(out.Decision, "atomic_consume", code, err.Error())
		return e.denied(ctx, in, out)
	}
	if res.Outcome == capability.Replayed {
		var s stored
		if err := json.Unmarshal(res.Stored, &s); err != nil {
			return nil, err
		}
		out.Replayed, out.Result, out.ResultEnvelope, out.Receipt = true, s.Result, s.ResultEnvelope, s.Receipt
		return out, nil
	}

	// 赢得唯一执行权：此后任何失败都把 Capability 标记为 FAILED。
	t = time.Now()
	cred, err := e.Credentials.Open(ctx, plan.Claim.CredentialID, plan.Claim.CredentialEpoch)
	e.Metrics.Since(metrics.StageDecrypt, t)
	if err != nil {
		out.Decision = deny(out.Decision, "credential_decrypt", errcode.CredentialUnavailable, "credential changed after consume")
		return e.failed(ctx, plan, out, nil)
	}
	out.CredentialLoaded = true

	t = time.Now()
	resp, err := e.Upstream.Do(ctx, plan.Call, cred)
	cred.Wipe()
	e.Metrics.Since(metrics.StageUpstream, t)
	if err != nil || resp.Status >= 500 {
		out.Decision = deny(out.Decision, "upstream", errcode.UpstreamError, "upstream call failed")
		return e.failed(ctx, plan, out, resp)
	}

	// 上游已执行（含 4xx 业务错误）：结果连同回执一起保存，之后的幂等重放返回同一份。
	outcome, code := receipt.OutcomeSuccess, ""
	if resp.Status >= 300 {
		outcome, code = receipt.OutcomeError, errcode.UpstreamRejected
	}
	out.Result = resp
	if _, err := e.sign(out, claimOf(plan), outcome, code, resp); err != nil {
		return nil, err
	}
	blob, err := json.Marshal(stored{Result: resp, ResultEnvelope: out.ResultEnvelope, Receipt: out.Receipt})
	if err != nil {
		return nil, err
	}
	if err := e.Store.Complete(ctx, plan.Claim.CapID, blob); err != nil {
		return nil, err
	}
	return out, nil
}

// denied 处理执行权获取之前的拒绝：记录审计；若 Capability 已通过验签，签发 DENIED 回执。
func (e *Executor) denied(ctx context.Context, in *verifier.Input, out *Outcome) (*Outcome, error) {
	data := map[string]any{"failed_step": out.Decision.FailedStep, "code": out.Decision.Code}
	if c, ok := verifiedClaim(in, out.Decision); ok {
		data["cap_id"], data["request_hash"] = c.CapabilityID, c.RequestHash
		id, err := e.sign(out, c, receipt.OutcomeDenied, out.Decision.Code, nil)
		if err != nil {
			return nil, err
		}
		if id != "" {
			data["receipt_id"] = id
		}
	}
	return out, e.Audit.Record(ctx, "execute.deny", data)
}

// failed 处理赢得执行权之后的失败：Capability -> FAILED，签发 ERROR 回执。
func (e *Executor) failed(ctx context.Context, plan *verifier.Plan, out *Outcome, resp *upstream.Response) (*Outcome, error) {
	if _, err := e.sign(out, claimOf(plan), receipt.OutcomeError, out.Decision.Code, resp); err != nil {
		return nil, err
	}
	return out, e.Store.Fail(ctx, plan.Claim.CapID, out.Decision.Code)
}

// sign 签发回执并写入 out，返回 receipt_id（未配置签发者时为空）。
func (e *Executor) sign(out *Outcome, c receipt.Claim, outcome, code string, resp *upstream.Response) (string, error) {
	if e.Receipts == nil {
		return "", nil
	}
	t := time.Now()
	defer e.Metrics.Since(metrics.StageReceipt, t)
	status, body := 0, []byte(nil)
	if resp != nil {
		status, body = resp.Status, resp.Body
	}
	issued, err := e.Receipts.Issue(c, receipt.NewEnvelope(c.CapabilityID, c.RequestHash, outcome, code, status, body))
	if err != nil {
		return "", err
	}
	out.ResultEnvelope, out.Receipt = issued.Envelope, issued.Bytes
	return issued.Receipt.Body.ReceiptID, nil
}

// verifiedClaim 只在 Capability 签名已验证通过时返回回执绑定信息：
// 未验签的 Capability 字段可能是伪造的，Broker 不为其签名。
func verifiedClaim(in *verifier.Input, d verifier.Decision) (receipt.Claim, bool) {
	if in.Plan != nil {
		return claimOf(in.Plan), true
	}
	if in.Bundle == nil || !stepPassed(d, verifier.StepCapabilitySignature) {
		return receipt.Claim{}, false
	}
	b := in.Bundle.Capability.Body
	return receipt.Claim{CapabilityID: b.CapabilityID, RequestHash: b.RequestHash,
		CredentialID: b.CredentialID, CredentialEpoch: b.CredentialEpoch}, true
}

func claimOf(p *verifier.Plan) receipt.Claim {
	return receipt.Claim{CapabilityID: p.Claim.CapID, RequestHash: p.Claim.RequestHash,
		CredentialID: p.Claim.CredentialID, CredentialEpoch: p.Claim.CredentialEpoch}
}

func stepPassed(d verifier.Decision, name string) bool {
	for _, s := range d.Steps {
		if s.Step == name {
			return s.Passed
		}
	}
	return false
}

func deny(d verifier.Decision, step, code, reason string) verifier.Decision {
	d.Allowed, d.FailedStep, d.Code, d.Reason = false, step, code, reason
	return d
}

func consumeErrCode(err error) (string, bool) {
	for target, code := range map[error]string{
		capability.ErrInProgress:      errcode.ReplayInProgress,
		capability.ErrRequestMismatch: errcode.IdempotencyConflict,
		capability.ErrClaimMismatch:   errcode.CapabilityClaimMismatch,
		capability.ErrNonceReused:     errcode.CapabilityNonceReused,
		capability.ErrAlreadyFailed:   errcode.CapabilityFailed,
		credential.ErrNotFound:        errcode.CredentialNotFound,
		credential.ErrInactive:        errcode.CredentialInactive,
		credential.ErrEpochMismatch:   errcode.CredentialEpochMismatch,
	} {
		if errors.Is(err, target) {
			return code, true
		}
	}
	return "", false
}
