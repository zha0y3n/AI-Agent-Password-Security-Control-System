// Package execution 串联 Broker 的可信执行路径：
//
//	校验流水线 -> Atomic Consume -> Vault 解密 -> 上游调用 -> 记录结果
//
// 任何拒绝都发生在 Credential 读取之前；Credential 明文只在本包内短暂存在并在调用后清零。
// 阶段二在此基础上增加 Execution Receipt 签发。
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
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/upstream"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

// Outcome 是一次执行的结果，可直接作为 API 响应的一部分。
type Outcome struct {
	Decision         verifier.Decision  `json:"decision"`
	CredentialLoaded bool               `json:"credential_loaded"`
	Replayed         bool               `json:"replayed"`
	Result           *upstream.Response `json:"result,omitempty"`
}

// Executor 是 Broker 的可信执行点。
type Executor struct {
	Pipeline    *verifier.Pipeline
	Store       *capability.Store
	Credentials *credential.Service
	Upstream    *upstream.Client
	Audit       *evidence.Auditor
	Metrics     *metrics.Recorder
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
		return out, e.auditDeny(ctx, in, out.Decision)
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
		return out, e.auditDeny(ctx, in, out.Decision)
	}
	if res.Outcome == capability.Replayed {
		out.Replayed = true
		out.Result = &upstream.Response{}
		if err := json.Unmarshal(res.Stored, out.Result); err != nil {
			return nil, err
		}
		return out, nil
	}

	// 赢得唯一执行权：此后任何失败都把 Capability 标记为 FAILED。
	t = time.Now()
	cred, err := e.Credentials.Open(ctx, plan.Claim.CredentialID, plan.Claim.CredentialEpoch)
	e.Metrics.Since(metrics.StageDecrypt, t)
	if err != nil {
		out.Decision = deny(out.Decision, "credential_decrypt", errcode.CredentialUnavailable, "credential changed after consume")
		return out, e.Store.Fail(ctx, plan.Claim.CapID, errcode.CredentialUnavailable)
	}
	out.CredentialLoaded = true

	t = time.Now()
	resp, err := e.Upstream.Do(ctx, plan.Call, cred)
	cred.Wipe()
	e.Metrics.Since(metrics.StageUpstream, t)
	if err != nil || resp.Status >= 500 {
		out.Decision = deny(out.Decision, "upstream", errcode.UpstreamError, "upstream call failed")
		return out, e.Store.Fail(ctx, plan.Claim.CapID, errcode.UpstreamError)
	}

	stored, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	if err := e.Store.Complete(ctx, plan.Claim.CapID, stored); err != nil {
		return nil, err
	}
	out.Result = resp
	return out, nil
}

func deny(d verifier.Decision, step, code, reason string) verifier.Decision {
	d.Allowed, d.FailedStep, d.Code, d.Reason = false, step, code, reason
	return d
}

func (e *Executor) auditDeny(ctx context.Context, in *verifier.Input, d verifier.Decision) error {
	data := map[string]any{"failed_step": d.FailedStep, "code": d.Code}
	if in.Plan != nil {
		data["cap_id"] = in.Plan.Claim.CapID
		data["request_hash"] = in.Plan.Claim.RequestHash
	}
	return e.Audit.Record(ctx, "execute.deny", data)
}

func consumeErrCode(err error) (string, bool) {
	for target, code := range map[error]string{
		capability.ErrInProgress:      errcode.ReplayInProgress,
		capability.ErrRequestMismatch: errcode.IdempotencyConflict,
		capability.ErrClaimMismatch:   errcode.CapabilityClaimMismatch,
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
