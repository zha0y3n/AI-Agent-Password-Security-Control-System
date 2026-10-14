package verifier

import (
	"context"
	"errors"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

// DefaultClockSkew 与 A 的参考校验器（clock_skew_seconds=5）一致，只放宽“签发时间在未来”的判断。
const DefaultClockSkew = 5 * time.Second

// Config 是协议校验步骤的依赖。全部来自 Broker 本地配置，不取自请求。
type Config struct {
	BrokerID      string                // 本 Broker 的 audience
	TrustedIssuer string                // 唯一信任的 AA issuer
	Keys          *protocol.KeyRegistry // AA / Agent 公钥
	Challenges    *challenge.Service
	ClockSkew     time.Duration
}

// Steps 返回 docs/a-b-interface.md 规定顺序的校验步骤：
//
//	schema → capability_signature → capability_validity → request_binding
//	→ holder_proof → execution_plan → challenge
//
// 前六步是纯计算；challenge 是第一处写状态的步骤，放在所有可静态判定的拒绝之后，
// 避免无效请求白白烧掉 Challenge。Credential 状态 / Epoch 检查与 Capability CAS
// 由 Executor 在同一事务中完成（capability.Store.Consume）。
func Steps(cfg Config) []Step {
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = DefaultClockSkew
	}
	return []Step{
		StepFunc{"schema", cfg.schema},
		StepFunc{StepCapabilitySignature, cfg.capabilitySignature},
		StepFunc{"capability_validity", cfg.capabilityValidity},
		StepFunc{"request_binding", cfg.requestBinding},
		StepFunc{"holder_proof", cfg.holderProof},
		StepFunc{"execution_plan", cfg.executionPlan},
		StepFunc{"challenge", cfg.challenge},
	}
}

// StepCapabilitySignature 之后 Capability 字段可信，Executor 据此决定是否为拒绝签发回执。
const StepCapabilitySignature = "capability_signature"

func denyProtocol(err *protocol.Error) *Denial {
	return &Denial{Code: err.Code, Reason: err.Message}
}

func denyf(code, reason string) *Denial { return &Denial{Code: code, Reason: reason} }

func (c Config) schema(_ context.Context, in *Input) *Denial {
	b, err := protocol.ParseExecutionBundle(in.Body)
	if err != nil {
		return denyProtocol(err)
	}
	in.Bundle = b
	return nil
}

func (c Config) capabilitySignature(_ context.Context, in *Input) *Denial {
	capb := in.Bundle.Capability.Body
	sig := in.Bundle.Capability.Signature
	if c.TrustedIssuer == "" || capb.Issuer != c.TrustedIssuer {
		return denyf(protocol.CodeUntrustedIssuer, "capability issuer is not trusted")
	}
	if sig.KeyID != capb.IssuerKeyID {
		return denyf(protocol.CodeSignatureKeyMismatch, "signature key id differs from signed body")
	}
	if c.Keys == nil {
		return denyf(protocol.CodeUnknownKey, "no trusted key registry configured")
	}
	pub, err := c.Keys.Lookup(capb.IssuerKeyID, protocol.KeyPurposeCapability, capb.Issuer, capb.IssuedAt)
	if err != nil {
		return denyProtocol(err)
	}
	if err := protocol.VerifySignature(pub, protocol.PurposeCapability, capb, sig); err != nil {
		return denyProtocol(err)
	}
	return nil
}

func (c Config) capabilityValidity(_ context.Context, in *Input) *Denial {
	capb := in.Bundle.Capability.Body
	now, skew := in.Now.Unix(), int64(c.ClockSkew/time.Second)
	switch {
	case now+skew < capb.IssuedAt:
		return denyf(protocol.CodeCapabilityNotYetValid, "capability issued_at is in the future")
	case now >= capb.ExpiresAt:
		return denyf(protocol.CodeCapabilityExpired, "capability has expired")
	case capb.Audience != c.BrokerID:
		return denyf(protocol.CodeAudienceMismatch, "capability audience does not match this Broker")
	}
	return nil
}

func (c Config) requestBinding(_ context.Context, in *Input) *Denial {
	capb, req := in.Bundle.Capability.Body, in.Bundle.Request
	if capb.AgentID != req.AgentID || capb.AgentKeyID != req.AgentKeyID || capb.TaskID != req.TaskID ||
		capb.Service != req.Service || capb.Resource != req.Resource || capb.Operation != req.Operation ||
		capb.CredentialID != req.CredentialID {
		return denyf(protocol.CodeRequestBinding, "request fields differ from the capability")
	}
	h, err := protocol.RequestHash(req)
	if err != nil {
		return denyf(protocol.CodeCanonicalization, err.Error())
	}
	if h != capb.RequestHash {
		return denyf(protocol.CodeRequestHash, "canonical request hash differs from capability")
	}
	in.RequestHash = h
	return nil
}

func (c Config) holderProof(_ context.Context, in *Input) *Denial {
	proof, capb := in.Bundle.HolderProof, in.Bundle.Capability.Body
	pb := proof.Body
	now, skew := in.Now.Unix(), int64(c.ClockSkew/time.Second)
	if proof.Signature.KeyID != pb.AgentKeyID {
		return denyf(protocol.CodeSignatureKeyMismatch, "proof signature key differs from body")
	}
	if pb.Audience != c.BrokerID {
		return denyf(protocol.CodeAudienceMismatch, "Holder Proof audience does not match Broker")
	}
	switch {
	case now+skew < pb.IssuedAt:
		return denyf(protocol.CodeProofNotYetValid, "Holder Proof issued_at is in the future")
	case now >= pb.ExpiresAt:
		return denyf(protocol.CodeProofExpired, "Holder Proof has expired")
	}
	capHash, err := protocol.CapabilityHash(in.Bundle.Capability)
	if err != nil {
		return denyf(protocol.CodeCanonicalization, err.Error())
	}
	if pb.CapabilityID != capb.CapabilityID || pb.CapabilityHash != capHash ||
		pb.RequestHash != in.RequestHash || pb.RequestHash != capb.RequestHash ||
		pb.AgentID != capb.AgentID || pb.AgentKeyID != capb.AgentKeyID {
		return denyf(protocol.CodeHolderBinding, "Holder Proof bindings do not match")
	}
	pub, perr := c.Keys.Lookup(pb.AgentKeyID, protocol.KeyPurposeHolderProof, pb.AgentID, pb.IssuedAt)
	if perr != nil {
		return denyProtocol(perr)
	}
	if perr := protocol.VerifySignature(pub, protocol.PurposeHolderProof, pb, proof.Signature); perr != nil {
		return denyProtocol(perr)
	}
	return nil
}

func (c Config) executionPlan(_ context.Context, in *Input) *Denial {
	capb := in.Bundle.Capability.Body
	call, err := MapRequest(in.Bundle.Request)
	if err != nil {
		return denyf(errcode.UnsupportedOperation, err.Error())
	}
	call.CapID, call.RequestHash = capb.CapabilityID, in.RequestHash
	in.Plan = &Plan{
		Claim: capability.Claim{
			CapID:           capb.CapabilityID,
			RequestHash:     in.RequestHash,
			CredentialID:    capb.CredentialID,
			CredentialEpoch: capb.CredentialEpoch,
		},
		Call: call,
	}
	return nil
}

// challenge 原子消费 Holder Proof 中的 Broker Challenge：
// 必须由本 Broker 签发给该 Agent、未过期、未使用。验签通过后才消费，防止 proof 重放。
func (c Config) challenge(ctx context.Context, in *Input) *Denial {
	pb := in.Bundle.HolderProof.Body
	if c.Challenges == nil {
		return denyf(errcode.ChallengeUnknown, "no challenge store configured")
	}
	err := c.Challenges.Consume(ctx, nil, pb.Challenge, pb.AgentID)
	for target, code := range map[error]string{
		challenge.ErrUnknown:       errcode.ChallengeUnknown,
		challenge.ErrUsed:          errcode.ChallengeUsed,
		challenge.ErrExpired:       errcode.ChallengeExpired,
		challenge.ErrWrongAgent:    errcode.ChallengeWrongAgent,
		challenge.ErrWrongAudience: errcode.ChallengeWrongAudience,
	} {
		if errors.Is(err, target) {
			return denyf(code, err.Error())
		}
	}
	if err != nil {
		// 存储故障同样拒绝：无法证明 Challenge 未被使用。
		return denyf(errcode.Internal, "challenge store unavailable")
	}
	return nil
}
