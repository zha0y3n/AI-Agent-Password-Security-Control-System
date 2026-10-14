// Package receipt 签发 Execution Receipt（docs/crypto-protocol.md §6）。
//
// 回执由 Broker 的 SM2 密钥对 ExecutionReceipt 做域分离签名（purpose = EXECUTION_RECEIPT），
// A 的 agent_aa.receipt.ReceiptVerifier 可直接验签。
//
// result_hash = lowercase_hex(SM3(ZTCANON-JSON-v1(result_envelope)))。
// result_envelope 的结构是 B 的提案（见 README「result_envelope」），等待 A/C 联审后固化进 shared/：
//
//	{
//	  "protocol_version": "1.0",
//	  "capability_id":    <Capability ID>,
//	  "request_hash":     <Capability 中签名的 request_hash>,
//	  "outcome":          "SUCCESS" | "DENIED" | "ERROR",
//	  "code":             <拒绝 / 错误码，SUCCESS 时为 null>,
//	  "upstream_status":  <上游 HTTP 状态码，未调用上游时为 null>,
//	  "upstream_body":    <上游 JSON 响应，未调用上游时为 null>
//	}
package receipt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

// Outcome 取值与 ExecutionReceipt.outcome 一致。
const (
	OutcomeSuccess = "SUCCESS"
	OutcomeDenied  = "DENIED"
	OutcomeError   = "ERROR"
)

// Envelope 是 result_envelope。UpstreamStatus 为 0 表示未调用上游。
type Envelope struct {
	CapabilityID   string
	RequestHash    string
	Outcome        string
	Code           string
	UpstreamStatus int
	upstreamBody   any
}

// NewEnvelope 构造 result_envelope。upstreamBody 为上游原始 JSON；
// 不符合 ZTCANON-JSON-v1（如含浮点数）时以原始文本字符串的形式放入，保证可规范化。
func NewEnvelope(capID, requestHash, outcome, code string, upstreamStatus int, upstreamBody []byte) *Envelope {
	e := &Envelope{CapabilityID: capID, RequestHash: requestHash, Outcome: outcome, Code: code, UpstreamStatus: upstreamStatus}
	if upstreamBody != nil {
		if v, err := canonical.Parse(upstreamBody); err == nil {
			e.upstreamBody = v
		} else {
			e.upstreamBody = strings.ToValidUTF8(string(upstreamBody), string(utf8.RuneError))
		}
	}
	return e
}

func (e *Envelope) Value() map[string]any {
	v := map[string]any{
		"protocol_version": protocol.ProtocolVersion,
		"capability_id":    e.CapabilityID,
		"request_hash":     e.RequestHash,
		"outcome":          e.Outcome,
		"code":             nil,
		"upstream_status":  nil,
		"upstream_body":    e.upstreamBody,
	}
	if e.Code != "" {
		v["code"] = e.Code
	}
	if e.UpstreamStatus != 0 {
		v["upstream_status"] = int64(e.UpstreamStatus)
	}
	return v
}

// Claim 是回执绑定的 Capability 信息，必须来自已验签的 Capability。
type Claim struct {
	CapabilityID    string
	RequestHash     string
	CredentialID    string
	CredentialEpoch int64
}

// Issued 是签好的回执及其 result_envelope 的规范字节。
type Issued struct {
	Receipt  *protocol.SignedReceipt
	Envelope []byte // ZTCANON-JSON-v1(result_envelope)
	Bytes    []byte // ZTCANON-JSON-v1(SignedReceipt)
}

// Issuer 用 Broker 密钥签发回执。
type Issuer struct {
	BrokerID string
	KeyID    string
	Signer   *crypto.SM2Signer
	Now      func() time.Time
}

// Issue 签发一张回执。签发前把回执按 A 的 schema 重新解析一遍，任何不合规字段都拒绝签发（fail closed）。
func (i *Issuer) Issue(c Claim, env *Envelope) (*Issued, error) {
	envBytes, err := protocol.Canonical(env)
	if err != nil {
		return nil, fmt.Errorf("receipt: canonicalize result envelope: %w", err)
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	now := time.Now
	if i.Now != nil {
		now = i.Now
	}
	body := &protocol.ExecutionReceipt{
		ProtocolVersion: protocol.ProtocolVersion,
		ReceiptID:       "rcpt_" + hex.EncodeToString(id),
		BrokerID:        i.BrokerID,
		BrokerKeyID:     i.KeyID,
		CapabilityID:    c.CapabilityID,
		RequestHash:     c.RequestHash,
		CredentialID:    c.CredentialID,
		CredentialEpoch: c.CredentialEpoch,
		ResultHash:      crypto.SM3Hex(envBytes),
		Outcome:         env.Outcome,
		ExecutedAt:      now().Unix(),
	}
	if _, perr := protocol.DecodeExecutionReceipt(body.Value()); perr != nil {
		return nil, fmt.Errorf("receipt: refusing to sign malformed receipt: %w", perr)
	}
	sig, err := protocol.Sign(i.Signer, i.KeyID, protocol.PurposeReceipt, body)
	if err != nil {
		return nil, err
	}
	signed := &protocol.SignedReceipt{Body: body, Signature: sig}
	raw, err := protocol.Canonical(signed)
	if err != nil {
		return nil, err
	}
	return &Issued{Receipt: signed, Envelope: envBytes, Bytes: raw}, nil
}
