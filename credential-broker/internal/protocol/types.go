package protocol

import (
	"errors"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
)

const (
	ProtocolVersion   = "1.0"
	SignatureAlg      = "SM2-SM3"
	SignatureEncoding = "ASN.1-DER/base64url-nopad"
)

// AgentRequest 是被哈希进 Capability 的完整动作描述。
type AgentRequest struct {
	ProtocolVersion string
	RequestID       string
	AgentID         string
	AgentKeyID      string
	TaskID          string
	Service         string
	Resource        string
	Operation       string
	Method          string
	Path            string
	Query           map[string]any // 值为 string 或非空 []any（元素均为 string）
	Body            any            // 任意 ZTCANON 值
	CredentialID    string
}

// Value 返回用于规范化的值树（包含全部字段，null 不省略）。
func (r *AgentRequest) Value() map[string]any {
	return map[string]any{
		"protocol_version": r.ProtocolVersion,
		"request_id":       r.RequestID,
		"agent_id":         r.AgentID,
		"agent_key_id":     r.AgentKeyID,
		"task_id":          r.TaskID,
		"service":          r.Service,
		"resource":         r.Resource,
		"operation":        r.Operation,
		"method":           r.Method,
		"path":             r.Path,
		"query":            r.Query,
		"body":             r.Body,
		"credential_id":    r.CredentialID,
	}
}

func decodeAgentRequest(v any, path string) (*AgentRequest, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	r := &AgentRequest{
		ProtocolVersion: o.literal("protocol_version", ProtocolVersion),
		RequestID:       o.identifier("request_id"),
		AgentID:         o.identifier("agent_id"),
		AgentKeyID:      o.identifier("agent_key_id"),
		TaskID:          o.identifier("task_id"),
		Service:         o.identifier("service"),
		Resource:        o.identifier("resource"),
		Operation:       o.identifier("operation"),
		Method:          o.oneOf("method", "GET", "POST", "PUT", "PATCH", "DELETE"),
		Path:            o.str("path"),
		CredentialID:    o.identifier("credential_id"),
		Query:           map[string]any{},
	}
	if o.err == nil && !validPath(r.Path) {
		o.fail("path", "must be an absolute slash path of 1..1024 characters without NUL, backslash or dot segments")
	}
	if q, ok := o.get("query"); ok {
		r.Query = decodeQuery(o, q)
	}
	r.Body, _ = o.get("body") // 缺失即 null；值已由严格解析器保证属于 ZTCANON 值域
	if err := o.done(); err != nil {
		return nil, err
	}
	return r, nil
}

func decodeQuery(o *object, v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		o.fail("query", "must be an object")
		return nil
	}
	for k, item := range m {
		if !reQueryKey.MatchString(k) {
			o.fail("query", "invalid query key %q", k)
			return nil
		}
		switch x := item.(type) {
		case string:
		case []any:
			if len(x) == 0 {
				o.fail("query", "query arrays must not be empty")
				return nil
			}
			for _, e := range x {
				if _, isStr := e.(string); !isStr {
					o.fail("query", "query array items must be strings")
					return nil
				}
			}
		default:
			o.fail("query", "query values must be a string or an array of strings")
			return nil
		}
	}
	return m
}

// ProtocolSignature 是签名元数据与签名值。
type ProtocolSignature struct {
	Algorithm string
	Encoding  string
	SM2UserID string
	KeyID     string
	Value     string
}

func (s *ProtocolSignature) value() map[string]any {
	return map[string]any{
		"algorithm":   s.Algorithm,
		"encoding":    s.Encoding,
		"sm2_user_id": s.SM2UserID,
		"key_id":      s.KeyID,
		"value":       s.Value,
	}
}

func decodeSignature(v any, path string) (ProtocolSignature, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return ProtocolSignature{}, err
	}
	s := ProtocolSignature{
		Algorithm: o.literal("algorithm", SignatureAlg),
		Encoding:  o.literal("encoding", SignatureEncoding),
		SM2UserID: o.literal("sm2_user_id", "1234567812345678"),
		KeyID:     o.identifier("key_id"),
		Value:     o.str("value"),
	}
	if o.err == nil {
		if n := len(s.Value); n < 8 || n > 256 || !reSigValue.MatchString(s.Value) {
			o.fail("value", "must be 8..256 base64url characters")
		} else if _, err := decodeSignatureValue(s.Value); err != nil {
			o.fail("value", "invalid base64url signature")
		}
	}
	if err := o.done(); err != nil {
		return ProtocolSignature{}, err
	}
	return s, nil
}

// CapabilityBody 是 AA 签名的授权内容。
type CapabilityBody struct {
	ProtocolVersion string
	CapabilityID    string
	Issuer          string
	IssuerKeyID     string
	Audience        string
	AgentID         string
	AgentKeyID      string
	TaskID          string
	Service         string
	Resource        string
	Operation       string
	RequestHash     string
	CredentialID    string
	CredentialEpoch int64
	IssuedAt        int64
	ExpiresAt       int64
	TTLSeconds      int64
	Nonce           string
	OneTime         bool
}

func (b *CapabilityBody) Value() map[string]any {
	return map[string]any{
		"protocol_version": b.ProtocolVersion,
		"capability_id":    b.CapabilityID,
		"issuer":           b.Issuer,
		"issuer_key_id":    b.IssuerKeyID,
		"audience":         b.Audience,
		"agent_id":         b.AgentID,
		"agent_key_id":     b.AgentKeyID,
		"task_id":          b.TaskID,
		"service":          b.Service,
		"resource":         b.Resource,
		"operation":        b.Operation,
		"request_hash":     b.RequestHash,
		"credential_id":    b.CredentialID,
		"credential_epoch": b.CredentialEpoch,
		"issued_at":        b.IssuedAt,
		"expires_at":       b.ExpiresAt,
		"ttl_seconds":      b.TTLSeconds,
		"nonce":            b.Nonce,
		"one_time":         b.OneTime,
	}
}

func decodeCapabilityBody(v any, path string) (*CapabilityBody, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	b := &CapabilityBody{
		ProtocolVersion: o.literal("protocol_version", ProtocolVersion),
		CapabilityID:    o.identifier("capability_id"),
		Issuer:          o.identifier("issuer"),
		IssuerKeyID:     o.identifier("issuer_key_id"),
		Audience:        o.identifier("audience"),
		AgentID:         o.identifier("agent_id"),
		AgentKeyID:      o.identifier("agent_key_id"),
		TaskID:          o.identifier("task_id"),
		Service:         o.identifier("service"),
		Resource:        o.identifier("resource"),
		Operation:       o.identifier("operation"),
		RequestHash:     o.match("request_hash", reHashHex),
		CredentialID:    o.identifier("credential_id"),
		CredentialEpoch: o.integer("credential_epoch", 1, maxEpoch),
		IssuedAt:        o.integer("issued_at", 0, maxTimestamp),
		ExpiresAt:       o.integer("expires_at", 0, maxTimestamp),
		TTLSeconds:      o.integer("ttl_seconds", 1, 300),
		Nonce:           o.match("nonce", reNonceHex),
		OneTime:         true,
	}
	if ot, ok := o.get("one_time"); ok {
		if t, isBool := ot.(bool); !isBool || !t {
			o.fail("one_time", "must be true")
		}
	}
	if o.err == nil {
		switch {
		case b.ExpiresAt <= b.IssuedAt:
			o.fail("expires_at", "capability expires_at must be after issued_at")
		case b.ExpiresAt-b.IssuedAt != b.TTLSeconds:
			o.fail("ttl_seconds", "ttl_seconds must equal expires_at - issued_at")
		}
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return b, nil
}

// SignedCapability 是 AA 签发给 Agent 的票据。
type SignedCapability struct {
	Body      *CapabilityBody
	Signature ProtocolSignature
}

func (c *SignedCapability) Value() map[string]any {
	return map[string]any{"body": c.Body.Value(), "signature": c.Signature.value()}
}

func decodeSignedCapability(v any, path string) (*SignedCapability, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	c := &SignedCapability{
		Body:      sub(o, "body", decodeCapabilityBody),
		Signature: sub(o, "signature", decodeSignature),
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return c, nil
}

// HolderProofBody 是 Agent 用自己私钥签名的持有证明内容。
type HolderProofBody struct {
	ProtocolVersion string
	ProofID         string
	CapabilityID    string
	CapabilityHash  string
	AgentID         string
	AgentKeyID      string
	Audience        string
	RequestHash     string
	Challenge       string
	IssuedAt        int64
	ExpiresAt       int64
}

func (b *HolderProofBody) Value() map[string]any {
	return map[string]any{
		"protocol_version": b.ProtocolVersion,
		"proof_id":         b.ProofID,
		"capability_id":    b.CapabilityID,
		"capability_hash":  b.CapabilityHash,
		"agent_id":         b.AgentID,
		"agent_key_id":     b.AgentKeyID,
		"audience":         b.Audience,
		"request_hash":     b.RequestHash,
		"challenge":        b.Challenge,
		"issued_at":        b.IssuedAt,
		"expires_at":       b.ExpiresAt,
	}
}

// MaxProofLifetime 对应 HolderProofBody 的 60 秒上限。
const MaxProofLifetime = 60

func decodeHolderProofBody(v any, path string) (*HolderProofBody, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	b := &HolderProofBody{
		ProtocolVersion: o.literal("protocol_version", ProtocolVersion),
		ProofID:         o.identifier("proof_id"),
		CapabilityID:    o.identifier("capability_id"),
		CapabilityHash:  o.match("capability_hash", reHashHex),
		AgentID:         o.identifier("agent_id"),
		AgentKeyID:      o.identifier("agent_key_id"),
		Audience:        o.identifier("audience"),
		RequestHash:     o.match("request_hash", reHashHex),
		Challenge:       o.match("challenge", reChallenge),
		IssuedAt:        o.integer("issued_at", 0, maxTimestamp),
		ExpiresAt:       o.integer("expires_at", 0, maxTimestamp),
	}
	if o.err == nil {
		switch {
		case b.ExpiresAt <= b.IssuedAt:
			o.fail("expires_at", "proof expires_at must be after issued_at")
		case b.ExpiresAt-b.IssuedAt > MaxProofLifetime:
			o.fail("expires_at", "holder proof lifetime may not exceed %d seconds", MaxProofLifetime)
		}
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return b, nil
}

// HolderProof 是带签名的持有证明。
type HolderProof struct {
	Body      *HolderProofBody
	Signature ProtocolSignature
}

func (p *HolderProof) Value() map[string]any {
	return map[string]any{"body": p.Body.Value(), "signature": p.Signature.value()}
}

func decodeHolderProof(v any, path string) (*HolderProof, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	p := &HolderProof{
		Body:      sub(o, "body", decodeHolderProofBody),
		Signature: sub(o, "signature", decodeSignature),
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return p, nil
}

// ExecutionReceipt 是 Broker 签发的执行回执内容。
type ExecutionReceipt struct {
	ProtocolVersion string
	ReceiptID       string
	BrokerID        string
	BrokerKeyID     string
	CapabilityID    string
	RequestHash     string
	CredentialID    string
	CredentialEpoch int64
	ResultHash      string
	Outcome         string
	ExecutedAt      int64
}

func (r *ExecutionReceipt) Value() map[string]any {
	return map[string]any{
		"protocol_version": r.ProtocolVersion,
		"receipt_id":       r.ReceiptID,
		"broker_id":        r.BrokerID,
		"broker_key_id":    r.BrokerKeyID,
		"capability_id":    r.CapabilityID,
		"request_hash":     r.RequestHash,
		"credential_id":    r.CredentialID,
		"credential_epoch": r.CredentialEpoch,
		"result_hash":      r.ResultHash,
		"outcome":          r.Outcome,
		"executed_at":      r.ExecutedAt,
	}
}

func decodeExecutionReceipt(v any, path string) (*ExecutionReceipt, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	r := &ExecutionReceipt{
		ProtocolVersion: o.literal("protocol_version", ProtocolVersion),
		ReceiptID:       o.identifier("receipt_id"),
		BrokerID:        o.identifier("broker_id"),
		BrokerKeyID:     o.identifier("broker_key_id"),
		CapabilityID:    o.identifier("capability_id"),
		RequestHash:     o.match("request_hash", reHashHex),
		CredentialID:    o.identifier("credential_id"),
		CredentialEpoch: o.integer("credential_epoch", 1, maxEpoch),
		ResultHash:      o.match("result_hash", reHashHex),
		Outcome:         o.oneOf("outcome", "SUCCESS", "DENIED", "ERROR"),
		ExecutedAt:      o.integer("executed_at", 0, maxTimestamp),
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return r, nil
}

// SignedReceipt 是带 Broker 签名的回执。
type SignedReceipt struct {
	Body      *ExecutionReceipt
	Signature ProtocolSignature
}

func (r *SignedReceipt) Value() map[string]any {
	return map[string]any{"body": r.Body.Value(), "signature": r.Signature.value()}
}

// ExecutionBundle 是 Agent 发给 Broker 的执行请求。
type ExecutionBundle struct {
	Request     *AgentRequest
	Capability  *SignedCapability
	HolderProof *HolderProof
}

func (b *ExecutionBundle) Value() map[string]any {
	return map[string]any{
		"request":      b.Request.Value(),
		"capability":   b.Capability.Value(),
		"holder_proof": b.HolderProof.Value(),
	}
}

func decodeExecutionBundle(v any, path string) (*ExecutionBundle, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	b := &ExecutionBundle{
		Request:     sub(o, "request", decodeAgentRequest),
		Capability:  sub(o, "capability", decodeSignedCapability),
		HolderProof: sub(o, "holder_proof", decodeHolderProof),
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return b, nil
}

// parse 先做 ZTCANON 严格解析，再按模型校验。
func parse[T any](data []byte, decode func(any, string) (T, *Error)) (T, *Error) {
	var zero T
	v, err := canonical.Parse(data)
	if err != nil {
		if errors.Is(err, canonical.ErrCanonical) {
			return zero, &Error{Code: CodeCanonicalization, Message: err.Error()}
		}
		return zero, &Error{Code: CodeCanonicalization, Message: "invalid JSON"}
	}
	return decode(v, "$")
}

// ParseExecutionBundle 严格解析 Agent 提交的 Execution Bundle。
func ParseExecutionBundle(data []byte) (*ExecutionBundle, *Error) {
	return parse(data, decodeExecutionBundle)
}

// 以下 Decode* 接受已解析的值树，主要用于测试向量。

func DecodeAgentRequest(v any) (*AgentRequest, *Error)         { return decodeAgentRequest(v, "$") }
func DecodeCapabilityBody(v any) (*CapabilityBody, *Error)     { return decodeCapabilityBody(v, "$") }
func DecodeSignedCapability(v any) (*SignedCapability, *Error) { return decodeSignedCapability(v, "$") }
func DecodeHolderProofBody(v any) (*HolderProofBody, *Error)   { return decodeHolderProofBody(v, "$") }
func DecodeHolderProof(v any) (*HolderProof, *Error)           { return decodeHolderProof(v, "$") }
func DecodeExecutionReceipt(v any) (*ExecutionReceipt, *Error) { return decodeExecutionReceipt(v, "$") }
func DecodeSignature(v any) (ProtocolSignature, *Error)        { return decodeSignature(v, "$") }
