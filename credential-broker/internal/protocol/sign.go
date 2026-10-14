package protocol

import (
	"crypto/ecdsa"
	"encoding/base64"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
)

// 签名域（docs/crypto-protocol.md §3.1）。
const (
	PurposeCapability  = "CAPABILITY"
	PurposeHolderProof = "HOLDER_PROOF"
	PurposeReceipt     = "EXECUTION_RECEIPT"
)

// Valuer 是可规范化的协议对象。
type Valuer interface {
	Value() map[string]any
}

// Canonical 返回对象的 ZTCANON-JSON-v1 字节。
func Canonical(v Valuer) ([]byte, error) {
	return canonical.Marshal(v.Value())
}

// SM3Hex 返回对象规范字节的小写十六进制 SM3。
func SM3Hex(v Valuer) (string, error) {
	b, err := Canonical(v)
	if err != nil {
		return "", err
	}
	return crypto.SM3Hex(b), nil
}

// RequestHash = lowercase_hex(SM3(ZTCANON(AgentRequest)))。
func RequestHash(r *AgentRequest) (string, error) { return SM3Hex(r) }

// CapabilityHash = lowercase_hex(SM3(ZTCANON(SignedCapability)))，覆盖 body 与 signature。
func CapabilityHash(c *SignedCapability) (string, error) { return SM3Hex(c) }

// SigningMessage = "AACRED" 0x00 purpose 0x00 "v1" 0x00 canonical_payload。
// 直接交给 SM2-with-SM3，不得预先做 SM3。
func SigningMessage(purpose string, payload []byte) []byte {
	msg := make([]byte, 0, len("AACRED")+len(purpose)+len("v1")+3+len(payload))
	msg = append(msg, "AACRED\x00"...)
	msg = append(msg, purpose...)
	msg = append(msg, 0)
	msg = append(msg, "v1\x00"...)
	return append(msg, payload...)
}

// VerifySignature 校验签名元数据与 SM2 签名。body 为被签对象，purpose 为签名域。
// 调用方负责先确认 sig.KeyID 与 body 中声明的 key id 一致、pub 来自可信注册表。
func VerifySignature(pub *ecdsa.PublicKey, purpose string, body Valuer, sig ProtocolSignature) *Error {
	if sig.Algorithm != SignatureAlg || sig.Encoding != SignatureEncoding || sig.SM2UserID != crypto.SM2UserID {
		return Errorf(CodeInvalidSignature, "unsupported signature metadata")
	}
	der, err := decodeSignatureValue(sig.Value)
	if err != nil {
		return Errorf(CodeInvalidSignatureEncode, "invalid base64url signature")
	}
	payload, err := Canonical(body)
	if err != nil {
		return Errorf(CodeCanonicalization, "%v", err)
	}
	if !crypto.SM2Verify(pub, SigningMessage(purpose, payload), der) {
		return Errorf(CodeInvalidSignature, "SM2 signature verification failed")
	}
	return nil
}

// Sign 用 Broker 私钥对 body 做域分离签名，返回协议签名结构（用于 Receipt 与测试）。
func Sign(signer *crypto.SM2Signer, keyID, purpose string, body Valuer) (ProtocolSignature, error) {
	payload, err := Canonical(body)
	if err != nil {
		return ProtocolSignature{}, err
	}
	der, err := signer.Sign(SigningMessage(purpose, payload))
	if err != nil {
		return ProtocolSignature{}, err
	}
	return ProtocolSignature{
		Algorithm: SignatureAlg,
		Encoding:  SignatureEncoding,
		SM2UserID: crypto.SM2UserID,
		KeyID:     keyID,
		Value:     base64.RawURLEncoding.EncodeToString(der),
	}, nil
}
