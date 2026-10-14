// Package protocol 是 A 协议对象（shared/schemas）在 Go 侧的严格实现：
// 解析、字段校验、规范化、请求摘要和 SM2 域分离签名。
//
// 权威定义是 A 的 agent_aa.models（Pydantic），本包逐字段镜像其约束与默认值，
// 保证同一份输入在 Python 与 Go 两侧得到相同的规范字节、摘要和验签结论。
package protocol

import "fmt"

// 错误码与 A 的 errors.py / docs/a-b-interface.md 保持一致。
const (
	CodeCanonicalization       = "CANONICALIZATION_ERROR"
	CodeSchema                 = "SCHEMA_VALIDATION_FAILED"
	CodeInvalidSignature       = "INVALID_SIGNATURE"
	CodeInvalidSignatureEncode = "INVALID_SIGNATURE_ENCODING"
	CodeSignatureKeyMismatch   = "SIGNATURE_KEY_MISMATCH"
	CodeUntrustedIssuer        = "UNTRUSTED_ISSUER"
	CodeCapabilityNotYetValid  = "CAPABILITY_NOT_YET_VALID"
	CodeCapabilityExpired      = "CAPABILITY_EXPIRED"
	CodeAudienceMismatch       = "AUDIENCE_MISMATCH"
	CodeRequestBinding         = "REQUEST_BINDING_MISMATCH"
	CodeRequestHash            = "REQUEST_HASH_MISMATCH"
	CodeHolderBinding          = "HOLDER_BINDING_MISMATCH"
	CodeProofNotYetValid       = "PROOF_NOT_YET_VALID"
	CodeProofExpired           = "PROOF_EXPIRED"
	CodeUnknownKey             = "UNKNOWN_KEY"
	CodeKeyRevoked             = "KEY_REVOKED"
	CodeWrongKeyPurpose        = "WRONG_KEY_PURPOSE"
	CodeKeySubjectMismatch     = "KEY_SUBJECT_MISMATCH"
	CodeKeyOutsideValidity     = "KEY_OUTSIDE_VALIDITY"
)

// Error 是带稳定错误码的协议错误。
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf 构造协议错误。
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}
