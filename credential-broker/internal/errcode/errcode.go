// Package errcode 定义 Broker 对外的错误 / 拒绝码。
// 协议校验类拒绝码沿用 A 的 errors.py（见 internal/protocol），这里是 B 扩展的执行 / 生命周期 / 重放类拒绝码。
package errcode

const (
	// 通用
	BadRequest   = "BAD_REQUEST"
	Unauthorized = "UNAUTHORIZED"
	NotFound     = "NOT_FOUND"
	Conflict     = "CONFLICT"
	Internal     = "INTERNAL_ERROR"

	// Challenge
	ChallengeUnknown       = "CHALLENGE_UNKNOWN"
	ChallengeUsed          = "CHALLENGE_USED"
	ChallengeExpired       = "CHALLENGE_EXPIRED"
	ChallengeWrongAgent    = "CHALLENGE_WRONG_AGENT"
	ChallengeWrongAudience = "CHALLENGE_WRONG_AUDIENCE"

	// Credential
	CredentialNotFound      = "CREDENTIAL_NOT_FOUND"
	CredentialInactive      = "CREDENTIAL_INACTIVE"
	CredentialEpochMismatch = "CREDENTIAL_EPOCH_MISMATCH"
	CredentialUnavailable   = "CREDENTIAL_UNAVAILABLE"
	InvalidTransition       = "INVALID_STATE_TRANSITION"

	// Capability 消费
	ReplayInProgress        = "REPLAY_IN_PROGRESS"
	IdempotencyConflict     = "IDEMPOTENCY_CONFLICT"
	CapabilityClaimMismatch = "CAPABILITY_CLAIM_MISMATCH"
	CapabilityFailed        = "CAPABILITY_ALREADY_FAILED"

	// 上游
	UpstreamError        = "UPSTREAM_ERROR"        // 上游不可达或 5xx，Capability -> FAILED
	UpstreamRejected     = "UPSTREAM_REJECTED"     // 上游已处理但返回 3xx/4xx（回执 outcome=ERROR，Capability 仍为 CONSUMED）
	UnsupportedOperation = "UNSUPPORTED_OPERATION" // AgentRequest 无法映射为受支持的上游调用
)

// 执行接口
const (
	ExecutionDisabled = "EXECUTION_DISABLED" // 未配置可信 issuer / 公钥表
	ResetDisabled     = "RESET_DISABLED"     // 未开启 BROKER_ENABLE_RESET
)

// ExecuteStatus 把 POST /v1/execute 的拒绝码映射为 HTTP 状态码：
//
//	400 请求本身不是合法的 Execution Bundle
//	409 与同一 Capability 的并发 / 先前执行冲突
//	502 赢得执行权后上游失败
//	500 Broker 内部故障
//	403 其余全部拒绝（签名、时间、绑定、Challenge、Credential 生命周期……）
func ExecuteStatus(code string) int {
	switch code {
	case "CANONICALIZATION_ERROR", "SCHEMA_VALIDATION_FAILED":
		return 400
	case ReplayInProgress, IdempotencyConflict, CapabilityClaimMismatch:
		return 409
	case UpstreamError:
		return 502
	case Internal:
		return 500
	default:
		return 403
	}
}
