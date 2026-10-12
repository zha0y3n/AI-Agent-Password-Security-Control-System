// Package errcode 定义 Broker 对外的错误 / 拒绝码。
// 当前为 B 侧草案，阶段二与 A 的 errors.py 统一。
package errcode

const (
	// 通用
	BadRequest   = "BAD_REQUEST"
	Unauthorized = "UNAUTHORIZED"
	NotFound     = "NOT_FOUND"
	Conflict     = "CONFLICT"
	Internal     = "INTERNAL_ERROR"

	// Challenge
	ChallengeUnknown    = "CHALLENGE_UNKNOWN"
	ChallengeUsed       = "CHALLENGE_USED"
	ChallengeExpired    = "CHALLENGE_EXPIRED"
	ChallengeWrongAgent = "CHALLENGE_WRONG_AGENT"

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
	UpstreamError = "UPSTREAM_ERROR"
)
