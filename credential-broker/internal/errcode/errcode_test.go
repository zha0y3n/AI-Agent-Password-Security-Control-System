package errcode_test

import (
	"os"
	"strings"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

// TestCodesAreDocumented 确认 Broker 能返回的每个错误码都写进了统一错误码表。
func TestCodesAreDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/error-codes.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{
		errcode.BadRequest, errcode.Unauthorized, errcode.NotFound, errcode.Conflict, errcode.Internal,
		errcode.ChallengeUnknown, errcode.ChallengeUsed, errcode.ChallengeExpired,
		errcode.ChallengeWrongAgent, errcode.ChallengeWrongAudience,
		errcode.CredentialNotFound, errcode.CredentialInactive, errcode.CredentialEpochMismatch,
		errcode.CredentialUnavailable, errcode.InvalidTransition,
		errcode.ReplayInProgress, errcode.IdempotencyConflict, errcode.CapabilityClaimMismatch,
		errcode.CapabilityFailed, errcode.CapabilityNonceReused,
		errcode.UpstreamError, errcode.UpstreamRejected, errcode.UnsupportedOperation,
		errcode.ExecutionDisabled, errcode.ResetDisabled,
		protocol.CodeCanonicalization, protocol.CodeSchema, protocol.CodeInvalidSignature,
		protocol.CodeInvalidSignatureEncode, protocol.CodeSignatureKeyMismatch, protocol.CodeUntrustedIssuer,
		protocol.CodeCapabilityNotYetValid, protocol.CodeCapabilityExpired, protocol.CodeAudienceMismatch,
		protocol.CodeRequestBinding, protocol.CodeRequestHash, protocol.CodeHolderBinding,
		protocol.CodeProofNotYetValid, protocol.CodeProofExpired, protocol.CodeUnknownKey,
		protocol.CodeKeyRevoked, protocol.CodeWrongKeyPurpose, protocol.CodeKeySubjectMismatch,
		protocol.CodeKeyOutsideValidity,
	} {
		if !strings.Contains(string(doc), "`"+code+"`") {
			t.Errorf("%s is missing from docs/error-codes.md", code)
		}
	}
}
