package protocol_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

// vectorBundle 用共享向量拼出一个结构合法的 Execution Bundle 值树（只测 schema，不测签名关系）。
func vectorBundle(t *testing.T) map[string]any {
	t.Helper()
	v := loadVector(t)
	hp := v["holder_proof_vector"].(map[string]any)
	sig := func(derHex, keyID string) map[string]any {
		der, _ := hex.DecodeString(derHex)
		return map[string]any{
			"algorithm": "SM2-SM3", "encoding": "ASN.1-DER/base64url-nopad",
			"sm2_user_id": "1234567812345678", "key_id": keyID,
			"value": base64.RawURLEncoding.EncodeToString(der),
		}
	}
	capBody := clone(v["capability_body"]).(map[string]any)
	proofBody := clone(hp["body"]).(map[string]any)
	return map[string]any{
		"request":      clone(v["request"]),
		"capability":   map[string]any{"body": capBody, "signature": sig(v["signature_der_hex"].(string), capBody["issuer_key_id"].(string))},
		"holder_proof": map[string]any{"body": proofBody, "signature": sig(hp["signature_der_hex"].(string), proofBody["agent_key_id"].(string))},
	}
}

func parseBundle(t *testing.T, tree any) *protocol.Error {
	t.Helper()
	raw, err := canonical.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	_, perr := protocol.ParseExecutionBundle(raw)
	return perr
}

func TestParseExecutionBundleValid(t *testing.T) {
	if perr := parseBundle(t, vectorBundle(t)); perr != nil {
		t.Fatal(perr)
	}
}

func TestParseExecutionBundleRejects(t *testing.T) {
	type edit func(b map[string]any)
	req := func(b map[string]any) map[string]any { return b["request"].(map[string]any) }
	capBody := func(b map[string]any) map[string]any {
		return b["capability"].(map[string]any)["body"].(map[string]any)
	}
	capSig := func(b map[string]any) map[string]any {
		return b["capability"].(map[string]any)["signature"].(map[string]any)
	}
	proofBody := func(b map[string]any) map[string]any {
		return b["holder_proof"].(map[string]any)["body"].(map[string]any)
	}

	cases := map[string]edit{
		"bundle_unknown_field":     func(b map[string]any) { b["task_context"] = map[string]any{} },
		"bundle_missing_proof":     func(b map[string]any) { delete(b, "holder_proof") },
		"request_unknown_field":    func(b map[string]any) { req(b)["extra"] = "x" },
		"request_missing_agent":    func(b map[string]any) { delete(req(b), "agent_id") },
		"request_short_identifier": func(b map[string]any) { req(b)["agent_id"] = "ab" },
		"request_bad_identifier":   func(b map[string]any) { req(b)["service"] = "-git" },
		"request_wrong_version":    func(b map[string]any) { req(b)["protocol_version"] = "2.0" },
		"request_bad_method":       func(b map[string]any) { req(b)["method"] = "get" },
		"request_relative_path":    func(b map[string]any) { req(b)["path"] = "repos/x" },
		"request_dotdot_path":      func(b map[string]any) { req(b)["path"] = "/repos/../secret" },
		"request_backslash_path":   func(b map[string]any) { req(b)["path"] = `/repos\x` },
		"request_empty_query_list": func(b map[string]any) { req(b)["query"] = map[string]any{"a": []any{}} },
		"request_bad_query_key":    func(b map[string]any) { req(b)["query"] = map[string]any{"a b": "1"} },
		"request_int_query_value":  func(b map[string]any) { req(b)["query"] = map[string]any{"a": int64(1)} },
		"request_number_as_string": func(b map[string]any) { req(b)["agent_id"] = int64(123) },
		"cap_epoch_zero":           func(b map[string]any) { capBody(b)["credential_epoch"] = int64(0) },
		"cap_epoch_bool":           func(b map[string]any) { capBody(b)["credential_epoch"] = true },
		"cap_epoch_string":         func(b map[string]any) { capBody(b)["credential_epoch"] = "17" },
		"cap_one_time_false":       func(b map[string]any) { capBody(b)["one_time"] = false },
		"cap_ttl_mismatch":         func(b map[string]any) { capBody(b)["ttl_seconds"] = capBody(b)["ttl_seconds"].(int64) + 1 },
		"cap_ttl_too_long": func(b map[string]any) {
			c := capBody(b)
			c["ttl_seconds"], c["expires_at"] = int64(301), c["issued_at"].(int64)+301
		},
		"cap_negative_time":      func(b map[string]any) { capBody(b)["issued_at"] = int64(-1) },
		"cap_upper_hash":         func(b map[string]any) { capBody(b)["request_hash"] = "AB" + capBody(b)["request_hash"].(string)[2:] },
		"cap_short_nonce":        func(b map[string]any) { capBody(b)["nonce"] = "abcd" },
		"sig_wrong_algorithm":    func(b map[string]any) { capSig(b)["algorithm"] = "SM2-SHA256" },
		"sig_wrong_uid":          func(b map[string]any) { capSig(b)["sm2_user_id"] = "ALICE123@YAHOO.COM" },
		"sig_padding":            func(b map[string]any) { capSig(b)["value"] = capSig(b)["value"].(string) + "==" },
		"sig_std_base64":         func(b map[string]any) { capSig(b)["value"] = "ab+/cdefgh" },
		"sig_too_short":          func(b map[string]any) { capSig(b)["value"] = "abcdef" },
		"sig_bad_length":         func(b map[string]any) { capSig(b)["value"] = "abcdefghi" }, // len%4==1
		"proof_base64_challenge": func(b map[string]any) { proofBody(b)["challenge"] = "q83vEjRWeJq83vEjRWeJq83vEjRWeJq83vEjRWeJq83" },
		"proof_upper_challenge":  func(b map[string]any) { proofBody(b)["challenge"] = "ABCDEF0123456789ABCDEF0123456789" },
		"proof_lifetime_61s": func(b map[string]any) {
			p := proofBody(b)
			p["expires_at"] = p["issued_at"].(int64) + 61
		},
		"proof_expires_before_issue": func(b map[string]any) {
			p := proofBody(b)
			p["expires_at"] = p["issued_at"]
		},
	}
	for name, mutate := range cases {
		b := vectorBundle(t)
		mutate(b)
		if perr := parseBundle(t, b); perr == nil || perr.Code != protocol.CodeSchema {
			t.Errorf("%s: got %v, want %s", name, perr, protocol.CodeSchema)
		}
	}
}

func TestParseExecutionBundleCanonicalErrors(t *testing.T) {
	for _, raw := range []string{`{"request":{},"request":{}}`, `{"x":1.5}`, `not json`} {
		if _, perr := protocol.ParseExecutionBundle([]byte(raw)); perr == nil || perr.Code != protocol.CodeCanonicalization {
			t.Errorf("%s: got %v, want %s", raw, perr, protocol.CodeCanonicalization)
		}
	}
}
