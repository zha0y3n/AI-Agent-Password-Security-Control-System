package receipt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/receipt"
)

var hash = strings.Repeat("ab", 32)

func TestEnvelopeNullsAndCanonicalFallback(t *testing.T) {
	denied, err := protocol.Canonical(receipt.NewEnvelope("cap_1", hash, receipt.OutcomeDenied, "CHALLENGE_USED", 0, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"capability_id":"cap_1","code":"CHALLENGE_USED","outcome":"DENIED","protocol_version":"1.0",` +
		`"request_hash":"` + hash + `","upstream_body":null,"upstream_status":null}`
	if string(denied) != want {
		t.Fatalf("got  %s\nwant %s", denied, want)
	}
	// 上游返回浮点数（不符合 ZTCANON-JSON-v1）：以原始文本字符串放入，仍可规范化。
	float, err := protocol.Canonical(receipt.NewEnvelope("cap_1", hash, receipt.OutcomeSuccess, "", 200, []byte(`{"x":1.5}`)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(float), `"upstream_body":"{\"x\":1.5}"`) || !strings.Contains(string(float), `"code":null`) {
		t.Fatalf("fallback envelope: %s", float)
	}
}

func TestIssueRefusesMalformedReceipt(t *testing.T) {
	signer, _ := crypto.GenerateSM2Signer()
	iss := &receipt.Issuer{BrokerID: "broker-01", KeyID: "broker-key-01", Signer: signer, Now: func() time.Time { return time.Unix(1000, 0) }}
	env := receipt.NewEnvelope("cap_1", hash, receipt.OutcomeSuccess, "", 200, []byte(`{}`))
	if _, err := iss.Issue(receipt.Claim{CapabilityID: "cap_1", RequestHash: hash, CredentialID: "github-prod", CredentialEpoch: 0}, env); err == nil {
		t.Fatal("signed a receipt with epoch 0")
	}
	got, err := iss.Issue(receipt.Claim{CapabilityID: "cap_1", RequestHash: hash, CredentialID: "github-prod", CredentialEpoch: 3}, env)
	if err != nil {
		t.Fatal(err)
	}
	if got.Receipt.Body.ExecutedAt != 1000 || got.Receipt.Body.ResultHash != crypto.SM3Hex(got.Envelope) {
		t.Fatalf("receipt body: %+v", got.Receipt.Body)
	}
	parsed, perr := protocol.ParseSignedReceipt(got.Bytes)
	if perr != nil {
		t.Fatal(perr)
	}
	if perr := protocol.VerifySignature(signer.PublicKey(), protocol.PurposeReceipt, parsed.Body, parsed.Signature); perr != nil {
		t.Fatal(perr)
	}
}
