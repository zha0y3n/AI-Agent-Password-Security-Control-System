package receipt_test

import (
	"strings"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/receipt"
)

// 拒绝路径上的 DENIED 回执成本，与“签发回执之前一定已完成的” Capability SM2 验签对比：
//
//	go test -run '^$' -bench . ./internal/receipt/
func BenchmarkIssueDeniedReceipt(b *testing.B) {
	signer, err := crypto.GenerateSM2Signer()
	if err != nil {
		b.Fatal(err)
	}
	iss := &receipt.Issuer{BrokerID: "broker-01", KeyID: "broker-key-01", Signer: signer}
	claim := receipt.Claim{CapabilityID: "cap_bench", RequestHash: strings.Repeat("ab", 32), CredentialID: "github-prod", CredentialEpoch: 17}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := iss.Issue(claim, receipt.NewEnvelope(claim.CapabilityID, claim.RequestHash, receipt.OutcomeDenied, "CHALLENGE_USED", 0, nil)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCapabilitySignatureVerify(b *testing.B) {
	signer, err := crypto.GenerateSM2Signer()
	if err != nil {
		b.Fatal(err)
	}
	msg := []byte(strings.Repeat("x", 600)) // 与规范化后的 Capability 大小相当
	sig, err := signer.Sign(msg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !crypto.SM2Verify(signer.PublicKey(), msg, sig) {
			b.Fatal("verify failed")
		}
	}
}
