package receipt_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/receipt"
)

// TestResultEnvelopeVectors 用 shared/ 中由 A 的 ResultEnvelope 生成的向量，
// 确认 Broker 构造的 result_envelope 与 result_hash 逐字节一致。
func TestResultEnvelopeVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../shared/test-vectors/result-envelope-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		CapabilityID string `json:"capability_id"`
		RequestHash  string `json:"request_hash"`
		Vectors      []struct {
			Name  string `json:"name"`
			Input struct {
				Outcome         string  `json:"outcome"`
				Code            *string `json:"code"`
				UpstreamStatus  *int    `json:"upstream_status"`
				UpstreamBodyRaw *string `json:"upstream_body_raw"`
			} `json:"input"`
			CanonicalHex string `json:"canonical_hex"`
			ResultHash   string `json:"result_hash"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range doc.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			code, status := "", 0
			var body []byte
			if v.Input.Code != nil {
				code = *v.Input.Code
			}
			if v.Input.UpstreamStatus != nil {
				status = *v.Input.UpstreamStatus
			}
			if v.Input.UpstreamBodyRaw != nil {
				body = []byte(*v.Input.UpstreamBodyRaw)
			}
			got, err := protocol.Canonical(receipt.NewEnvelope(doc.CapabilityID, doc.RequestHash, v.Input.Outcome, code, status, body))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != v.CanonicalHex {
				t.Fatalf("canonical bytes differ\ngot  %s", got)
			}
			if crypto.SM3Hex(got) != v.ResultHash {
				t.Fatalf("result_hash differs")
			}
		})
	}
}
