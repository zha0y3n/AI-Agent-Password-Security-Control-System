package protocol_test

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

const vectorPath = "../../../shared/test-vectors/sm2-sm3-v1.json"

func loadVector(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	v, err := canonical.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

// clone 深拷贝值树，便于构造篡改样本。
func clone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = clone(e)
		}
		return m
	case []any:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = clone(e)
		}
		return a
	default:
		return v
	}
}

func sigFromDER(t *testing.T, derHex, keyID string) protocol.ProtocolSignature {
	t.Helper()
	der, err := hex.DecodeString(derHex)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.ProtocolSignature{
		Algorithm: protocol.SignatureAlg, Encoding: protocol.SignatureEncoding,
		SM2UserID: crypto.SM2UserID, KeyID: keyID,
		Value: base64.RawURLEncoding.EncodeToString(der),
	}
}

func TestSM3KnownAnswer(t *testing.T) {
	ka := loadVector(t)["sm3_known_answer"].(map[string]any)
	msg, _ := hex.DecodeString(ka["message_hex"].(string))
	if got := crypto.SM3Hex(msg); got != ka["digest_hex"] {
		t.Fatalf("SM3 known answer: got %s want %s", got, ka["digest_hex"])
	}
}

func TestRequestHashVector(t *testing.T) {
	v := loadVector(t)
	req, perr := protocol.DecodeAgentRequest(v["request"])
	if perr != nil {
		t.Fatal(perr)
	}
	h, err := protocol.RequestHash(req)
	if err != nil {
		t.Fatal(err)
	}
	if h != v["request_sm3_hex"] {
		t.Fatalf("request hash: got %s want %s", h, v["request_sm3_hex"])
	}
}

// Pydantic 默认值：缺失 protocol_version / query / body 与显式给出默认值哈希相同。
func TestRequestDefaultsMatchPydantic(t *testing.T) {
	v := loadVector(t)
	full := clone(v["request"]).(map[string]any)
	full["query"], full["body"], full["protocol_version"] = map[string]any{}, nil, "1.0"
	min := clone(full).(map[string]any)
	delete(min, "query")
	delete(min, "body")
	delete(min, "protocol_version")
	a, perr := protocol.DecodeAgentRequest(full)
	if perr != nil {
		t.Fatal(perr)
	}
	b, perr := protocol.DecodeAgentRequest(min)
	if perr != nil {
		t.Fatal(perr)
	}
	ha, _ := protocol.RequestHash(a)
	hb, _ := protocol.RequestHash(b)
	if ha != hb {
		t.Fatalf("defaults change hash: %s vs %s", ha, hb)
	}
}

type signedVector struct {
	name    string
	purpose string
	body    protocol.Valuer
	sig     protocol.ProtocolSignature
	pemKey  string
	msgHex  string
	mutate  func() protocol.Valuer // 返回篡改了一个字段的 body
}

func signedVectors(t *testing.T) []signedVector {
	t.Helper()
	v := loadVector(t)
	hp := v["holder_proof_vector"].(map[string]any)
	rc := v["receipt_vector"].(map[string]any)

	cap, perr := protocol.DecodeCapabilityBody(v["capability_body"])
	if perr != nil {
		t.Fatal(perr)
	}
	proof, perr := protocol.DecodeHolderProofBody(hp["body"])
	if perr != nil {
		t.Fatal(perr)
	}
	receipt, perr := protocol.DecodeExecutionReceipt(rc["body"])
	if perr != nil {
		t.Fatal(perr)
	}
	return []signedVector{
		{
			name: "capability", purpose: protocol.PurposeCapability, body: cap,
			sig:    sigFromDER(t, v["signature_der_hex"].(string), cap.IssuerKeyID),
			pemKey: v["public_key_spki_pem"].(string), msgHex: v["signature_message_hex"].(string),
			mutate: func() protocol.Valuer { c := *cap; c.CredentialEpoch++; return &c },
		},
		{
			name: "holder_proof", purpose: protocol.PurposeHolderProof, body: proof,
			sig:    sigFromDER(t, hp["signature_der_hex"].(string), proof.AgentKeyID),
			pemKey: hp["public_key_spki_pem"].(string), msgHex: hp["signature_message_hex"].(string),
			mutate: func() protocol.Valuer { p := *proof; p.Challenge = strings.Repeat("0", 32); return &p },
		},
		{
			name: "receipt", purpose: protocol.PurposeReceipt, body: receipt,
			sig:    sigFromDER(t, rc["signature_der_hex"].(string), receipt.BrokerKeyID),
			pemKey: rc["public_key_spki_pem"].(string), msgHex: rc["signature_message_hex"].(string),
			mutate: func() protocol.Valuer { r := *receipt; r.Outcome = "ERROR"; return &r },
		},
	}
}

// 三组 Python 签名必须能被 Go 验过；每组的篡改版本必须全部失败。
func TestSharedVectorSignatures(t *testing.T) {
	vectors := signedVectors(t)
	for i, sv := range vectors {
		t.Run(sv.name, func(t *testing.T) {
			pub, err := crypto.ParseSM2PublicKeyPEM(sv.pemKey)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := protocol.Canonical(sv.body)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(protocol.SigningMessage(sv.purpose, payload)); got != sv.msgHex {
				t.Fatalf("signing message differs:\n got %s\nwant %s", got, sv.msgHex)
			}
			if perr := protocol.VerifySignature(pub, sv.purpose, sv.body, sv.sig); perr != nil {
				t.Fatalf("valid vector rejected: %v", perr)
			}

			der, _ := base64.RawURLEncoding.DecodeString(sv.sig.Value)
			flipped := append([]byte(nil), der...)
			flipped[len(flipped)-1] ^= 0x01
			badDER := sv.sig
			badDER.Value = base64.RawURLEncoding.EncodeToString(flipped)
			brokenDER := sv.sig // 破坏 DER 结构（C 报告 A 侧 500 的同一构造）
			brokenDER.Value = "AAAA" + sv.sig.Value[4:]
			wrongAlg := sv.sig
			wrongAlg.Algorithm = "SM2-SHA256"
			wrongUID := sv.sig
			wrongUID.SM2UserID = "0000000000000000"
			otherPub, _ := crypto.ParseSM2PublicKeyPEM(vectors[(i+1)%len(vectors)].pemKey)
			otherPurpose := protocol.PurposeCapability
			if sv.purpose == otherPurpose {
				otherPurpose = protocol.PurposeHolderProof
			}

			for name, c := range map[string]struct {
				pub     *ecdsa.PublicKey
				purpose string
				body    protocol.Valuer
				sig     protocol.ProtocolSignature
				code    string
			}{
				"tampered_body":   {pub, sv.purpose, sv.mutate(), sv.sig, protocol.CodeInvalidSignature},
				"flipped_sig":     {pub, sv.purpose, sv.body, badDER, protocol.CodeInvalidSignature},
				"broken_der":      {pub, sv.purpose, sv.body, brokenDER, protocol.CodeInvalidSignature},
				"wrong_purpose":   {pub, otherPurpose, sv.body, sv.sig, protocol.CodeInvalidSignature},
				"wrong_key":       {otherPub, sv.purpose, sv.body, sv.sig, protocol.CodeInvalidSignature},
				"wrong_algorithm": {pub, sv.purpose, sv.body, wrongAlg, protocol.CodeInvalidSignature},
				"wrong_uid":       {pub, sv.purpose, sv.body, wrongUID, protocol.CodeInvalidSignature},
			} {
				perr := protocol.VerifySignature(c.pub, c.purpose, c.body, c.sig)
				if perr == nil || perr.Code != c.code {
					t.Errorf("%s: got %v, want %s", name, perr, c.code)
				}
			}
		})
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, err := crypto.GenerateSM2Signer()
	if err != nil {
		t.Fatal(err)
	}
	rc := loadVector(t)["receipt_vector"].(map[string]any)
	receipt, perr := protocol.DecodeExecutionReceipt(rc["body"])
	if perr != nil {
		t.Fatal(perr)
	}
	sig, err := protocol.Sign(signer, receipt.BrokerKeyID, protocol.PurposeReceipt, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if perr := protocol.VerifySignature(signer.PublicKey(), protocol.PurposeReceipt, receipt, sig); perr != nil {
		t.Fatal(perr)
	}
	// 生成的签名结构本身也必须通过严格解析
	if _, perr := protocol.DecodeSignature((&protocol.SignedReceipt{Body: receipt, Signature: sig}).Value()["signature"]); perr != nil {
		t.Fatal(perr)
	}
	pemKey, err := crypto.MarshalSM2PublicKeyPEM(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if pub, err := crypto.ParseSM2PublicKeyPEM(pemKey); err != nil || !pub.Equal(signer.PublicKey()) {
		t.Fatalf("PEM round trip failed: %v", err)
	}
}

func TestParsePublicKeyPEMRejects(t *testing.T) {
	good := loadVector(t)["public_key_spki_pem"].(string)
	for name, in := range map[string]string{
		"empty":         "",
		"garbage":       "not a pem",
		"wrong_type":    strings.Replace(good, "PUBLIC KEY", "PRIVATE KEY", 2),
		"trailing_data": good + "junk",
		"two_blocks":    good + good,
	} {
		if _, err := crypto.ParseSM2PublicKeyPEM(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
