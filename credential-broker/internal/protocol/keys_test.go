package protocol_test

import (
	"os"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

func keyRecord(keyID, subject, purpose, pem string) map[string]any {
	return map[string]any{
		"key_id": keyID, "subject_id": subject, "purpose": purpose,
		"algorithm": "SM2", "status": "ACTIVE", "public_key_pem": pem,
		"not_before": int64(1000), "not_after": int64(2000),
	}
}

func registryDoc(t *testing.T) map[string]any {
	t.Helper()
	v := loadVector(t)
	return map[string]any{
		"protocol_version": "1.0",
		"keys": []any{
			keyRecord("aa-key-01", "aa-01", protocol.KeyPurposeCapability, v["public_key_spki_pem"].(string)),
			keyRecord("agent-key-01", "agent-01", protocol.KeyPurposeHolderProof,
				v["holder_proof_vector"].(map[string]any)["public_key_spki_pem"].(string)),
		},
	}
}

func mustParseRegistry(t *testing.T, doc any) (*protocol.KeyRegistry, error) {
	t.Helper()
	raw, err := canonical.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return protocol.ParseKeyRegistry(raw)
}

func TestKeyRegistryLookup(t *testing.T) {
	reg, err := mustParseRegistry(t, registryDoc(t))
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 2 {
		t.Fatalf("len = %d", reg.Len())
	}
	if _, perr := reg.Lookup("aa-key-01", protocol.KeyPurposeCapability, "aa-01", 1500); perr != nil {
		t.Fatal(perr)
	}
	for name, c := range map[string]struct {
		keyID, purpose, subject string
		at                      int64
		code                    string
	}{
		"unknown":       {"nope-key", protocol.KeyPurposeCapability, "aa-01", 1500, protocol.CodeUnknownKey},
		"wrong_purpose": {"agent-key-01", protocol.KeyPurposeCapability, "agent-01", 1500, protocol.CodeWrongKeyPurpose},
		"wrong_subject": {"aa-key-01", protocol.KeyPurposeCapability, "aa-evil", 1500, protocol.CodeKeySubjectMismatch},
		"before_window": {"aa-key-01", protocol.KeyPurposeCapability, "aa-01", 999, protocol.CodeKeyOutsideValidity},
		"at_not_after":  {"aa-key-01", protocol.KeyPurposeCapability, "aa-01", 2000, protocol.CodeKeyOutsideValidity},
	} {
		if _, perr := reg.Lookup(c.keyID, c.purpose, c.subject, c.at); perr == nil || perr.Code != c.code {
			t.Errorf("%s: got %v want %s", name, perr, c.code)
		}
	}
}

func TestKeyRegistryRevoked(t *testing.T) {
	doc := registryDoc(t)
	doc["keys"].([]any)[0].(map[string]any)["status"] = "REVOKED"
	reg, err := mustParseRegistry(t, doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, perr := reg.Lookup("aa-key-01", protocol.KeyPurposeCapability, "aa-01", 1500); perr == nil || perr.Code != protocol.CodeKeyRevoked {
		t.Fatalf("revoked key: %v", perr)
	}
}

func TestKeyRegistryRejects(t *testing.T) {
	for name, mutate := range map[string]func(doc map[string]any){
		"duplicate_key_id": func(d map[string]any) {
			d["keys"] = append(d["keys"].([]any), d["keys"].([]any)[0])
		},
		"unknown_field":   func(d map[string]any) { d["keys"].([]any)[0].(map[string]any)["x"] = "y" },
		"bad_purpose":     func(d map[string]any) { d["keys"].([]any)[0].(map[string]any)["purpose"] = "ANY" },
		"bad_algorithm":   func(d map[string]any) { d["keys"].([]any)[0].(map[string]any)["algorithm"] = "RSA" },
		"bad_status":      func(d map[string]any) { d["keys"].([]any)[0].(map[string]any)["status"] = "active" },
		"inverted_window": func(d map[string]any) { d["keys"].([]any)[0].(map[string]any)["not_after"] = int64(1000) },
		"garbage_pem": func(d map[string]any) {
			d["keys"].([]any)[0].(map[string]any)["public_key_pem"] = "-----BEGIN PUBLIC KEY-----\n" +
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END PUBLIC KEY-----\n"
		},
		"keys_not_list": func(d map[string]any) { d["keys"] = map[string]any{} },
		"wrong_version": func(d map[string]any) { d["protocol_version"] = "0.9" },
	} {
		doc := registryDoc(t)
		mutate(doc)
		if _, err := mustParseRegistry(t, doc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// BROKER_TEST_A_KEYS 指向 `agent-aa init-demo` 生成的 public-keys.json 时，
// 验证 Broker 能直接加载 A 的真实运行时注册表。
func TestLoadARuntimeRegistry(t *testing.T) {
	path := os.Getenv("BROKER_TEST_A_KEYS")
	if path == "" {
		t.Skip("BROKER_TEST_A_KEYS not set")
	}
	reg, err := protocol.LoadKeyRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() == 0 {
		t.Fatal("empty registry")
	}
}
