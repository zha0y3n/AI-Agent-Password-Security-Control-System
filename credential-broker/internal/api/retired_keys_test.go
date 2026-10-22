package api_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/api"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/logging"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
)

func receiptKey(t *testing.T, keyID, subject, purpose, status string, s *crypto.SM2Signer) map[string]any {
	t.Helper()
	pemKey, err := crypto.MarshalSM2PublicKeyPEM(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"key_id": keyID, "subject_id": subject, "purpose": purpose, "algorithm": "SM2",
		"status": status, "public_key_pem": pemKey, "not_before": int64(1000), "not_after": int64(2000)}
}

func writeRegistry(t *testing.T, keys ...any) string {
	t.Helper()
	doc, err := canonical.Marshal(map[string]any{"protocol_version": "1.0", "keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "retired.json")
	if err := os.WriteFile(path, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRetiredKeys(t *testing.T) {
	current, _ := crypto.GenerateSM2Signer()
	old, _ := crypto.GenerateSM2Signer()
	leaked, _ := crypto.GenerateSM2Signer()

	path := writeRegistry(t,
		receiptKey(t, "broker-key-00", "broker-01", protocol.KeyPurposeReceipt, "ACTIVE", old),
		receiptKey(t, "broker-key-leaked", "broker-01", protocol.KeyPurposeReceipt, "REVOKED", leaked),
	)
	keys, err := api.LoadRetiredKeys(path, "broker-01", "broker-key-01", current.PublicKey())
	if err != nil || len(keys) != 2 {
		t.Fatalf("valid retired keys: %v %v", keys, err)
	}

	for name, rec := range map[string]map[string]any{
		"wrong purpose":   receiptKey(t, "broker-key-00", "broker-01", protocol.KeyPurposeCapability, "ACTIVE", old),
		"wrong subject":   receiptKey(t, "broker-key-00", "broker-02", protocol.KeyPurposeReceipt, "ACTIVE", old),
		"current key id":  receiptKey(t, "broker-key-01", "broker-01", protocol.KeyPurposeReceipt, "ACTIVE", old),
		"current pub key": receiptKey(t, "broker-key-00", "broker-01", protocol.KeyPurposeReceipt, "ACTIVE", current),
	} {
		if _, err := api.LoadRetiredKeys(writeRegistry(t, rec), "broker-01", "broker-key-01", current.PublicKey()); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(bad, []byte(`{"protocol_version":"1.0","keys":[{}]}`), 0o600)
	if _, err := api.LoadRetiredKeys(bad, "broker-01", "broker-key-01", current.PublicKey()); err == nil {
		t.Error("malformed registry: expected error")
	}
}

func TestKeyRegistryPublishesRetiredKeys(t *testing.T) {
	current, _ := crypto.GenerateSM2Signer()
	checkpoint, _ := crypto.GenerateSM2Signer()
	leaked, _ := crypto.GenerateSM2Signer()
	retired, err := api.LoadRetiredKeys(
		writeRegistry(t, receiptKey(t, "broker-key-00", "broker-01", protocol.KeyPurposeReceipt, "REVOKED", leaked)),
		"broker-01", "broker-key-01", current.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	srv := &api.Server{BrokerID: "broker-01", Signer: current, CheckpointSigner: checkpoint,
		KeyID: "broker-key-01", KeyNotBefore: 1000, KeyNotAfter: 3000, RetiredKeys: retired,
		Metrics: metrics.New(), Log: logging.New(io.Discard, "info")}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/v1/broker/key-registry")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// 发布的文档必须仍能被严格解析（A 的 KeyRegistry 同样严格）
	reg, err := protocol.ParseKeyRegistry(body)
	if err != nil {
		t.Fatalf("published registry: %v\n%s", err, body)
	}
	if _, perr := reg.Lookup("broker-key-01", protocol.KeyPurposeReceipt, "broker-01", 1500); perr != nil {
		t.Fatalf("current key: %v", perr)
	}
	if _, perr := reg.Lookup("broker-key-00", protocol.KeyPurposeReceipt, "broker-01", 1500); perr == nil || perr.Code != protocol.CodeKeyRevoked {
		t.Fatalf("revoked retired key: %v", perr)
	}
	var doc struct{ Keys []json.RawMessage }
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Keys) != 2 {
		t.Fatalf("keys: %d %v", len(doc.Keys), err)
	}
}
