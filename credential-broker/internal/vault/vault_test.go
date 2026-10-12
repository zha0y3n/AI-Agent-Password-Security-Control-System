package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
)

func TestVaultBindsMetadata(t *testing.T) {
	v, err := New(bytes.Repeat([]byte{7}, 16))
	if err != nil {
		t.Fatal(err)
	}
	s := secret.Secret("ghp_example")
	nonce, ct, err := v.Seal("git-prod", "github", 17, s)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("ghp_example")) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := v.Open("git-prod", "github", 17, nonce, ct)
	if err != nil || string(got.Bytes()) != "ghp_example" {
		t.Fatalf("open: %v", err)
	}
	for _, c := range []struct {
		id, provider string
		epoch        int64
	}{
		{"git-prod", "github", 18},
		{"git-prod", "github", 16},
		{"git-test", "github", 17},
		{"git-prod", "gitlab", 17},
	} {
		if _, err := v.Open(c.id, c.provider, c.epoch, nonce, ct); err == nil {
			t.Errorf("open with %+v should fail", c)
		}
	}
	if v.Opens() != 5 {
		t.Errorf("opens = %d, want 5", v.Opens())
	}
}

func TestAADIsUnambiguous(t *testing.T) {
	if bytes.Equal(AAD("a", "bc", 1), AAD("ab", "c", 1)) {
		t.Fatal("AAD must be length-prefixed")
	}
}

func TestSecretNeverPrinted(t *testing.T) {
	s := secret.Secret("super-secret-token")
	out, _ := json.Marshal(map[string]any{"s": s})
	for _, str := range []string{fmt.Sprint(s), fmt.Sprintf("%v %s %#v", s, s, s), string(out)} {
		if bytes.Contains([]byte(str), []byte("super-secret")) {
			t.Fatalf("secret leaked: %s", str)
		}
	}
	s.Wipe()
	if !bytes.Equal(s, make([]byte, len(s))) {
		t.Fatal("wipe failed")
	}
}
