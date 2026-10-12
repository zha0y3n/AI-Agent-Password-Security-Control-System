package logging

import (
	"bytes"
	"strings"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
)

func TestRedaction(t *testing.T) {
	var buf bytes.Buffer
	log := New(&buf, "debug")
	log.Info("event",
		"secret", "plain-1",
		"admin_token", "plain-2",
		"Authorization", "Bearer plain-3",
		"cred", secret.Secret("plain-4"),
		"cap_id", "cap-001",
	)
	out := buf.String()
	if strings.Contains(out, "plain-") {
		t.Fatalf("sensitive value leaked: %s", out)
	}
	if !strings.Contains(out, "cap-001") {
		t.Fatalf("non-sensitive value dropped: %s", out)
	}
}
