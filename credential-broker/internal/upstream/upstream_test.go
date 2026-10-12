package upstream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
)

var ctx = context.Background()

func newPair(t *testing.T) (*Mock, *Client) {
	t.Helper()
	m := NewMock("git-token", "db-token")
	srv := httptest.NewServer(m.Handler())
	t.Cleanup(srv.Close)
	return m, NewClient(srv.URL, 5*time.Second)
}

func TestRequiresCorrectCredential(t *testing.T) {
	m, c := newPair(t)
	read := Call{Service: "git", Operation: "read_file", Resource: "repo-A", Args: map[string]string{"path": "README.md"}}

	resp, err := c.Do(ctx, read, secret.Secret("wrong"))
	if err != nil || resp.Status != http.StatusUnauthorized {
		t.Fatalf("wrong credential: %+v %v", resp, err)
	}
	resp, err = c.Do(ctx, read, secret.Secret("db-token"))
	if err != nil || resp.Status != http.StatusUnauthorized {
		t.Fatalf("other service's credential: %+v %v", resp, err)
	}
	resp, err = c.Do(ctx, read, secret.Secret("git-token"))
	if err != nil || resp.Status != http.StatusOK || !strings.Contains(string(resp.Body), "public project readme") {
		t.Fatalf("read: %+v %v", resp, err)
	}
	if s := m.Stats(); s.AuthFailures != 2 || s.Calls["git"] != 1 || s.SideEffects != 0 {
		t.Fatalf("stats: %+v", s)
	}
	if _, err := c.Do(ctx, Call{Service: "git", Operation: "delete_repo"}, secret.Secret("git-token")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported: %v", err)
	}
}

func TestWriteSideEffectsAndIdempotency(t *testing.T) {
	m, c := newPair(t)
	write := Call{
		Service: "git", Operation: "write_file", Resource: "repo-A",
		Args:  map[string]string{"path": "docs/new.md", "content": "hello"},
		CapID: "cap-1", RequestHash: "h1",
	}
	resp, err := c.Do(ctx, write, secret.Secret("git-token"))
	if err != nil || resp.Status != http.StatusOK || resp.Replay {
		t.Fatalf("write: %+v %v", resp, err)
	}
	// 同 cap + 同请求：返回旧结果，副作用不增加
	resp, err = c.Do(ctx, write, secret.Secret("git-token"))
	if err != nil || resp.Status != http.StatusOK || !resp.Replay {
		t.Fatalf("replay: %+v %v", resp, err)
	}
	// 同 cap + 不同请求：409
	write.RequestHash, write.Args["content"] = "h2", "evil"
	resp, err = c.Do(ctx, write, secret.Secret("git-token"))
	if err != nil || resp.Status != http.StatusConflict {
		t.Fatalf("conflict: %+v %v", resp, err)
	}

	upd := Call{Service: "db", Operation: "update", Resource: "app-db",
		Args: map[string]string{"key": "user:1", "value": "mallory"}, CapID: "cap-2", RequestHash: "h"}
	if resp, err := c.Do(ctx, upd, secret.Secret("db-token")); err != nil || resp.Status != http.StatusOK {
		t.Fatalf("db update: %+v %v", resp, err)
	}
	q := Call{Service: "db", Operation: "query", Resource: "app-db", Args: map[string]string{"key": "user:1"}}
	if resp, _ := c.Do(ctx, q, secret.Secret("db-token")); !strings.Contains(string(resp.Body), "mallory") {
		t.Fatalf("db query: %s", resp.Body)
	}

	s := m.Stats()
	if s.SideEffects != 2 || s.ByCapability["cap-1"] != 1 || s.ByCapability["cap-2"] != 1 ||
		s.ByResource["git:repo-A"] != 1 || s.Replays != 1 {
		t.Fatalf("stats: %+v", s)
	}
	m.Reset()
	if s := m.Stats(); s.SideEffects != 0 {
		t.Fatal("reset failed")
	}
	if c.Calls() != 5 {
		t.Fatalf("client calls = %d", c.Calls())
	}
}
