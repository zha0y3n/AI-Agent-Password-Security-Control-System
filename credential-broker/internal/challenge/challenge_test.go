package challenge

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
)

var ctx = context.Background()

func newService(t *testing.T) *Service {
	t.Helper()
	db, err := repository.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewService(db, time.Minute, "broker-01")
}

func TestChallengeRules(t *testing.T) {
	s := newService(t)
	c, err := s.Issue(ctx, "agent-01")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Issue(ctx, ""); !errors.Is(err, ErrBadAgent) {
		t.Errorf("empty agent: %v", err)
	}
	if err := s.Consume(ctx, nil, c.Challenge, "agent-02"); !errors.Is(err, ErrWrongAgent) {
		t.Errorf("wrong agent: %v", err)
	}
	if err := s.Consume(ctx, nil, c.Challenge, "agent-01"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := s.Consume(ctx, nil, c.Challenge, "agent-01"); !errors.Is(err, ErrUsed) {
		t.Errorf("reuse: %v", err)
	}
	if err := s.Consume(ctx, nil, "nope", "agent-01"); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown: %v", err)
	}

	expired, _ := s.Issue(ctx, "agent-01")
	s.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if err := s.Consume(ctx, nil, expired.Challenge, "agent-01"); !errors.Is(err, ErrExpired) {
		t.Errorf("expired: %v", err)
	}
	if n, err := s.Purge(ctx, 0); err != nil || n != 2 {
		t.Errorf("purge: n=%d err=%v", n, err)
	}
}

func TestChallengeSingleUseUnderConcurrency(t *testing.T) {
	s := newService(t)
	c, _ := s.Issue(ctx, "agent-01")
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.Consume(ctx, nil, c.Challenge, "agent-01") == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("challenge consumed %d times", ok.Load())
	}
}

// Challenge 必须满足 A 的 HolderProofBody.challenge 约束：^[0-9a-f]{32,64}$。
func TestChallengeFormatMatchesHolderProofSchema(t *testing.T) {
	s := newService(t)
	re := regexp.MustCompile(`^[0-9a-f]{32,64}$`)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		c, err := s.Issue(ctx, "agent-01")
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(c.Challenge) || len(c.Challenge) != 2*Size {
			t.Fatalf("challenge %q does not match holder proof schema", c.Challenge)
		}
		if c.Audience != "broker-01" {
			t.Fatalf("audience = %q", c.Audience)
		}
		if seen[c.Challenge] {
			t.Fatal("duplicate challenge")
		}
		seen[c.Challenge] = true
	}
}

// 另一个 Broker（不同 audience）即使共享存储也不能消费本 Broker 的 Challenge。
func TestChallengeBoundToAudience(t *testing.T) {
	s := newService(t)
	other := NewService(s.db, time.Minute, "broker-02")
	c, _ := s.Issue(ctx, "agent-01")
	if err := other.Consume(ctx, nil, c.Challenge, "agent-01"); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("cross-audience consume: %v", err)
	}
	if err := s.Consume(ctx, nil, c.Challenge, "agent-01"); err != nil {
		t.Fatalf("own audience: %v", err)
	}
}

// 旧库（challenges 无 audience 列）迁移后可用，旧 Challenge 无法被消费。
func TestChallengeMigratesLegacyTable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE challenges (challenge TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
		expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL);
		INSERT INTO challenges VALUES ('legacy', 'agent-01', 9999999999, 0, 0);`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	db, err := repository.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil { // 重复迁移必须幂等
		t.Fatal(err)
	}
	s := NewService(db, time.Minute, "broker-01")
	if err := s.Consume(ctx, nil, "legacy", "agent-01"); !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("legacy challenge: %v", err)
	}
	c, err := s.Issue(ctx, "agent-01")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Consume(ctx, nil, c.Challenge, "agent-01"); err != nil {
		t.Fatal(err)
	}
}
