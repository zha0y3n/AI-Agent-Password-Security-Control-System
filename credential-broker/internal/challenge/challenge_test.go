package challenge

import (
	"context"
	"errors"
	"path/filepath"
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
	return NewService(db, time.Minute)
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
