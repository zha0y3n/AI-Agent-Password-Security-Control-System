package capability_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
)

var ctx = context.Background()

func setup(t *testing.T) (*testenv.Env, *capability.Store) {
	t.Helper()
	env := testenv.New(t)
	if _, err := env.Credentials.Create(ctx, "git-prod", "github", secret.Secret("tok")); err != nil {
		t.Fatal(err)
	}
	return env, capability.NewStore(env.DB, env.Auditor)
}

func claim(capID string) capability.Claim {
	return capability.Claim{CapID: capID, RequestHash: "h1", CredentialID: "git-prod", CredentialEpoch: 1}
}

func TestConsumeLifecycleAndIdempotency(t *testing.T) {
	_, store := setup(t)

	res, err := store.Consume(ctx, claim("cap-1"))
	if err != nil || res.Outcome != capability.Won {
		t.Fatalf("first consume: %+v %v", res, err)
	}
	if _, err := store.Consume(ctx, claim("cap-1")); !errors.Is(err, capability.ErrInProgress) {
		t.Fatalf("consume while CONSUMING: %v", err)
	}
	if err := store.Complete(ctx, "cap-1", []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}

	// 同 cap + 同请求：返回旧结果，不产生新副作用
	res, err = store.Consume(ctx, claim("cap-1"))
	if err != nil || res.Outcome != capability.Replayed || string(res.Stored) != `{"ok":true}` {
		t.Fatalf("idempotent replay: %+v %v", res, err)
	}
	// 同 cap + 不同请求：拒绝
	c := claim("cap-1")
	c.RequestHash = "h2"
	if _, err := store.Consume(ctx, c); !errors.Is(err, capability.ErrRequestMismatch) {
		t.Fatalf("idempotency conflict: %v", err)
	}
	c = claim("cap-1")
	c.CredentialEpoch = 2
	if _, err := store.Consume(ctx, c); !errors.Is(err, capability.ErrClaimMismatch) {
		t.Fatalf("claim mismatch: %v", err)
	}
	if err := store.Complete(ctx, "cap-1", nil); !errors.Is(err, capability.ErrNotConsuming) {
		t.Fatalf("double complete: %v", err)
	}
}

func TestNonceIsSingleUse(t *testing.T) {
	_, store := setup(t)
	a := claim("cap-a")
	a.Nonce = "0123456789abcdef0123456789abcdef"
	if res, err := store.Consume(ctx, a); err != nil || res.Outcome != capability.Won {
		t.Fatalf("first consume: %+v %v", res, err)
	}
	// 另一个 cap_id 复用同一 nonce：拒绝，且不留下记录
	b := claim("cap-b")
	b.Nonce = a.Nonce
	if _, err := store.Consume(ctx, b); !errors.Is(err, capability.ErrNonceReused) {
		t.Fatalf("nonce reuse: %v", err)
	}
	if _, err := store.Get(ctx, "cap-b"); err == nil {
		t.Fatal("rejected capability left a record")
	}
	// 同一 cap_id 换 nonce：claim 不一致
	a2 := a
	a2.Nonce = "fedcba9876543210fedcba9876543210"
	if _, err := store.Consume(ctx, a2); !errors.Is(err, capability.ErrClaimMismatch) {
		t.Fatalf("same cap, different nonce: %v", err)
	}
	if info, err := store.Get(ctx, "cap-a"); err != nil || info.Nonce != a.Nonce {
		t.Fatalf("info: %+v %v", info, err)
	}
}

func TestFailedCapabilityCannotBeReused(t *testing.T) {
	_, store := setup(t)
	if _, err := store.Consume(ctx, claim("cap-f")); err != nil {
		t.Fatal(err)
	}
	if err := store.Fail(ctx, "cap-f", "UPSTREAM_ERROR"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, claim("cap-f")); !errors.Is(err, capability.ErrAlreadyFailed) {
		t.Fatalf("reuse failed cap: %v", err)
	}
}

func TestRecoverAbandonedFailsOnlyConsuming(t *testing.T) {
	env, store := setup(t)
	for _, id := range []string{"cap-stuck", "cap-done"} {
		if _, err := store.Consume(ctx, claim(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Complete(ctx, "cap-done", []byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}

	n, err := store.RecoverAbandoned(ctx, "INTERNAL_ERROR")
	if err != nil || n != 1 {
		t.Fatalf("recover: n=%d err=%v", n, err)
	}
	info, err := store.Get(ctx, "cap-stuck")
	if err != nil || info.State != capability.StateFailed || info.ErrorCode != "INTERNAL_ERROR" {
		t.Fatalf("stuck capability after recovery: %+v %v", info, err)
	}
	// 恢复后不允许再次消费：上游可能已经执行过
	if _, err := store.Consume(ctx, claim("cap-stuck")); !errors.Is(err, capability.ErrAlreadyFailed) {
		t.Fatalf("reuse recovered cap: %v", err)
	}
	// 已完成的 Capability 不受影响，仍然幂等返回旧结果
	res, err := store.Consume(ctx, claim("cap-done"))
	if err != nil || res.Outcome != capability.Replayed {
		t.Fatalf("completed cap after recovery: %+v %v", res, err)
	}
	if auditSeq(t, env, "capability.recover", "cap_id", "cap-stuck") == 0 {
		t.Fatal("recovery must be audited")
	}
	if n, err := store.RecoverAbandoned(ctx, "INTERNAL_ERROR"); err != nil || n != 0 {
		t.Fatalf("second recovery: n=%d err=%v", n, err)
	}
}

func TestDeniedConsumeLeavesNoState(t *testing.T) {
	env, store := setup(t)
	if _, err := env.Credentials.Apply(ctx, "git-prod", credential.ActionDisable); err != nil {
		t.Fatal(err)
	}
	c := claim("cap-d")
	c.CredentialEpoch = 2
	if _, err := store.Consume(ctx, c); !errors.Is(err, credential.ErrInactive) {
		t.Fatalf("disabled credential: %v", err)
	}
	if _, err := store.Consume(ctx, claim("cap-e")); !errors.Is(err, credential.ErrInactive) {
		t.Fatalf("old epoch on disabled credential: %v", err)
	}
	if _, err := store.State(ctx, "cap-d"); err == nil {
		t.Fatal("denied consume must not persist capability row")
	}
}

func TestOldEpochRejected(t *testing.T) {
	env, store := setup(t)
	if _, err := env.Credentials.Rotate(ctx, "git-prod", secret.Secret("tok2")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, claim("cap-old")); !errors.Is(err, credential.ErrEpochMismatch) {
		t.Fatalf("old epoch: %v", err)
	}
}

func TestConcurrentReplayExactlyOneWinner(t *testing.T) {
	_, store := setup(t)
	const n = 100
	var wg sync.WaitGroup
	var mu sync.Mutex
	won, inProgress := 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := store.Consume(ctx, claim("cap-race"))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil && res.Outcome == capability.Won:
				won++
			case errors.Is(err, capability.ErrInProgress):
				inProgress++
			default:
				t.Errorf("unexpected: %+v %v", res, err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if won != 1 || inProgress != n-1 {
		t.Fatalf("won=%d inProgress=%d, want 1/%d", won, inProgress, n-1)
	}
}

// 撤销竞态：Consume 与 Revoke 并发。由于两者在同一写锁下串行化，
// 只允许两种线性化结果：
//   - Consume 先提交：Won，且审计中 consume 的 seq < revoke 的 seq
//   - Revoke 先提交：Consume 被拒绝（ErrInactive）
func TestRevocationRaceIsLinearizable(t *testing.T) {
	env := testenv.New(t)
	store := capability.NewStore(env.DB, env.Auditor)
	const trials = 40
	wins, denies := 0, 0
	for i := 0; i < trials; i++ {
		credID := fmt.Sprintf("cred-%d", i)
		if _, err := env.Credentials.Create(ctx, credID, "github", secret.Secret("tok")); err != nil {
			t.Fatal(err)
		}
		c := capability.Claim{CapID: "cap-" + credID, RequestHash: "h", CredentialID: credID, CredentialEpoch: 1}

		var wg sync.WaitGroup
		var consumeErr, revokeErr error
		var res *capability.Result
		start := make(chan struct{})
		wg.Add(2)
		go func() { defer wg.Done(); <-start; res, consumeErr = store.Consume(ctx, c) }()
		go func() {
			defer wg.Done()
			<-start
			_, revokeErr = env.Credentials.Apply(ctx, credID, credential.ActionRevoke)
		}()
		close(start)
		wg.Wait()

		if revokeErr != nil {
			t.Fatalf("revoke: %v", revokeErr)
		}
		consumeSeq, revokeSeq := auditSeq(t, env, "capability.consume", "cap_id", c.CapID),
			auditSeq(t, env, "credential.revoke", "credential_id", credID)
		switch {
		case consumeErr == nil && res.Outcome == capability.Won:
			wins++
			if consumeSeq == 0 || consumeSeq > revokeSeq {
				t.Fatalf("trial %d: consume won but was linearized after revoke (%d > %d)", i, consumeSeq, revokeSeq)
			}
		case errors.Is(consumeErr, credential.ErrInactive):
			denies++
			if consumeSeq != 0 {
				t.Fatalf("trial %d: denied consume left an audit entry", i)
			}
		default:
			t.Fatalf("trial %d: unexpected consume result %+v %v", i, res, consumeErr)
		}
	}
	t.Logf("consume-first=%d revoke-first=%d", wins, denies)
}

func auditSeq(t *testing.T, env *testenv.Env, typ, key, value string) int64 {
	t.Helper()
	rs, err := env.Auditor.Records(ctx, 1, 100000)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		var e struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(r.Entry), &e); err != nil {
			t.Fatal(err)
		}
		if e.Type == typ && e.Data[key] == value {
			return r.Seq
		}
	}
	return 0
}
