package credential_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
)

var ctx = context.Background()

// ok 断言调用成功并返回结果：ok(t)(svc.Create(...))。
func ok(t *testing.T) func(*credential.Info, error) *credential.Info {
	return func(info *credential.Info, err error) *credential.Info {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
}

func TestCreateAndOpen(t *testing.T) {
	env := testenv.New(t)
	svc := env.Credentials
	info := ok(t)(svc.Create(ctx, "git-prod", "github", secret.Secret("tok-1")))
	if info.Status != credential.StatusActive || info.Epoch != 1 {
		t.Fatalf("unexpected %+v", info)
	}
	s, err := svc.Open(ctx, "git-prod", 1)
	if err != nil || string(s.Bytes()) != "tok-1" {
		t.Fatalf("open: %v", err)
	}
	if _, err := svc.Create(ctx, "git-prod", "github", secret.Secret("x")); !errors.Is(err, credential.ErrExists) {
		t.Errorf("duplicate create: %v", err)
	}
	if _, err := svc.Create(ctx, "bad id!", "github", secret.Secret("x")); !errors.Is(err, credential.ErrInvalidInput) {
		t.Errorf("invalid id: %v", err)
	}
	if _, err := svc.Open(ctx, "missing", 1); !errors.Is(err, credential.ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
}

func TestRotateInvalidatesOldEpoch(t *testing.T) {
	svc := testenv.New(t).Credentials
	ok(t)(svc.Create(ctx, "git-prod", "github", secret.Secret("tok-1")))
	info := ok(t)(svc.Rotate(ctx, "git-prod", secret.Secret("tok-2")))
	if info.Epoch != 2 {
		t.Fatalf("epoch = %d", info.Epoch)
	}
	if _, err := svc.Open(ctx, "git-prod", 1); !errors.Is(err, credential.ErrEpochMismatch) {
		t.Errorf("old epoch: %v", err)
	}
	s, err := svc.Open(ctx, "git-prod", 2)
	if err != nil || string(s.Bytes()) != "tok-2" {
		t.Fatalf("new epoch: %v", err)
	}
}

func TestDisableEnableDoesNotReviveOldEpoch(t *testing.T) {
	svc := testenv.New(t).Credentials
	ok(t)(svc.Create(ctx, "db-prod", "postgres", secret.Secret("pw")))
	ok(t)(svc.Apply(ctx, "db-prod", credential.ActionDisable))
	if _, err := svc.Open(ctx, "db-prod", 2); !errors.Is(err, credential.ErrInactive) {
		t.Errorf("disabled: %v", err)
	}
	info := ok(t)(svc.Apply(ctx, "db-prod", credential.ActionEnable))
	if info.Status != credential.StatusActive || info.Epoch != 3 {
		t.Fatalf("unexpected %+v", info)
	}
	if _, err := svc.Open(ctx, "db-prod", 1); !errors.Is(err, credential.ErrEpochMismatch) {
		t.Errorf("old ticket revived: %v", err)
	}
	if _, err := svc.Open(ctx, "db-prod", 3); err != nil {
		t.Errorf("current epoch: %v", err)
	}
}

func TestTransitions(t *testing.T) {
	svc := testenv.New(t).Credentials
	ok(t)(svc.Create(ctx, "c", "p", secret.Secret("s")))

	if _, err := svc.Apply(ctx, "c", credential.ActionEnable); !errors.Is(err, credential.ErrInvalidTransition) {
		t.Errorf("enable active: %v", err)
	}
	ok(t)(svc.Apply(ctx, "c", credential.ActionCompromise))
	info := ok(t)(svc.Rotate(ctx, "c", secret.Secret("s2")))
	if info.Status != credential.StatusActive {
		t.Errorf("rotate after compromise should recover, got %s", info.Status)
	}
	ok(t)(svc.Apply(ctx, "c", credential.ActionRevoke))
	for _, a := range []credential.Action{credential.ActionEnable, credential.ActionDisable, credential.ActionCompromise} {
		if _, err := svc.Apply(ctx, "c", a); !errors.Is(err, credential.ErrInvalidTransition) {
			t.Errorf("%s from REVOKED: %v", a, err)
		}
	}
	if _, err := svc.Rotate(ctx, "c", secret.Secret("s3")); !errors.Is(err, credential.ErrInvalidTransition) {
		t.Errorf("rotate revoked: %v", err)
	}
	info = ok(t)(svc.Apply(ctx, "c", credential.ActionDestroy))
	if info.Status != credential.StatusDestroyed || info.Epoch != 5 {
		t.Fatalf("destroy: %+v", info)
	}
	if _, err := svc.Apply(ctx, "c", credential.ActionDestroy); !errors.Is(err, credential.ErrInvalidTransition) {
		t.Errorf("destroy twice: %v", err)
	}

	info = ok(t)(svc.Create(ctx, "c", "p", secret.Secret("fresh")))
	if info.Epoch != 6 {
		t.Fatalf("recreate must continue epoch, got %d", info.Epoch)
	}
}

func TestLifecycleIsAudited(t *testing.T) {
	env := testenv.New(t)
	svc := env.Credentials
	ok(t)(svc.Create(ctx, "c", "p", secret.Secret("plaintext-marker")))
	ok(t)(svc.Rotate(ctx, "c", secret.Secret("plaintext-marker-2")))
	ok(t)(svc.Apply(ctx, "c", credential.ActionRevoke))

	rs, err := env.Auditor.Records(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 3 {
		t.Fatalf("audit entries = %d", len(rs))
	}
	for _, r := range rs {
		if strings.Contains(r.Entry, "plaintext-marker") {
			t.Fatalf("audit leaked secret: %s", r.Entry)
		}
	}
	cps, _ := env.Auditor.Checkpoints(ctx)
	if err := evidence.VerifyChain(rs, cps, env.CheckpointSigner.PublicKey()); err != nil {
		t.Fatal(err)
	}
}
