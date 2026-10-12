// Package credential 管理长期 Credential 的生命周期与 Epoch。
//
// 任何状态变更（含 Rotate）都会使 epoch++，
// 签发时绑定旧 Epoch 的 Capability 随即失效，且不会因 Re-enable 而复活。
package credential

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/vault"
)

// Status 是 Credential 状态。
type Status string

const (
	StatusActive      Status = "ACTIVE"
	StatusDisabled    Status = "DISABLED"
	StatusRevoked     Status = "REVOKED"
	StatusCompromised Status = "COMPROMISED"
	StatusDestroyed   Status = "DESTROYED"
)

// Action 是生命周期操作。
type Action string

const (
	ActionDisable    Action = "disable"
	ActionEnable     Action = "enable"
	ActionRevoke     Action = "revoke"
	ActionCompromise Action = "compromise"
	ActionDestroy    Action = "destroy"
)

var (
	ErrNotFound          = errors.New("credential not found")
	ErrExists            = errors.New("credential already exists")
	ErrInvalidTransition = errors.New("invalid credential state transition")
	ErrInactive          = errors.New("credential is not active")
	ErrEpochMismatch     = errors.New("credential epoch mismatch")
	ErrInvalidInput      = errors.New("invalid credential input")
)

// transitions 定义除 Create / Rotate 外的状态迁移：action -> (允许的源状态, 目标状态)。
var transitions = map[Action]struct {
	from []Status
	to   Status
}{
	ActionDisable:    {[]Status{StatusActive}, StatusDisabled},
	ActionEnable:     {[]Status{StatusDisabled}, StatusActive},
	ActionRevoke:     {[]Status{StatusActive, StatusDisabled, StatusCompromised}, StatusRevoked},
	ActionCompromise: {[]Status{StatusActive, StatusDisabled}, StatusCompromised},
	ActionDestroy:    {[]Status{StatusActive, StatusDisabled, StatusRevoked, StatusCompromised}, StatusDestroyed},
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Info 是对外可见的 Credential 元数据，不含任何密文或明文。
type Info struct {
	ID        string `json:"credential_id"`
	Provider  string `json:"provider"`
	Status    Status `json:"status"`
	Epoch     int64  `json:"credential_epoch"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// Service 实现 Credential 生命周期。
type Service struct {
	db    *repository.DB
	vault *vault.Vault
	audit *evidence.Auditor
	now   func() time.Time
}

// NewService 创建 Service。
func NewService(db *repository.DB, v *vault.Vault, a *evidence.Auditor) *Service {
	return &Service{db: db, vault: v, audit: a, now: time.Now}
}

type row struct {
	Info
	nonce, ciphertext []byte
}

func getRow(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, id string) (*row, error) {
	var r row
	err := q.QueryRowContext(ctx,
		`SELECT id, provider, status, epoch, nonce, ciphertext, created_at, updated_at FROM credentials WHERE id = ?`, id).
		Scan(&r.ID, &r.Provider, &r.Status, &r.Epoch, &r.nonce, &r.ciphertext, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &r, err
}

// Create 录入新 Credential，状态 ACTIVE。
// 对已 DESTROYED 的 ID 重新创建时，epoch 在原值基础上继续递增，旧票据永不复活。
func (s *Service) Create(ctx context.Context, id, provider string, sec secret.Secret) (*Info, error) {
	if !idPattern.MatchString(id) || !idPattern.MatchString(provider) || len(sec) == 0 {
		return nil, ErrInvalidInput
	}
	var info *Info
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		now := s.now().Unix()
		existing, err := getRow(ctx, tx, id)
		switch {
		case err == nil && existing.Status != StatusDestroyed:
			return ErrExists
		case err != nil && !errors.Is(err, ErrNotFound):
			return err
		}
		epoch, createdAt := int64(1), now
		if existing != nil {
			epoch, createdAt = existing.Epoch+1, existing.CreatedAt
		}
		nonce, ct, err := s.vault.Seal(id, provider, epoch, sec)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO credentials(id, provider, status, epoch, nonce, ciphertext, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET provider=excluded.provider, status=excluded.status, epoch=excluded.epoch,
				nonce=excluded.nonce, ciphertext=excluded.ciphertext, updated_at=excluded.updated_at`,
			id, provider, StatusActive, epoch, nonce, ct, createdAt, now); err != nil {
			return err
		}
		info = &Info{ID: id, Provider: provider, Status: StatusActive, Epoch: epoch, CreatedAt: createdAt, UpdatedAt: now}
		_, err = s.audit.Append(ctx, tx, "credential.create", map[string]any{
			"credential_id": id, "provider": provider, "status": string(StatusActive), "credential_epoch": epoch,
		})
		return err
	})
	return info, err
}

// Rotate 用新明文替换 Credential，epoch++。
// COMPROMISED 状态下轮换视为恢复，状态回到 ACTIVE；其余状态保持不变。
func (s *Service) Rotate(ctx context.Context, id string, sec secret.Secret) (*Info, error) {
	if len(sec) == 0 {
		return nil, ErrInvalidInput
	}
	var info *Info
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		r, err := getRow(ctx, tx, id)
		if err != nil {
			return err
		}
		to := r.Status
		switch r.Status {
		case StatusActive, StatusDisabled:
		case StatusCompromised:
			to = StatusActive
		default:
			return fmt.Errorf("%w: rotate from %s", ErrInvalidTransition, r.Status)
		}
		epoch := r.Epoch + 1
		nonce, ct, err := s.vault.Seal(id, r.Provider, epoch, sec)
		if err != nil {
			return err
		}
		info, err = s.update(ctx, tx, r, "rotate", to, epoch, nonce, ct)
		return err
	})
	return info, err
}

// Apply 执行 disable / enable / revoke / compromise / destroy，epoch++。
func (s *Service) Apply(ctx context.Context, id string, action Action) (*Info, error) {
	t, ok := transitions[action]
	if !ok {
		return nil, fmt.Errorf("%w: unknown action %q", ErrInvalidTransition, action)
	}
	var info *Info
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		r, err := getRow(ctx, tx, id)
		if err != nil {
			return err
		}
		allowed := false
		for _, f := range t.from {
			allowed = allowed || f == r.Status
		}
		if !allowed {
			return fmt.Errorf("%w: %s from %s", ErrInvalidTransition, action, r.Status)
		}
		epoch := r.Epoch + 1
		var nonce, ct []byte
		if t.to != StatusDestroyed {
			// AAD 绑定 epoch，epoch 变化后必须重新加密。
			if nonce, ct, err = s.reseal(r, epoch); err != nil {
				return err
			}
		}
		info, err = s.update(ctx, tx, r, string(action), t.to, epoch, nonce, ct)
		return err
	})
	return info, err
}

// reseal 将密文从当前 epoch 的 AAD 迁移到 newEpoch 的 AAD，明文用后立即清零。
func (s *Service) reseal(r *row, newEpoch int64) (nonce, ct []byte, err error) {
	plain, err := s.vault.Open(r.ID, r.Provider, r.Epoch, r.nonce, r.ciphertext)
	if err != nil {
		return nil, nil, err
	}
	defer plain.Wipe()
	return s.vault.Seal(r.ID, r.Provider, newEpoch, plain)
}

func (s *Service) update(ctx context.Context, tx *sql.Tx, r *row, action string, to Status, epoch int64, nonce, ct []byte) (*Info, error) {
	now := s.now().Unix()
	if _, err := tx.ExecContext(ctx,
		`UPDATE credentials SET status = ?, epoch = ?, nonce = ?, ciphertext = ?, updated_at = ? WHERE id = ?`,
		to, epoch, nonce, ct, now, r.ID); err != nil {
		return nil, err
	}
	if _, err := s.audit.Append(ctx, tx, "credential."+action, map[string]any{
		"credential_id": r.ID, "from_status": string(r.Status), "to_status": string(to),
		"from_epoch": r.Epoch, "credential_epoch": epoch,
	}); err != nil {
		return nil, err
	}
	return &Info{ID: r.ID, Provider: r.Provider, Status: to, Epoch: epoch, CreatedAt: r.CreatedAt, UpdatedAt: now}, nil
}

// Ping 检查数据库可用（健康检查用）。
func (s *Service) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

// Get 返回 Credential 元数据。
func (s *Service) Get(ctx context.Context, id string) (*Info, error) {
	r, err := getRow(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	return &r.Info, nil
}

// CheckUsable 在调用方事务内确认 Credential 为 ACTIVE 且 epoch 与 Capability 一致。
// 与 Atomic Consume 同事务执行，构成撤销竞态的线性化点。
func CheckUsable(ctx context.Context, tx *sql.Tx, id string, epoch int64) error {
	r, err := getRow(ctx, tx, id)
	if err != nil {
		return err
	}
	if r.Status != StatusActive {
		return ErrInactive
	}
	if r.Epoch != epoch {
		return ErrEpochMismatch
	}
	return nil
}

// Open 解密 Credential 供上游调用使用。仅在 Atomic Consume 成功之后调用。
// 若消费后 Credential 被轮换或撤销，状态 / epoch 检查或 AAD 校验会使解密失败。
func (s *Service) Open(ctx context.Context, id string, epoch int64) (secret.Secret, error) {
	r, err := getRow(ctx, s.db, id)
	if err != nil {
		return nil, err
	}
	if r.Status != StatusActive {
		return nil, ErrInactive
	}
	if r.Epoch != epoch {
		return nil, ErrEpochMismatch
	}
	return s.vault.Open(id, r.Provider, epoch, r.nonce, r.ciphertext)
}
