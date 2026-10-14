// Package capability 实现 Capability 的原子消费（Atomic Consume）、重放防护与幂等。
//
// 状态机：ISSUED -> CONSUMING -> CONSUMED
//
//	\-> FAILED
//
// 消费在单个 BEGIN IMMEDIATE 事务内完成“Credential 状态 / Epoch 检查 + CAS”，
// 与 Revoke / Rotate 的 epoch++ 由 SQLite 写锁串行化，保证：
//
//	SideEffectCount(Capability) <= 1
//
// 注意：本包只处理已通过签名与绑定校验的 Capability（由 verifier 流水线保证），
// 未经验证的 cap_id 不应进入这里。
package capability

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
)

// State 是 Capability 消费状态。
type State string

const (
	StateIssued    State = "ISSUED"
	StateConsuming State = "CONSUMING"
	StateConsumed  State = "CONSUMED"
	StateFailed    State = "FAILED"
)

var (
	// ErrRequestMismatch：同一 cap_id 携带了不同的 request_hash（幂等冲突）。
	ErrRequestMismatch = errors.New("capability already bound to a different request")
	// ErrClaimMismatch：同一 cap_id 携带了不同的 credential_id / epoch。
	ErrClaimMismatch = errors.New("capability claim does not match recorded claim")
	// ErrInProgress：另一请求已赢得消费权且尚未完成（并发重放）。
	ErrInProgress = errors.New("capability is being consumed")
	// ErrAlreadyFailed：该 Capability 之前的执行已失败，不可再次使用。
	ErrAlreadyFailed = errors.New("capability execution previously failed")
	// ErrNotConsuming：完成 / 失败时 Capability 不处于 CONSUMING。
	ErrNotConsuming = errors.New("capability is not in CONSUMING state")
)

// Claim 是从已验证 Capability 中提取的消费信息。
type Claim struct {
	CapID           string
	RequestHash     string
	CredentialID    string
	CredentialEpoch int64
}

// Outcome 区分“本次赢得执行权”与“幂等重放返回旧结果”。
type Outcome int

const (
	// Won：本请求赢得唯一执行权，可以读取 Credential 并调用上游。
	Won Outcome = iota + 1
	// Replayed：同一 cap_id + 同一 request_hash 已执行完成，返回已保存的结果，不产生新副作用。
	Replayed
)

// Result 是 Consume 的结果。
type Result struct {
	Outcome Outcome
	Stored  []byte // Outcome == Replayed 时为之前保存的结果
}

// Store 管理 Capability 状态。
type Store struct {
	db    *repository.DB
	audit *evidence.Auditor
	now   func() time.Time
}

// NewStore 创建 Store。
func NewStore(db *repository.DB, a *evidence.Auditor) *Store {
	return &Store{db: db, audit: a, now: time.Now}
}

// Consume 尝试原子地获取 Capability 的唯一执行权。
// 返回错误时事务回滚，数据库中不留下任何状态。
func (s *Store) Consume(ctx context.Context, c Claim) (*Result, error) {
	var res *Result
	err := s.db.WithTx(ctx, func(tx *sql.Tx) error {
		now := s.now().Unix()
		if _, err := tx.ExecContext(ctx, `
			INSERT OR IGNORE INTO capabilities(cap_id, state, request_hash, credential_id, credential_epoch, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			c.CapID, StateIssued, c.RequestHash, c.CredentialID, c.CredentialEpoch, now, now); err != nil {
			return err
		}

		var rec Claim
		var state State
		var stored []byte
		if err := tx.QueryRowContext(ctx, `
			SELECT state, request_hash, credential_id, credential_epoch, result FROM capabilities WHERE cap_id = ?`, c.CapID).
			Scan(&state, &rec.RequestHash, &rec.CredentialID, &rec.CredentialEpoch, &stored); err != nil {
			return err
		}
		if rec.CredentialID != c.CredentialID || rec.CredentialEpoch != c.CredentialEpoch {
			return ErrClaimMismatch
		}
		if rec.RequestHash != c.RequestHash {
			return ErrRequestMismatch
		}

		switch state {
		case StateConsumed:
			res = &Result{Outcome: Replayed, Stored: stored}
			return nil
		case StateConsuming:
			return ErrInProgress
		case StateFailed:
			return ErrAlreadyFailed
		}

		// 线性化点：Credential 状态 / Epoch 检查与 CAS 处于同一写事务。
		if err := credential.CheckUsable(ctx, tx, c.CredentialID, c.CredentialEpoch); err != nil {
			return err
		}
		r, err := tx.ExecContext(ctx,
			`UPDATE capabilities SET state = ?, updated_at = ? WHERE cap_id = ? AND state = ?`,
			StateConsuming, now, c.CapID, StateIssued)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n != 1 {
			return ErrInProgress
		}
		if _, err := s.audit.Append(ctx, tx, "capability.consume", map[string]any{
			"cap_id": c.CapID, "request_hash": c.RequestHash,
			"credential_id": c.CredentialID, "credential_epoch": c.CredentialEpoch,
		}); err != nil {
			return err
		}
		res = &Result{Outcome: Won}
		return nil
	})
	return res, err
}

// Complete 记录执行结果：CONSUMING -> CONSUMED。结果用于后续幂等重放。
func (s *Store) Complete(ctx context.Context, capID string, result []byte) error {
	return s.finish(ctx, capID, StateConsumed, result, "", "capability.complete", map[string]any{
		"cap_id": capID, "result_hash": crypto.SM3Hex(result),
	})
}

// Fail 记录执行失败：CONSUMING -> FAILED。
func (s *Store) Fail(ctx context.Context, capID, errorCode string) error {
	return s.finish(ctx, capID, StateFailed, nil, errorCode, "capability.fail", map[string]any{
		"cap_id": capID, "error_code": errorCode,
	})
}

func (s *Store) finish(ctx context.Context, capID string, to State, result []byte, code, event string, data map[string]any) error {
	return s.db.WithTx(ctx, func(tx *sql.Tx) error {
		var errCode any
		if code != "" {
			errCode = code
		}
		r, err := tx.ExecContext(ctx,
			`UPDATE capabilities SET state = ?, result = ?, error_code = ?, updated_at = ? WHERE cap_id = ? AND state = ?`,
			to, result, errCode, s.now().Unix(), capID, StateConsuming)
		if err != nil {
			return err
		}
		if n, _ := r.RowsAffected(); n != 1 {
			return ErrNotConsuming
		}
		_, err = s.audit.Append(ctx, tx, event, data)
		return err
	})
}

// State 返回 Capability 当前状态（不存在时返回 sql.ErrNoRows）。
func (s *Store) State(ctx context.Context, capID string) (State, error) {
	var st State
	err := s.db.QueryRowContext(ctx, `SELECT state FROM capabilities WHERE cap_id = ?`, capID).Scan(&st)
	return st, err
}

// Info 是 Capability 消费记录的元数据，供管理接口与实验查询（不含执行结果）。
type Info struct {
	CapID           string `json:"capability_id"`
	State           State  `json:"state"`
	RequestHash     string `json:"request_hash"`
	CredentialID    string `json:"credential_id"`
	CredentialEpoch int64  `json:"credential_epoch"`
	ErrorCode       string `json:"error_code,omitempty"`
	CreatedAt       int64  `json:"created_at"`
	UpdatedAt       int64  `json:"updated_at"`
}

// Get 返回 Capability 消费记录（不存在时返回 sql.ErrNoRows）。
func (s *Store) Get(ctx context.Context, capID string) (*Info, error) {
	var in Info
	var code sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT cap_id, state, request_hash, credential_id, credential_epoch, error_code, created_at, updated_at
		FROM capabilities WHERE cap_id = ?`, capID).
		Scan(&in.CapID, &in.State, &in.RequestHash, &in.CredentialID, &in.CredentialEpoch, &code, &in.CreatedAt, &in.UpdatedAt)
	if err != nil {
		return nil, err
	}
	in.ErrorCode = code.String
	return &in, nil
}
