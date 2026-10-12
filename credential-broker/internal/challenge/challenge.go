// Package challenge 实现 Broker Challenge：Holder Proof 需绑定的一次性随机数。
// 字段名、长度与编码在阶段二按 A 的 docs/crypto-protocol.md 调整。
package challenge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
)

// Size 是 Challenge 随机字节数。
const Size = 32

var (
	ErrUnknown    = errors.New("unknown challenge")
	ErrUsed       = errors.New("challenge already used")
	ErrExpired    = errors.New("challenge expired")
	ErrWrongAgent = errors.New("challenge issued to a different agent")
	ErrBadAgent   = errors.New("agent_id is required")
)

// Challenge 是下发给 Agent 的挑战。
type Challenge struct {
	Challenge string `json:"challenge"`
	AgentID   string `json:"agent_id"`
	ExpiresAt int64  `json:"expires_at"`
}

// Service 生成并消费 Challenge。
type Service struct {
	db  *repository.DB
	ttl time.Duration
	now func() time.Time
}

// NewService 创建 Service。
func NewService(db *repository.DB, ttl time.Duration) *Service {
	return &Service{db: db, ttl: ttl, now: time.Now}
}

// Issue 为 agentID 生成一个 CSPRNG Challenge（base64url，无填充）。
func (s *Service) Issue(ctx context.Context, agentID string) (*Challenge, error) {
	if agentID == "" || len(agentID) > 128 {
		return nil, ErrBadAgent
	}
	raw := make([]byte, Size)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	now := s.now()
	c := &Challenge{
		Challenge: base64.RawURLEncoding.EncodeToString(raw),
		AgentID:   agentID,
		ExpiresAt: now.Add(s.ttl).Unix(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges(challenge, agent_id, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)`,
		c.Challenge, c.AgentID, c.ExpiresAt, now.Unix())
	return c, err
}

// Consume 原子地消费 Challenge：必须存在、属于 agentID、未过期、未使用。
// 若传入 tx 则在调用方事务内执行（阶段二与 Capability 消费合并），否则单独开事务。
func (s *Service) Consume(ctx context.Context, tx *sql.Tx, challenge, agentID string) error {
	if tx == nil {
		return s.db.WithTx(ctx, func(tx *sql.Tx) error { return s.consume(ctx, tx, challenge, agentID) })
	}
	return s.consume(ctx, tx, challenge, agentID)
}

func (s *Service) consume(ctx context.Context, tx *sql.Tx, challenge, agentID string) error {
	now := s.now().Unix()
	r, err := tx.ExecContext(ctx,
		`UPDATE challenges SET used = 1 WHERE challenge = ? AND agent_id = ? AND used = 0 AND expires_at > ?`,
		challenge, agentID, now)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 1 {
		return nil
	}
	// 失败时区分原因，便于返回明确的拒绝码。
	var owner string
	var used int
	var expiresAt int64
	err = tx.QueryRowContext(ctx, `SELECT agent_id, used, expires_at FROM challenges WHERE challenge = ?`, challenge).
		Scan(&owner, &used, &expiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrUnknown
	case err != nil:
		return err
	case owner != agentID:
		return ErrWrongAgent
	case used != 0:
		return ErrUsed
	default:
		return ErrExpired
	}
}

// Purge 删除过期超过 grace 的 Challenge，返回删除数量。
func (s *Service) Purge(ctx context.Context, grace time.Duration) (int64, error) {
	r, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE expires_at < ?`, s.now().Add(-grace).Unix())
	if err != nil {
		return 0, err
	}
	return r.RowsAffected()
}
