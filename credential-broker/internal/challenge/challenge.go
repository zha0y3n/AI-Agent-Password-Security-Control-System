// Package challenge 实现 Broker Challenge：Holder Proof 需绑定的一次性随机数。
//
// 格式遵循 A 的 HolderProofBody.challenge（^[0-9a-f]{32,64}$）：32 字节 CSPRNG 的小写十六进制。
// 按 docs/crypto-protocol.md §5，每个 Challenge 记录 agent、audience、过期时间与是否已消费。
package challenge

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
)

// Size 是 Challenge 随机字节数。
const Size = 32

var (
	ErrUnknown       = errors.New("unknown challenge")
	ErrUsed          = errors.New("challenge already used")
	ErrExpired       = errors.New("challenge expired")
	ErrWrongAgent    = errors.New("challenge issued to a different agent")
	ErrWrongAudience = errors.New("challenge issued for a different audience")
	ErrBadAgent      = errors.New("agent_id is required")
)

// Challenge 是下发给 Agent 的挑战。
type Challenge struct {
	Challenge string `json:"challenge"`
	AgentID   string `json:"agent_id"`
	Audience  string `json:"audience"`
	ExpiresAt int64  `json:"expires_at"`
}

// Service 生成并消费 Challenge。audience 是本 Broker 的 broker_id。
type Service struct {
	db       *repository.DB
	ttl      time.Duration
	audience string
	now      func() time.Time
}

// NewService 创建 Service。
func NewService(db *repository.DB, ttl time.Duration, audience string) *Service {
	return &Service{db: db, ttl: ttl, audience: audience, now: time.Now}
}

// Issue 为 agentID 生成一个 CSPRNG Challenge（小写十六进制）。
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
		Challenge: hex.EncodeToString(raw),
		AgentID:   agentID,
		Audience:  s.audience,
		ExpiresAt: now.Add(s.ttl).Unix(),
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO challenges(challenge, agent_id, audience, expires_at, used, created_at) VALUES (?, ?, ?, ?, 0, ?)`,
		c.Challenge, c.AgentID, c.Audience, c.ExpiresAt, now.Unix())
	return c, err
}

// Consume 原子地消费 Challenge：必须存在、属于 agentID、audience 为本 Broker、未过期、未使用。
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
		`UPDATE challenges SET used = 1 WHERE challenge = ? AND agent_id = ? AND audience = ? AND used = 0 AND expires_at > ?`,
		challenge, agentID, s.audience, now)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 1 {
		return nil
	}
	// 失败时区分原因，便于返回明确的拒绝码。
	var owner, audience string
	var used int
	var expiresAt int64
	err = tx.QueryRowContext(ctx, `SELECT agent_id, audience, used, expires_at FROM challenges WHERE challenge = ?`, challenge).
		Scan(&owner, &audience, &used, &expiresAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ErrUnknown
	case err != nil:
		return err
	case owner != agentID:
		return ErrWrongAgent
	case audience != s.audience:
		return ErrWrongAudience
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
