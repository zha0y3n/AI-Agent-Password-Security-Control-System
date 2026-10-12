// Package evidence 实现 Broker 侧的可验证证据：审计哈希链与签名检查点。
// 字节格式说明见 docs/audit-chain.md，供 C 独立验证。
package evidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
)

// CheckpointDomain 是检查点签名消息的域分隔前缀。
const CheckpointDomain = "ACG-AUDIT-CHECKPOINT-v1"

// GenesisHash 是链首条目的 prev_hash（32 个零字节）。
var GenesisHash = make([]byte, crypto.SM3Size)

// entryBody 是审计条目 L_i 的结构。字段顺序固定，data 为 map 时键按字典序输出。
// TODO(阶段二): 改用与 A 一致的 Canonical JSON 实现。
type entryBody struct {
	Seq  int64          `json:"seq"`
	At   int64          `json:"at"`
	Type string         `json:"type"`
	Data map[string]any `json:"data"`
}

// Record 是导出的审计条目。Entry 为 L_i 的原始字节（JSON 文本）。
type Record struct {
	Seq      int64  `json:"seq"`
	Entry    string `json:"entry"`
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Checkpoint 是导出的签名检查点。
type Checkpoint struct {
	Seq       int64  `json:"seq"`
	HeadHash  string `json:"head_hash"`
	CreatedAt int64  `json:"created_at"`
	Signature string `json:"signature"`
}

// Auditor 追加审计条目并定期生成签名检查点。
type Auditor struct {
	db              *repository.DB
	signer          *crypto.SM2Signer
	checkpointEvery int64
	now             func() time.Time
}

// NewAuditor 创建 Auditor。checkpointEvery <= 0 时不自动生成检查点。
func NewAuditor(db *repository.DB, signer *crypto.SM2Signer, checkpointEvery int) *Auditor {
	return &Auditor{db: db, signer: signer, checkpointEvery: int64(checkpointEvery), now: time.Now}
}

// Append 在调用方事务中追加一条审计记录，使审计与业务状态变更原子提交。
func (a *Auditor) Append(ctx context.Context, tx *sql.Tx, typ string, data map[string]any) (int64, error) {
	var lastSeq int64
	prev := GenesisHash
	err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&lastSeq, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	seq := lastSeq + 1
	if data == nil {
		data = map[string]any{}
	}
	entry, err := json.Marshal(entryBody{Seq: seq, At: a.now().Unix(), Type: typ, Data: data})
	if err != nil {
		return 0, err
	}
	hash := crypto.SM3Concat(prev, entry)
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO audit_log(seq, entry, prev_hash, hash) VALUES (?, ?, ?, ?)`,
		seq, entry, prev, hash); err != nil {
		return 0, err
	}
	if a.checkpointEvery > 0 && seq%a.checkpointEvery == 0 {
		if _, err := a.writeCheckpoint(ctx, tx, seq, hash); err != nil {
			return 0, err
		}
	}
	return seq, nil
}

// Record 在独立事务中追加一条审计记录（用于拒绝决策等不伴随状态变更的事件）。
func (a *Auditor) Record(ctx context.Context, typ string, data map[string]any) error {
	return a.db.WithTx(ctx, func(tx *sql.Tx) error {
		_, err := a.Append(ctx, tx, typ, data)
		return err
	})
}

// CreateCheckpoint 为当前链头生成检查点（已存在则直接返回）。
func (a *Auditor) CreateCheckpoint(ctx context.Context) (*Checkpoint, error) {
	var cp *Checkpoint
	err := a.db.WithTx(ctx, func(tx *sql.Tx) error {
		var seq int64
		var head []byte
		if err := tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&seq, &head); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return errors.New("audit log is empty")
			}
			return err
		}
		existing, err := scanCheckpoint(tx.QueryRowContext(ctx,
			`SELECT seq, head_hash, created_at, signature FROM checkpoints WHERE seq = ?`, seq))
		if err == nil {
			cp = existing
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		cp, err = a.writeCheckpoint(ctx, tx, seq, head)
		return err
	})
	return cp, err
}

func (a *Auditor) writeCheckpoint(ctx context.Context, tx *sql.Tx, seq int64, head []byte) (*Checkpoint, error) {
	at := a.now().Unix()
	sig, err := a.signer.Sign(CheckpointMessage(seq, head, at))
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO checkpoints(seq, head_hash, created_at, signature) VALUES (?, ?, ?, ?)`,
		seq, head, at, sig); err != nil {
		return nil, err
	}
	return &Checkpoint{Seq: seq, HeadHash: hex.EncodeToString(head), CreatedAt: at, Signature: hex.EncodeToString(sig)}, nil
}

// CheckpointMessage 构造检查点签名消息：
// "ACG-AUDIT-CHECKPOINT-v1" ‖ uint64be(seq) ‖ head_hash(32B) ‖ uint64be(created_at)。
func CheckpointMessage(seq int64, head []byte, createdAt int64) []byte {
	var buf bytes.Buffer
	buf.WriteString(CheckpointDomain)
	binary.Write(&buf, binary.BigEndian, uint64(seq))
	buf.Write(head)
	binary.Write(&buf, binary.BigEndian, uint64(createdAt))
	return buf.Bytes()
}

// Records 返回 seq >= from 的最多 limit 条审计记录。
func (a *Auditor) Records(ctx context.Context, from int64, limit int) ([]Record, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT seq, entry, prev_hash, hash FROM audit_log WHERE seq >= ? ORDER BY seq LIMIT ?`, from, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var entry, prev, hash []byte
		if err := rows.Scan(&r.Seq, &entry, &prev, &hash); err != nil {
			return nil, err
		}
		r.Entry, r.PrevHash, r.Hash = string(entry), hex.EncodeToString(prev), hex.EncodeToString(hash)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Checkpoints 返回全部检查点。
func (a *Auditor) Checkpoints(ctx context.Context) ([]Checkpoint, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT seq, head_hash, created_at, signature FROM checkpoints ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Checkpoint{}
	for rows.Next() {
		cp, err := scanCheckpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *cp)
	}
	return out, rows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanCheckpoint(s scanner) (*Checkpoint, error) {
	var cp Checkpoint
	var head, sig []byte
	if err := s.Scan(&cp.Seq, &head, &cp.CreatedAt, &sig); err != nil {
		return nil, err
	}
	cp.HeadHash, cp.Signature = hex.EncodeToString(head), hex.EncodeToString(sig)
	return &cp, nil
}

// VerifyChain 校验从 seq=1 开始的完整审计链与全部检查点：
//   - 条目 seq 连续，且与条目内嵌 seq 一致（检测删除、重排）
//   - prev_hash 衔接、hash = SM3(prev_hash ‖ entry)（检测篡改）
//   - 检查点签名有效，且其 head_hash 与对应条目一致（检测回滚、截断、检查点篡改）
func VerifyChain(records []Record, checkpoints []Checkpoint, pub *ecdsa.PublicKey) error {
	prev := GenesisHash
	hashes := make([][]byte, len(records))
	for i, r := range records {
		want := int64(i + 1)
		if r.Seq != want {
			return fmt.Errorf("seq %d: expected seq %d (entry missing or reordered)", r.Seq, want)
		}
		var body entryBody
		if err := json.Unmarshal([]byte(r.Entry), &body); err != nil {
			return fmt.Errorf("seq %d: malformed entry: %w", r.Seq, err)
		}
		if body.Seq != r.Seq {
			return fmt.Errorf("seq %d: entry claims seq %d", r.Seq, body.Seq)
		}
		if r.PrevHash != hex.EncodeToString(prev) {
			return fmt.Errorf("seq %d: prev_hash does not link to previous entry", r.Seq)
		}
		h := crypto.SM3Concat(prev, []byte(r.Entry))
		if r.Hash != hex.EncodeToString(h) {
			return fmt.Errorf("seq %d: hash mismatch (entry tampered)", r.Seq)
		}
		hashes[i], prev = h, h
	}
	for _, cp := range checkpoints {
		head, err1 := hex.DecodeString(cp.HeadHash)
		sig, err2 := hex.DecodeString(cp.Signature)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("checkpoint %d: malformed encoding", cp.Seq)
		}
		if !crypto.SM2Verify(pub, CheckpointMessage(cp.Seq, head, cp.CreatedAt), sig) {
			return fmt.Errorf("checkpoint %d: invalid broker signature", cp.Seq)
		}
		if cp.Seq < 1 || cp.Seq > int64(len(records)) {
			return fmt.Errorf("checkpoint %d: log has only %d entries (rollback or truncation)", cp.Seq, len(records))
		}
		if !bytes.Equal(hashes[cp.Seq-1], head) {
			return fmt.Errorf("checkpoint %d: head hash does not match log", cp.Seq)
		}
	}
	return nil
}
