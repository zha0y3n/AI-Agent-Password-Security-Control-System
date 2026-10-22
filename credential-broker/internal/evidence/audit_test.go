package evidence

import (
	"context"
	"database/sql"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/canonical"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
)

func newAuditor(t *testing.T, every int) *Auditor {
	t.Helper()
	db, err := repository.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	signer, err := crypto.GenerateSM2Signer()
	if err != nil {
		t.Fatal(err)
	}
	return NewAuditor(db, signer, every)
}

func appendN(t *testing.T, a *Auditor, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		err := a.db.WithTx(ctx, func(tx *sql.Tx) error {
			_, err := a.Append(ctx, tx, "test.event", map[string]any{"i": i, "b": "x", "a": "y"})
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func load(t *testing.T, a *Auditor) ([]Record, []Checkpoint) {
	t.Helper()
	rs, err := a.Records(context.Background(), 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	cps, err := a.Checkpoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return rs, cps
}

func TestChainVerifies(t *testing.T) {
	a := newAuditor(t, 4)
	appendN(t, a, 10)
	rs, cps := load(t, a)
	if len(rs) != 10 || len(cps) != 2 {
		t.Fatalf("got %d records, %d checkpoints", len(rs), len(cps))
	}
	if err := VerifyChain(rs, cps, a.signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	cp, err := a.CreateCheckpoint(context.Background())
	if err != nil || cp.Seq != 10 {
		t.Fatalf("manual checkpoint: %+v %v", cp, err)
	}
	again, _ := a.CreateCheckpoint(context.Background())
	if again.Signature != cp.Signature {
		t.Error("checkpoint at same seq should be reused")
	}
	rs, cps = load(t, a)
	if err := VerifyChain(rs, cps, a.signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
}

func TestChainTamperDetection(t *testing.T) {
	a := newAuditor(t, 4)
	appendN(t, a, 10)
	pub := a.signer.PublicKey()

	cases := map[string]func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint){
		"modify middle entry": func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint) {
			rs[4].Entry = strings.Replace(rs[4].Entry, `"b":"x"`, `"b":"z"`, 1)
			return rs, cps
		},
		"modify entry and recompute its hash": func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint) {
			rs[4].Entry = strings.Replace(rs[4].Entry, `"b":"x"`, `"b":"z"`, 1)
			prev, _ := hex.DecodeString(rs[4].PrevHash)
			rs[4].Hash = hex.EncodeToString(crypto.SM3Concat(prev, []byte(rs[4].Entry)))
			return rs, cps
		},
		"delete middle entry": func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint) {
			return append(rs[:4:4], rs[5:]...), cps
		},
		"rollback tail past checkpoint": func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint) {
			return rs[:6], cps
		},
		"modify checkpoint head": func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint) {
			cps[0].HeadHash = rs[2].Hash
			return rs, cps
		},
		"modify checkpoint seq": func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint) {
			cps[0].Seq = 3
			return rs, cps
		},
		"forged checkpoint signature": func(rs []Record, cps []Checkpoint) ([]Record, []Checkpoint) {
			other, _ := crypto.GenerateSM2Signer()
			head, _ := hex.DecodeString(cps[0].HeadHash)
			sig, _ := other.Sign(CheckpointMessage(cps[0].Seq, head, cps[0].CreatedAt))
			cps[0].Signature = hex.EncodeToString(sig)
			return rs, cps
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rs, cps := load(t, a)
			rs, cps = mutate(rs, cps)
			if err := VerifyChain(rs, cps, pub); err == nil {
				t.Fatal("tampering not detected")
			} else {
				t.Log(err)
			}
		})
	}
}

type testStatus string

func TestEntriesAreCanonical(t *testing.T) {
	a := newAuditor(t, 0)
	err := a.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		_, err := a.Append(context.Background(), tx, "test.event", map[string]any{
			"status": testStatus("ACTIVE"), "epoch": int64(17), "note": "<&>", "list": []string{"b", "a"},
		})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := load(t, a)
	v, err := canonical.Parse([]byte(rs[0].Entry))
	if err != nil {
		t.Fatalf("entry is not ZTCANON-JSON-v1: %v", err)
	}
	again, err := canonical.Marshal(v)
	if err != nil || string(again) != rs[0].Entry {
		t.Fatalf("entry is not in canonical form:\n%s\n%s", rs[0].Entry, again)
	}
	if !strings.HasPrefix(rs[0].Entry, `{"at":`) ||
		!strings.HasSuffix(rs[0].Entry, `,"data":{"epoch":17,"list":["b","a"],"note":"<&>","status":"ACTIVE"},"seq":1,"type":"test.event"}`) {
		t.Fatalf("unexpected entry %s", rs[0].Entry)
	}
}

func TestEntryRejectsNonCanonicalData(t *testing.T) {
	a := newAuditor(t, 0)
	err := a.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		_, err := a.Append(context.Background(), tx, "test.event", map[string]any{"ratio": 1.5})
		return err
	})
	if err == nil {
		t.Fatal("float audit data must be rejected")
	}
	if rs, _ := load(t, a); len(rs) != 0 {
		t.Fatal("rejected entry must not be written")
	}
}

// 升级前用 encoding/json 写入的条目：哈希覆盖原始字节，仍然可以复核。
func TestLegacyEntriesStillVerify(t *testing.T) {
	a := newAuditor(t, 0)
	appendN(t, a, 2)
	legacy := `{"seq":3,"at":1791797696,"type":"credential.rotate","data":{"credential_id":"github-prod"}}`
	err := a.db.WithTx(context.Background(), func(tx *sql.Tx) error {
		var prev []byte
		if err := tx.QueryRow(`SELECT hash FROM audit_log WHERE seq = 2`).Scan(&prev); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO audit_log(seq, entry, prev_hash, hash) VALUES (3, ?, ?, ?)`,
			[]byte(legacy), prev, crypto.SM3Concat(prev, []byte(legacy)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, a, 1)
	rs, cps := load(t, a)
	if err := VerifyChain(rs, cps, a.signer.PublicKey()); err != nil {
		t.Fatalf("mixed legacy/canonical chain: %v", err)
	}
}
