package repository

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestMigrateIsIdempotent(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for i := 0; i < 3; i++ {
		if err := db.Migrate(context.Background()); err != nil {
			t.Fatalf("migrate #%d: %v", i, err)
		}
	}
}

func TestWithTxRollback(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	boom := errors.New("boom")

	err = db.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.Exec(`INSERT INTO challenges(challenge, agent_id, expires_at, created_at) VALUES ('c1','a',1,1)`); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	func() {
		defer func() { recover() }()
		db.WithTx(ctx, func(tx *sql.Tx) error {
			tx.Exec(`INSERT INTO challenges(challenge, agent_id, expires_at, created_at) VALUES ('c2','a',1,1)`)
			panic("crash")
		})
	}()

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM challenges`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("rolled back rows persisted: %d", n)
	}
}

// 旧库的 capabilities 表没有 nonce 列：迁移补列后，多条旧记录的空 nonce 不触发唯一约束，新 nonce 必须唯一。
func TestMigrateAddsCapabilityNonce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE capabilities (cap_id TEXT PRIMARY KEY, state TEXT NOT NULL,
		request_hash TEXT NOT NULL, credential_id TEXT NOT NULL, credential_epoch INTEGER NOT NULL,
		result BLOB, error_code TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
		INSERT INTO capabilities VALUES ('old-1', 'CONSUMED', 'h', 'c', 1, NULL, NULL, 0, 0);
		INSERT INTO capabilities VALUES ('old-2', 'CONSUMED', 'h', 'c', 1, NULL, NULL, 0, 0);`); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	insert := func(id, nonce string) error {
		_, err := db.Exec(`INSERT INTO capabilities(cap_id, state, request_hash, credential_id, credential_epoch, nonce, created_at, updated_at)
			VALUES (?, 'ISSUED', 'h', 'c', 1, ?, 0, 0)`, id, nonce)
		return err
	}
	if err := insert("new-1", "n1"); err != nil {
		t.Fatal(err)
	}
	if err := insert("new-2", "n1"); err == nil {
		t.Fatal("duplicate nonce accepted")
	}
}
