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
