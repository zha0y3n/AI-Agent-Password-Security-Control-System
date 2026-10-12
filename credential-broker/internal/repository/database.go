// Package repository 管理 Broker 的 SQLite 存储与事务。
package repository

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

//go:embed schema.sql
var schemaSQL string

// DB 包装 *sql.DB。
//
// 所有事务以 BEGIN IMMEDIATE 开启：事务开始即获取写锁，
// 使 Consume / Revoke / Rotate 等状态变更严格串行化，
// 这正是撤销竞态的线性化点。
type DB struct {
	*sql.DB
}

// Open 打开（必要时创建）SQLite 数据库并执行迁移。
func Open(path string) (*DB, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db := &DB{DB: sqlDB}
	if err := db.Migrate(context.Background()); err != nil {
		sqlDB.Close()
		return nil, err
	}
	// 库中虽只有密文，仍限制为仅属主可读写。
	_ = os.Chmod(path, 0o600)
	return db, nil
}

// Migrate 执行建表语句，可重复执行。
func (db *DB) Migrate(ctx context.Context) error {
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// WithTx 在单个事务中执行 fn；fn 返回错误或 panic 时回滚。
func (db *DB) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
		if err != nil {
			tx.Rollback()
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}
