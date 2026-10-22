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
	// 旧库补列：默认值为空串，旧 Challenge 因 audience 不匹配而无法消费（fail closed）。
	if err := db.ensureColumn(ctx, "challenges", "audience", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	// Capability nonce 全局唯一（空串为旧记录 / 内部测试，不参与约束）。
	if err := db.ensureColumn(ctx, "capabilities", "nonce", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_capabilities_nonce ON capabilities(nonce) WHERE nonce <> ''`); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// ensureColumn 在列不存在时追加列。table / column / ddl 均为代码内常量。
func (db *DB) ensureColumn(ctx context.Context, table, column, ddl string) error {
	rows, err := db.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN "+column+" "+ddl); err != nil {
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

// resetTables 是 Reset 清空的表，顺序无依赖关系。
var resetTables = []string{"capabilities", "challenges", "credentials", "audit_log", "checkpoints"}

// Reset 在单个事务中清空全部业务表（Credential、Capability、Challenge、审计链与检查点）。
// 仅用于开发 / 实验环境让每轮实验从干净状态开始；生产环境不得开放。
func (db *DB) Reset(ctx context.Context) error {
	return db.WithTx(ctx, func(tx *sql.Tx) error {
		for _, t := range resetTables {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+t); err != nil {
				return fmt.Errorf("reset %s: %w", t, err)
			}
		}
		return nil
	})
}
