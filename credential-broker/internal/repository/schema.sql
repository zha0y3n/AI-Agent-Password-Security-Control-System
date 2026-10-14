-- 长期业务凭据：仅保存 SM4-GCM 密文，明文永不落库。
CREATE TABLE IF NOT EXISTS credentials (
    id          TEXT PRIMARY KEY,
    provider    TEXT    NOT NULL,
    status      TEXT    NOT NULL,
    epoch       INTEGER NOT NULL,
    nonce       BLOB,
    ciphertext  BLOB,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- Capability 消费状态：ISSUED -> CONSUMING -> CONSUMED / FAILED。
-- request_hash + result 同时作为幂等记录（idempotency_key = cap_id）。
CREATE TABLE IF NOT EXISTS capabilities (
    cap_id            TEXT PRIMARY KEY,
    state             TEXT    NOT NULL,
    request_hash      TEXT    NOT NULL,
    credential_id     TEXT    NOT NULL,
    credential_epoch  INTEGER NOT NULL,
    result            BLOB,
    error_code        TEXT,
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL
);

-- Broker Challenge：单次使用，带过期时间，绑定 agent 与 audience（本 Broker 的 broker_id）。
CREATE TABLE IF NOT EXISTS challenges (
    challenge   TEXT PRIMARY KEY,
    agent_id    TEXT    NOT NULL,
    audience    TEXT    NOT NULL DEFAULT '',
    expires_at  INTEGER NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_expires ON challenges(expires_at);

-- 审计哈希链：hash = SM3(prev_hash || entry)。
CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    entry      BLOB NOT NULL,
    prev_hash  BLOB NOT NULL,
    hash       BLOB NOT NULL
);

-- Broker 对审计链头的 SM2 签名检查点。
CREATE TABLE IF NOT EXISTS checkpoints (
    seq        INTEGER PRIMARY KEY,
    head_hash  BLOB    NOT NULL,
    created_at INTEGER NOT NULL,
    signature  BLOB    NOT NULL
);
