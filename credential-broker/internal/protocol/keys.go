package protocol

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"sort"
	"sync/atomic"
	"unicode/utf8"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
)

// 公钥用途（PublicKeyRecord.purpose）。
const (
	KeyPurposeCapability  = "CAPABILITY_SIGNING"
	KeyPurposeHolderProof = "HOLDER_PROOF"
	KeyPurposeReceipt     = "RECEIPT_SIGNING"
)

// KeyRecord 是可信注册表中的一把公钥，对应 agent_aa.models.PublicKeyRecord。
type KeyRecord struct {
	KeyID     string
	SubjectID string
	Purpose   string
	Status    string
	PublicKey *ecdsa.PublicKey
	NotBefore int64
	NotAfter  int64
}

// KeyRegistry 是 Broker 信任的 AA / Agent 公钥集合。
// 只从 Broker 本地配置加载，绝不接受请求中携带的公钥。
type KeyRegistry struct {
	records map[string]*KeyRecord
}

// LoadKeyRegistry 读取 KeyRegistryDocument JSON（与 A 的 public-keys.json 同格式）。
func LoadKeyRegistry(path string) (*KeyRegistry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKeyRegistry(data)
}

// ParseKeyRegistry 严格解析 KeyRegistryDocument；任一记录非法即整体拒绝。
func ParseKeyRegistry(data []byte) (*KeyRegistry, error) {
	reg, perr := parse(data, decodeKeyRegistry)
	if perr != nil {
		return nil, perr
	}
	return reg, nil
}

func decodeKeyRegistry(v any, path string) (*KeyRegistry, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	o.literal("protocol_version", ProtocolVersion)
	raw, ok := o.required("keys")
	list, isList := raw.([]any)
	if ok && !isList {
		o.fail("keys", "must be an array")
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	reg := &KeyRegistry{records: map[string]*KeyRecord{}}
	for i, item := range list {
		rec, err := decodeKeyRecord(item, fmt.Sprintf("%s.keys[%d]", path, i))
		if err != nil {
			return nil, err
		}
		if _, dup := reg.records[rec.KeyID]; dup {
			return nil, Errorf("DUPLICATE_KEY_ID", "duplicate key id: %s", rec.KeyID)
		}
		reg.records[rec.KeyID] = rec
	}
	return reg, nil
}

func decodeKeyRecord(v any, path string) (*KeyRecord, *Error) {
	o, err := newObject(v, path)
	if err != nil {
		return nil, err
	}
	rec := &KeyRecord{
		KeyID:     o.identifier("key_id"),
		SubjectID: o.identifier("subject_id"),
		Purpose:   o.oneOf("purpose", KeyPurposeCapability, KeyPurposeHolderProof, KeyPurposeReceipt),
		NotBefore: o.integer("not_before", 0, maxTimestamp),
		NotAfter:  o.integer("not_after", 0, maxTimestamp),
	}
	o.literal("algorithm", "SM2")
	rec.Status = "ACTIVE"
	if _, present := o.get("status"); present {
		rec.Status = o.oneOf("status", "ACTIVE", "REVOKED")
	}
	pemKey := o.str("public_key_pem")
	if o.err == nil {
		if n := utf8.RuneCountInString(pemKey); n < 100 || n > 2048 {
			o.fail("public_key_pem", "must be 100..2048 characters")
		} else if pub, err := crypto.ParseSM2PublicKeyPEM(pemKey); err != nil {
			o.fail("public_key_pem", "%v", err)
		} else {
			rec.PublicKey = pub
		}
	}
	if o.err == nil && rec.NotAfter <= rec.NotBefore {
		o.fail("not_after", "key not_after must be after not_before")
	}
	if err := o.done(); err != nil {
		return nil, err
	}
	return rec, nil
}

// Lookup 返回可用于验签的公钥。检查顺序与 A 的 KeyRegistry.get_record 一致：
// 存在 → 状态 → 用途 → 主体 → 有效期（at 落在 [not_before, not_after)）。
func (r *KeyRegistry) Lookup(keyID, purpose, subjectID string, at int64) (*ecdsa.PublicKey, *Error) {
	rec, ok := r.records[keyID]
	switch {
	case !ok:
		return nil, Errorf(CodeUnknownKey, "unknown key id: %s", keyID)
	case rec.Status != "ACTIVE":
		return nil, Errorf(CodeKeyRevoked, "key is not active: %s", keyID)
	case rec.Purpose != purpose:
		return nil, Errorf(CodeWrongKeyPurpose, "key %s is not for %s", keyID, purpose)
	case rec.SubjectID != subjectID:
		return nil, Errorf(CodeKeySubjectMismatch, "key is bound to a different subject")
	case at < rec.NotBefore || at >= rec.NotAfter:
		return nil, Errorf(CodeKeyOutsideValidity, "key is outside its validity window")
	}
	return rec.PublicKey, nil
}

// Len 返回注册表中的公钥数量。
func (r *KeyRegistry) Len() int { return len(r.records) }

// Records 返回注册表中全部公钥记录的副本，按 key_id 排序。
func (r *KeyRegistry) Records() []KeyRecord {
	out := make([]KeyRecord, 0, len(r.records))
	for _, rec := range r.records {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].KeyID < out[j].KeyID })
	return out
}

// KeyLookup 是校验流水线查找可信公钥所需的接口，由 *KeyRegistry 与 *ReloadableKeyRegistry 实现。
type KeyLookup interface {
	Lookup(keyID, purpose, subjectID string, at int64) (*ecdsa.PublicKey, *Error)
}

// ReloadableKeyRegistry 从文件加载公钥表，并支持运行时整体替换（例如收到 SIGHUP 时）。
// 替换是原子的：新文件必须整体通过严格解析，否则保留当前公钥表不变。
type ReloadableKeyRegistry struct {
	path string
	cur  atomic.Pointer[KeyRegistry]
}

// LoadReloadableKeyRegistry 首次加载公钥表；失败时返回错误（启动 fail closed）。
func LoadReloadableKeyRegistry(path string) (*ReloadableKeyRegistry, error) {
	r := &ReloadableKeyRegistry{path: path}
	if _, err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload 重新读取文件，成功后替换当前公钥表并返回新表；失败时当前公钥表保持不变。
func (r *ReloadableKeyRegistry) Reload() (*KeyRegistry, error) {
	reg, err := LoadKeyRegistry(r.path)
	if err != nil {
		return nil, err
	}
	r.cur.Store(reg)
	return reg, nil
}

// Lookup 在当前公钥表中查找。
func (r *ReloadableKeyRegistry) Lookup(keyID, purpose, subjectID string, at int64) (*ecdsa.PublicKey, *Error) {
	return r.cur.Load().Lookup(keyID, purpose, subjectID, at)
}

// Len 返回当前公钥表中的公钥数量。
func (r *ReloadableKeyRegistry) Len() int { return r.cur.Load().Len() }
