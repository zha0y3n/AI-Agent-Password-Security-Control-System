// Package upstream 包含受保护的 Mock 业务服务（Mock Git / Mock DB）以及 Broker 调用它们的客户端。
//
// Mock 服务只认 Credential：持有正确 Credential 才能调用。
// Agent 拿不到 Credential，因此只能经由 Broker 间接使用。
package upstream

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// 头部约定：Broker 调用上游时携带，用于下游幂等与按 Capability 统计副作用。
const (
	HeaderIdempotencyKey = "X-Idempotency-Key" // = cap_id
	HeaderRequestHash    = "X-Request-Hash"
	HeaderReplay         = "X-Idempotent-Replay"
)

// Stats 是 Mock 服务的调用与副作用统计，供 C 断言“实际副作用发生了几次”。
type Stats struct {
	Calls        map[string]int `json:"calls"`         // service -> 成功调用次数（含读）
	SideEffects  int            `json:"side_effects"`  // 写操作实际生效次数
	ByCapability map[string]int `json:"by_capability"` // cap_id -> 实际生效的写操作次数
	ByResource   map[string]int `json:"by_resource"`   // service:resource -> 实际生效的写操作次数
	AuthFailures int            `json:"auth_failures"` // Credential 缺失或错误的调用
	Replays      int            `json:"replays"`       // 幂等重放（未产生新副作用）
}

type idemRecord struct {
	requestHash string
	status      int
	body        []byte
}

// Mock 是内存中的 Mock Git + Mock DB 服务。
type Mock struct {
	tokens map[string]string // service -> 期望的 Credential

	mu    sync.Mutex
	repos map[string]map[string]string // repo -> path -> content
	dbs   map[string]map[string]string // db -> key -> value
	idem  map[string]idemRecord
	stats Stats
}

// NewMock 创建 Mock，gitToken / dbToken 为两类服务各自期望的 Credential。
func NewMock(gitToken, dbToken string) *Mock {
	m := &Mock{tokens: map[string]string{"git": gitToken, "db": dbToken}}
	m.Reset()
	return m
}

// Reset 恢复种子数据并清空统计（Demo / 实验之间使用）。
func (m *Mock) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.repos = map[string]map[string]string{
		"repo-A":         {"README.md": "# repo-A\npublic project readme\n"},
		"private-repo":   {"secret.txt": "internal roadmap\n"},
		"course-project": {"README.md": "# course-project\nA demo task target\n"}, // A 的 demo 任务
	}
	m.dbs = map[string]map[string]string{
		"app-db": {"user:1": "alice", "user:2": "bob"},
	}
	m.idem = map[string]idemRecord{}
	m.stats = Stats{Calls: map[string]int{}, ByCapability: map[string]int{}, ByResource: map[string]int{}}
}

// Stats 返回统计快照。
func (m *Mock) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.stats
	s.Calls, s.ByCapability, s.ByResource = clone(s.Calls), clone(s.ByCapability), clone(s.ByResource)
	return s
}

func clone(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Handler 返回 Mock 服务路由。
func (m *Mock) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /git/repos/{repo}/files/{path...}", m.auth("git", m.gitRead))
	mux.HandleFunc("PUT /git/repos/{repo}/files/{path...}", m.auth("git", m.idempotent("git", "repo", m.gitWrite)))
	mux.HandleFunc("POST /db/{db}/query", m.auth("db", m.dbQuery))
	mux.HandleFunc("POST /db/{db}/update", m.auth("db", m.idempotent("db", "db", m.dbUpdate)))
	mux.HandleFunc("GET /stats", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, http.StatusOK, m.Stats()) })
	mux.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		m.Reset()
		writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
	})
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	return mux
}

// auth 校验 Authorization: Bearer <credential>，比较使用常量时间。
func (m *Mock) auth(service string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		want := m.tokens[service]
		if !ok || want == "" || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			m.mu.Lock()
			m.stats.AuthFailures++
			m.mu.Unlock()
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credential"})
			return
		}
		next(w, r)
	}
}

// writeOp 在持锁状态下执行写操作，返回状态码与响应体。
type writeOp func(r *http.Request, body []byte) (int, any)

// idempotent 为写操作提供下游幂等：同 key 同 request_hash 返回旧结果，不同 request_hash 返回 409。
func (m *Mock) idempotent(service, resourceParam string, op writeOp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := readLimited(r)
		key, reqHash := r.Header.Get(HeaderIdempotencyKey), r.Header.Get(HeaderRequestHash)

		m.mu.Lock()
		defer m.mu.Unlock()
		if key != "" {
			if rec, seen := m.idem[key]; seen {
				if rec.requestHash != reqHash {
					writeJSON(w, http.StatusConflict, map[string]string{"error": "idempotency key reused with different request"})
					return
				}
				m.stats.Replays++
				w.Header().Set(HeaderReplay, "true")
				writeRaw(w, rec.status, rec.body)
				return
			}
		}
		status, resp := op(r, body)
		m.stats.Calls[service]++
		raw, _ := json.Marshal(resp)
		if status < 300 {
			m.stats.SideEffects++
			m.stats.ByResource[service+":"+r.PathValue(resourceParam)]++
			if key != "" {
				m.stats.ByCapability[key]++
				m.idem[key] = idemRecord{requestHash: reqHash, status: status, body: raw}
			}
		}
		writeRaw(w, status, raw)
	}
}

func (m *Mock) gitRead(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.Calls["git"]++
	repo, path := r.PathValue("repo"), r.PathValue("path")
	content, ok := m.repos[repo][path]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "file not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"repo": repo, "path": path, "content": content})
}

func (m *Mock) gitWrite(r *http.Request, body []byte) (int, any) {
	var in struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		return http.StatusBadRequest, map[string]string{"error": "invalid body"}
	}
	repo, path := r.PathValue("repo"), r.PathValue("path")
	if m.repos[repo] == nil {
		return http.StatusNotFound, map[string]string{"error": "repo not found"}
	}
	m.repos[repo][path] = in.Content
	return http.StatusOK, map[string]string{"repo": repo, "path": path, "status": "written"}
}

func (m *Mock) dbQuery(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key string `json:"key"`
	}
	body, _ := readLimited(r)
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats.Calls["db"]++
	db := r.PathValue("db")
	v, ok := m.dbs[db][in.Key]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "key not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"db": db, "key": in.Key, "value": v})
}

func (m *Mock) dbUpdate(r *http.Request, body []byte) (int, any) {
	var in struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &in); err != nil || in.Key == "" {
		return http.StatusBadRequest, map[string]string{"error": "invalid body"}
	}
	db := r.PathValue("db")
	if m.dbs[db] == nil {
		return http.StatusNotFound, map[string]string{"error": "db not found"}
	}
	m.dbs[db][in.Key] = in.Value
	return http.StatusOK, map[string]string{"db": db, "key": in.Key, "status": "updated"}
}

func readLimited(r *http.Request) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r.Body, 1<<20))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	raw, _ := json.Marshal(v)
	writeRaw(w, status, raw)
}

func writeRaw(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(raw)
}
