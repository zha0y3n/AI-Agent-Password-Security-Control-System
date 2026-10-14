// Package api 是 Broker 的 HTTP 接口层。
//
// 提供：执行接口（Execution Bundle -> Receipt）、Challenge、Credential 管理与状态查询、
// Capability 状态、审计导出与复核、Broker 公钥、性能指标，以及仅限实验环境的状态重置。
package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/capability"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/execution"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
)

const maxBodyBytes = 1 << 20

// Server 聚合 HTTP 处理所需依赖。
type Server struct {
	BrokerID    string
	AdminToken  string
	Credentials *credential.Service
	Challenges  *challenge.Service
	Auditor     *evidence.Auditor
	Signer      *crypto.SM2Signer
	Metrics     *metrics.Recorder
	Log         *slog.Logger

	// Receipt 签名公钥的标识与有效期，按 A 的 PublicKeyRecord 格式公布。
	KeyID        string
	KeyNotBefore int64
	KeyNotAfter  int64

	// Executor 为 nil 时 POST /v1/execute 返回 503。
	Executor     *execution.Executor
	Capabilities *capability.Store
	// ResetDB 非 nil 时开放 POST /v1/admin/reset（仅开发 / 实验环境）。
	ResetDB *repository.DB
}

// Handler 返回带中间件的路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("GET /v1/broker/public-key", s.publicKey)
	mux.HandleFunc("GET /v1/broker/key-registry", s.keyRegistry)

	mux.HandleFunc("POST /v1/execute", s.execute)
	mux.HandleFunc("GET /v1/capabilities/{id}", s.admin(s.capabilityStatus))

	mux.HandleFunc("POST /v1/challenge", s.issueChallenge)

	mux.HandleFunc("GET /v1/credentials/{id}/status", s.credentialStatus)
	mux.HandleFunc("POST /v1/credentials", s.admin(s.createCredential))
	mux.HandleFunc("POST /v1/credentials/{id}/rotate", s.admin(s.rotateCredential))
	mux.HandleFunc("POST /v1/credentials/{id}/{action}", s.admin(s.applyCredential))

	mux.HandleFunc("GET /v1/audit", s.auditRecords)
	mux.HandleFunc("GET /v1/audit/checkpoints", s.auditCheckpoints)
	mux.HandleFunc("POST /v1/audit/checkpoints", s.admin(s.createCheckpoint))
	mux.HandleFunc("GET /v1/audit/verify", s.auditVerify)

	mux.HandleFunc("GET /v1/metrics", s.metrics)
	mux.HandleFunc("POST /v1/metrics/reset", s.admin(s.resetMetrics))

	mux.HandleFunc("POST /v1/admin/reset", s.admin(s.reset))

	return s.recoverer(s.accessLog(mux))
}

// ---- 中间件 ----

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// accessLog 只记录方法、路径、状态码、耗时，从不记录请求体或头部。
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"duration_ms", float64(time.Since(start))/float64(time.Millisecond))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				s.Log.Error("panic", "path", r.URL.Path, "panic", p)
				writeError(w, http.StatusInternalServerError, errcode.Internal, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// admin 要求 Authorization: Bearer <BROKER_ADMIN_TOKEN>。Agent 不持有该令牌。
func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.AdminToken)) != 1 {
			writeError(w, http.StatusUnauthorized, errcode.Unauthorized, "admin token required")
			return
		}
		next(w, r)
	}
}

// ---- 工具 ----

type errorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// writeJSON 关闭 HTML 转义，使嵌入的规范字节（result_envelope / receipt）原样输出。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	var b errorBody
	b.Error.Code, b.Error.Message = code, msg
	writeJSON(w, status, b)
}

// decode 严格解析 JSON：限制大小、拒绝未知字段、拒绝尾随数据。
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, errcode.BadRequest, "invalid JSON body")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, errcode.BadRequest, "unexpected data after JSON body")
		return false
	}
	return true
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.Log.Error("internal error", "error", err.Error())
	writeError(w, http.StatusInternalServerError, errcode.Internal, "internal error")
}
