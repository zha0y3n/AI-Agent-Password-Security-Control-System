package api

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"net/http"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/protocol"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/verifier"
)

// execute 是 Broker 的唯一业务入口：请求体为 A 的 Execution Bundle（原始字节交给流水线严格解析）。
// 响应为 execution.Outcome；拒绝时的 HTTP 状态码见 errcode.ExecuteStatus。
func (s *Server) execute(w http.ResponseWriter, r *http.Request) {
	if s.Executor == nil {
		writeError(w, http.StatusServiceUnavailable, errcode.ExecutionDisabled, "execution is not configured on this broker")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, errcode.BadRequest, "request body too large")
		return
	}
	out, err := s.Executor.Execute(r.Context(), &verifier.Input{Body: body})
	if err != nil {
		s.internalError(w, err)
		return
	}
	status := http.StatusOK
	if !out.Decision.Allowed {
		status = errcode.ExecuteStatus(out.Decision.Code)
	}
	writeJSON(w, status, out)
}

// keyRecord 是 Broker 回执公钥的 A 格式 PublicKeyRecord（agent_aa.models.PublicKeyRecord）。
func (s *Server) keyRecord() (map[string]any, error) {
	pemKey, err := s.publicKeyPEM()
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"key_id":         s.KeyID,
		"subject_id":     s.BrokerID,
		"purpose":        protocol.KeyPurposeReceipt,
		"algorithm":      "SM2",
		"status":         "ACTIVE",
		"public_key_pem": pemKey,
		"not_before":     s.KeyNotBefore,
		"not_after":      s.KeyNotAfter,
	}, nil
}

// keyRegistry 以 A 的 KeyRegistryDocument 格式公布 Broker 公钥，
// 可直接交给 agent_aa.keys.KeyRegistry 用于 ReceiptVerifier。
func (s *Server) keyRegistry(w http.ResponseWriter, r *http.Request) {
	rec, err := s.keyRecord()
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"protocol_version": protocol.ProtocolVersion, "keys": []any{rec}})
}

// capabilityStatus 返回 Capability 的消费状态，供 C 断言重放 / 并发 / 撤销实验的最终状态。
func (s *Server) capabilityStatus(w http.ResponseWriter, r *http.Request) {
	if s.Capabilities == nil {
		writeError(w, http.StatusServiceUnavailable, errcode.ExecutionDisabled, "execution is not configured on this broker")
		return
	}
	info, err := s.Capabilities.Get(r.Context(), r.PathValue("id"))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		writeError(w, http.StatusNotFound, errcode.NotFound, "capability has never been consumed by this broker")
	case err != nil:
		s.internalError(w, err)
	default:
		writeJSON(w, http.StatusOK, info)
	}
}

// auditVerify 在 Broker 侧完整复核审计链与全部检查点（C 也可用导出数据独立复核）。
func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) {
	records, err := s.allAuditRecords(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	cps, err := s.Auditor.Checkpoints(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	res := map[string]any{"valid": true, "entries": len(records), "checkpoints": len(cps), "head_hash": nil}
	if n := len(records); n > 0 {
		res["head_hash"] = records[n-1].Hash
	}
	if err := evidence.VerifyChain(records, cps, s.Signer.PublicKey()); err != nil {
		res["valid"], res["error"] = false, err.Error()
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) allAuditRecords(ctx context.Context) ([]evidence.Record, error) {
	const page = 1000
	var all []evidence.Record
	for from := int64(1); ; {
		rs, err := s.Auditor.Records(ctx, from, page)
		if err != nil {
			return nil, err
		}
		all = append(all, rs...)
		if len(rs) < page {
			return all, nil
		}
		from = rs[len(rs)-1].Seq + 1
	}
}

// reset 清空 Broker 状态并重置指标，让每轮实验从干净状态开始（需 BROKER_ENABLE_RESET）。
// Mock 上游需另行 POST /reset（scripts/reset.sh 会一并处理）。
func (s *Server) reset(w http.ResponseWriter, r *http.Request) {
	if s.ResetDB == nil {
		writeError(w, http.StatusForbidden, errcode.ResetDisabled, "reset is disabled (set BROKER_ENABLE_RESET=1 in dev only)")
		return
	}
	if err := s.ResetDB.Reset(r.Context()); err != nil {
		s.internalError(w, err)
		return
	}
	s.Metrics.Reset()
	s.Log.Warn("broker state reset by admin")
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}
