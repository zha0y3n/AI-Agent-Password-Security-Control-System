package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/errcode"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
)

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if err := s.Credentials.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable", "broker_id": s.BrokerID})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "broker_id": s.BrokerID})
}

func (s *Server) publicKey(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"broker_id":  s.BrokerID,
		"algorithm":  "SM2",
		"encoding":   "uncompressed-hex(04||X||Y)",
		"uid":        crypto.SM2UserID,
		"signature":  "ASN.1 DER(r,s)",
		"public_key": s.Signer.PublicKeyHex(),
	})
}

// ---- Challenge ----

func (s *Server) issueChallenge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		AgentID string `json:"agent_id"`
	}
	if !decode(w, r, &in) {
		return
	}
	c, err := s.Challenges.Issue(r.Context(), in.AgentID)
	switch {
	case errors.Is(err, challenge.ErrBadAgent):
		writeError(w, http.StatusBadRequest, errcode.BadRequest, err.Error())
	case err != nil:
		s.internalError(w, err)
	default:
		writeJSON(w, http.StatusCreated, c)
	}
}

// ---- Credential ----

func (s *Server) credentialStatus(w http.ResponseWriter, r *http.Request) {
	info, err := s.Credentials.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		s.credentialError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) createCredential(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string        `json:"credential_id"`
		Provider string        `json:"provider"`
		Secret   secret.Secret `json:"secret"`
	}
	if !decode(w, r, &in) {
		return
	}
	defer in.Secret.Wipe()
	info, err := s.Credentials.Create(r.Context(), in.ID, in.Provider, in.Secret)
	if err != nil {
		s.credentialError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, info)
}

func (s *Server) rotateCredential(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Secret secret.Secret `json:"secret"`
	}
	if !decode(w, r, &in) {
		return
	}
	defer in.Secret.Wipe()
	info, err := s.Credentials.Rotate(r.Context(), r.PathValue("id"), in.Secret)
	if err != nil {
		s.credentialError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) applyCredential(w http.ResponseWriter, r *http.Request) {
	info, err := s.Credentials.Apply(r.Context(), r.PathValue("id"), credential.Action(r.PathValue("action")))
	if err != nil {
		s.credentialError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) credentialError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, credential.ErrNotFound):
		writeError(w, http.StatusNotFound, errcode.CredentialNotFound, err.Error())
	case errors.Is(err, credential.ErrExists):
		writeError(w, http.StatusConflict, errcode.Conflict, err.Error())
	case errors.Is(err, credential.ErrInvalidTransition):
		writeError(w, http.StatusConflict, errcode.InvalidTransition, err.Error())
	case errors.Is(err, credential.ErrInvalidInput):
		writeError(w, http.StatusBadRequest, errcode.BadRequest, err.Error())
	default:
		s.internalError(w, err)
	}
}

// ---- 审计 ----

func (s *Server) auditRecords(w http.ResponseWriter, r *http.Request) {
	from, limit := int64(1), 100
	if v := r.URL.Query().Get("from"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, errcode.BadRequest, "invalid from")
			return
		}
		from = n
	}
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeError(w, http.StatusBadRequest, errcode.BadRequest, "limit must be 1..1000")
			return
		}
		limit = n
	}
	rs, err := s.Auditor.Records(r.Context(), from, limit)
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": rs})
}

func (s *Server) auditCheckpoints(w http.ResponseWriter, r *http.Request) {
	cps, err := s.Auditor.Checkpoints(r.Context())
	if err != nil {
		s.internalError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"checkpoints": cps})
}

func (s *Server) createCheckpoint(w http.ResponseWriter, r *http.Request) {
	cp, err := s.Auditor.CreateCheckpoint(r.Context())
	if err != nil {
		writeError(w, http.StatusConflict, errcode.Conflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cp)
}

// ---- 指标 ----

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"stages": s.Metrics.Snapshot()})
}

func (s *Server) resetMetrics(w http.ResponseWriter, r *http.Request) {
	s.Metrics.Reset()
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}
