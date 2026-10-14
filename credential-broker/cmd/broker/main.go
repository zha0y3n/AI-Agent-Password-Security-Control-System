// Command broker 启动 Credential Broker（可信执行域）。
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/api"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/challenge"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/config"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/credential"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/crypto"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/evidence"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/logging"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/metrics"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/repository"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/vault"
)

func main() {
	if err := run(); err != nil {
		slog.Error("broker exited", "error", err.Error())
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := logging.New(os.Stdout, cfg.LogLevel)

	db, err := repository.Open(cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()

	signer, created, err := crypto.LoadOrCreateSM2Signer(cfg.SigningKeyFile)
	if err != nil {
		return err
	}
	if created {
		log.Warn("generated new broker SM2 signing key", "path", cfg.SigningKeyFile)
	}
	v, err := vault.New(cfg.VaultKey)
	if err != nil {
		return err
	}
	auditor := evidence.NewAuditor(db, signer, cfg.CheckpointEvery)
	challenges := challenge.NewService(db, cfg.ChallengeTTL, cfg.BrokerID)

	srv := &api.Server{
		BrokerID:    cfg.BrokerID,
		AdminToken:  cfg.AdminToken,
		Credentials: credential.NewService(db, v, auditor),
		Challenges:  challenges,
		Auditor:     auditor,
		Signer:      signer,
		Metrics:     metrics.New(),
		Log:         log,
	}
	httpSrv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go purgeChallenges(ctx, challenges, cfg.ChallengeTTL, log)

	errc := make(chan error, 1)
	go func() {
		log.Info("broker listening", "addr", cfg.Addr, "broker_id", cfg.BrokerID, "public_key", signer.PublicKeyHex())
		errc <- httpSrv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// purgeChallenges 定期清理过期 Challenge。
func purgeChallenges(ctx context.Context, s *challenge.Service, ttl time.Duration, log *slog.Logger) {
	t := time.NewTicker(ttl)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.Purge(ctx, ttl); err != nil && ctx.Err() == nil {
				log.Warn("purge challenges failed", "error", err.Error())
			}
		}
	}
}
