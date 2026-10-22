package config

import (
	"strings"
	"testing"
)

func setBase(t *testing.T) {
	t.Helper()
	t.Setenv("BROKER_VAULT_KEY", strings.Repeat("ab", 16))
	t.Setenv("BROKER_ADMIN_TOKEN", strings.Repeat("x", 16))
}

func TestLoadRejectsInconsistentTLS(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"server cert without key":     {"BROKER_TLS_CERT_FILE": "c.pem"},
		"client CA without TLS":       {"BROKER_TLS_CLIENT_CA_FILE": "ca.pem"},
		"upstream cert without key":   {"BROKER_UPSTREAM_URL": "https://mock:9090", "BROKER_UPSTREAM_CLIENT_CERT_FILE": "c.pem"},
		"upstream CA over plain HTTP": {"BROKER_UPSTREAM_URL": "http://mock:9090", "BROKER_UPSTREAM_CA_FILE": "ca.pem"},
		"upstream cert over HTTP": {"BROKER_UPSTREAM_URL": "http://mock:9090",
			"BROKER_UPSTREAM_CLIENT_CERT_FILE": "c.pem", "BROKER_UPSTREAM_CLIENT_KEY_FILE": "c.key"},
	} {
		t.Run(name, func(t *testing.T) {
			setBase(t)
			for k, v := range env {
				t.Setenv(k, v)
			}
			if _, err := Load(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLoadAcceptsUpstreamMTLS(t *testing.T) {
	setBase(t)
	t.Setenv("BROKER_UPSTREAM_URL", "https://mock:9090")
	t.Setenv("BROKER_UPSTREAM_CA_FILE", "ca.pem")
	t.Setenv("BROKER_UPSTREAM_CLIENT_CERT_FILE", "c.pem")
	t.Setenv("BROKER_UPSTREAM_CLIENT_KEY_FILE", "c.key")
	c, err := Load()
	if err != nil || c.UpstreamClientCertFile != "c.pem" {
		t.Fatalf("%+v %v", c, err)
	}
}
