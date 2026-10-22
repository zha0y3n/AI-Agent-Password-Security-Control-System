package config

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
)

func writeFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestServerTLSDisabled(t *testing.T) {
	c := &Config{}
	if cfg, err := c.ServerTLS(); err != nil || cfg != nil {
		t.Fatalf("plain HTTP: %v %v", cfg, err)
	}
}

func TestServerTLSLoadErrors(t *testing.T) {
	dir := t.TempDir()
	ca := testenv.IssueCert(t, "test-ca", nil, 0)
	srv := testenv.IssueCert(t, "broker", ca, x509.ExtKeyUsageServerAuth)
	certFile := writeFile(t, dir, "srv.pem", srv.CertPEM)
	keyFile := writeFile(t, dir, "srv.key", srv.KeyPEM)

	for name, c := range map[string]*Config{
		"missing cert":     {TLSCertFile: filepath.Join(dir, "nope.pem"), TLSKeyFile: keyFile},
		"mismatched key":   {TLSCertFile: certFile, TLSKeyFile: writeFile(t, dir, "other.key", testenv.IssueCert(t, "x", ca, x509.ExtKeyUsageServerAuth).KeyPEM)},
		"missing CA":       {TLSCertFile: certFile, TLSKeyFile: keyFile, TLSClientCAFile: filepath.Join(dir, "nope-ca.pem")},
		"CA without certs": {TLSCertFile: certFile, TLSKeyFile: keyFile, TLSClientCAFile: writeFile(t, dir, "empty.pem", []byte("not pem"))},
	} {
		if _, err := c.ServerTLS(); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestServerMutualTLS(t *testing.T) {
	dir := t.TempDir()
	ca := testenv.IssueCert(t, "test-ca", nil, 0)
	srv := testenv.IssueCert(t, "broker", ca, x509.ExtKeyUsageServerAuth)
	client := testenv.IssueCert(t, "aa", ca, x509.ExtKeyUsageClientAuth)
	rogueCA := testenv.IssueCert(t, "rogue-ca", nil, 0)
	rogue := testenv.IssueCert(t, "rogue", rogueCA, x509.ExtKeyUsageClientAuth)

	c := &Config{
		TLSCertFile:     writeFile(t, dir, "srv.pem", srv.CertPEM),
		TLSKeyFile:      writeFile(t, dir, "srv.key", srv.KeyPEM),
		TLSClientCAFile: writeFile(t, dir, "ca.pem", ca.CertPEM),
	}
	cfg, err := c.ServerTLS()
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	ts.TLS = cfg
	ts.StartTLS()
	defer ts.Close()

	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	get := func(cert *testenv.Cert) error {
		tc := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if cert != nil {
			tc.Certificates = []tls.Certificate{cert.TLSCertificate(t)}
		}
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 5 * time.Second}
		resp, err := hc.Get(ts.URL)
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status %d", resp.StatusCode)
		}
		return nil
	}

	if err := get(client); err != nil {
		t.Fatalf("trusted client certificate: %v", err)
	}
	if err := get(nil); err == nil {
		t.Fatal("client without certificate must be rejected")
	}
	if err := get(rogue); err == nil {
		t.Fatal("client certificate from an untrusted CA must be rejected")
	}
}
