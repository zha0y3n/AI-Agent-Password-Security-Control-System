package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCert struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	keyPEM  []byte
}

// issue 生成测试证书：parent 为 nil 时自签（CA）。
func issue(t *testing.T, cn string, parent *testCert, usage x509.ExtKeyUsage) *testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signerCert, signerKey := tmpl, key
	if parent == nil {
		tmpl.IsCA, tmpl.BasicConstraintsValid = true, true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	} else {
		signerCert, signerKey = parent.cert, parent.key
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{usage}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return &testCert{
		cert: cert, key: key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	}
}

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
	ca := issue(t, "test-ca", nil, 0)
	srv := issue(t, "broker", ca, x509.ExtKeyUsageServerAuth)
	certFile := writeFile(t, dir, "srv.pem", srv.certPEM)
	keyFile := writeFile(t, dir, "srv.key", srv.keyPEM)

	for name, c := range map[string]*Config{
		"missing cert":     {TLSCertFile: filepath.Join(dir, "nope.pem"), TLSKeyFile: keyFile},
		"mismatched key":   {TLSCertFile: certFile, TLSKeyFile: writeFile(t, dir, "other.key", issue(t, "x", ca, x509.ExtKeyUsageServerAuth).keyPEM)},
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
	ca := issue(t, "test-ca", nil, 0)
	srv := issue(t, "broker", ca, x509.ExtKeyUsageServerAuth)
	client := issue(t, "aa", ca, x509.ExtKeyUsageClientAuth)
	rogueCA := issue(t, "rogue-ca", nil, 0)
	rogue := issue(t, "rogue", rogueCA, x509.ExtKeyUsageClientAuth)

	c := &Config{
		TLSCertFile:     writeFile(t, dir, "srv.pem", srv.certPEM),
		TLSKeyFile:      writeFile(t, dir, "srv.key", srv.keyPEM),
		TLSClientCAFile: writeFile(t, dir, "ca.pem", ca.certPEM),
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
	roots.AddCert(ca.cert)
	get := func(cert *testCert) error {
		tc := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		if cert != nil {
			pair, err := tls.X509KeyPair(cert.certPEM, cert.keyPEM)
			if err != nil {
				t.Fatal(err)
			}
			tc.Certificates = []tls.Certificate{pair}
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
