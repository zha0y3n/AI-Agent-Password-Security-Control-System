package upstream

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/secret"
	"github.com/zha0y3n/AI-Agent-Password-Security-Control-System/credential-broker/internal/testenv"
)

// 上游只接受出示受信客户端证书（Broker）的连接：持有正确 Credential 但没有证书的调用方被拒，
// 且不会产生副作用；实验接口 /stats 仍可无证书访问。
func TestMockRequiresBrokerClientCertificate(t *testing.T) {
	ca := testenv.IssueCert(t, "test-ca", nil, 0)
	server := testenv.IssueCert(t, "mock", ca, x509.ExtKeyUsageServerAuth)
	broker := testenv.IssueCert(t, "broker", ca, x509.ExtKeyUsageClientAuth)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)

	m := NewMock("git-token", "db-token")
	m.RequireClientCert = true
	srv := httptest.NewUnstartedServer(m.Handler())
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{server.TLSCertificate(t)},
		ClientCAs: roots, ClientAuth: tls.VerifyClientCertIfGiven,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	write := Call{Service: "git", Operation: "write_file", Resource: "repo-A",
		Args: map[string]string{"path": "x.txt", "content": "hi"}, CapID: "cap-1", RequestHash: "h1"}

	withCert := NewTLSClient(srv.URL, 5*time.Second, &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{broker.TLSCertificate(t)}})
	resp, err := withCert.Do(ctx, write, secret.Secret("git-token"))
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("broker with client certificate: %+v %v", resp, err)
	}

	stolen := write
	stolen.CapID = "cap-2"
	withoutCert := NewTLSClient(srv.URL, 5*time.Second, &tls.Config{RootCAs: roots})
	resp, err = withoutCert.Do(ctx, stolen, secret.Secret("git-token"))
	if err != nil || resp.Status != http.StatusForbidden {
		t.Fatalf("stolen credential without client certificate: %+v %v", resp, err)
	}
	if s := m.Stats(); s.SideEffects != 1 || s.AuthFailures != 1 {
		t.Fatalf("stats: %+v", s)
	}

	statsResp, err := withoutCert.http.Get(srv.URL + "/stats")
	if err != nil || statsResp.StatusCode != http.StatusOK {
		t.Fatalf("/stats without client certificate: %v %v", statsResp, err)
	}
	statsResp.Body.Close()
}
