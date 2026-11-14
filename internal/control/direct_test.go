package control

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDirectControllerHostAndTLS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "controller.invalid"}, DNSNames: []string{"controller.invalid"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "controller.invalid" || !strings.HasPrefix(r.Host, "controller.invalid:") {
			t.Error("Host/SNI identity lost")
			http.Error(w, "wrong identity", 421)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	u, _ := url.Parse(server.URL)
	config := Config{ServerID: 1, Controller: server.URL, ControllerHost: "controller.invalid:" + u.Port(), Token: strings.Repeat("a", 256), ControllerIPs: []string{"127.0.0.1/32"}, StateDirectory: t.TempDir(), TLSDirectory: t.TempDir()}
	pool := x509.NewCertPool()
	certificate, _ := x509.ParseCertificate(der)
	pool.AddCert(certificate)
	makeClient := func(c Config, roots *x509.CertPool) *Client {
		t.Helper()
		client, err := New(c)
		if err != nil {
			t.Fatal(err)
		}
		transport := client.HTTP.Transport.(*http.Transport)
		transport.TLSClientConfig.RootCAs = roots
		t.Cleanup(transport.CloseIdleConnections)
		return client
	}
	client := makeClient(config, pool)
	var response struct {
		OK bool `json:"ok"`
	}
	if err := client.Do(context.Background(), "GET", "/api/agent/config", nil, &response); err != nil || !response.OK {
		t.Fatal("direct IP connection with unresolvable Host failed", err)
	}
	if client.HTTP.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS validation disabled")
	}
	wrong := config
	wrong.ControllerHost = "wrong.invalid:" + u.Port()
	if err := makeClient(wrong, pool).Do(context.Background(), "GET", "/", nil, nil); err == nil {
		t.Fatal("incorrect certificate identity accepted")
	}
	if err := makeClient(config, x509.NewCertPool()).Do(context.Background(), "GET", "/", nil, nil); err == nil {
		t.Fatal("untrusted controller certificate accepted")
	}
	wrong = config
	wrong.ControllerIPs = []string{"192.0.2.1/32"}
	if err := makeClient(wrong, pool).Do(context.Background(), "GET", "/", nil, nil); err == nil {
		t.Fatal("controller outside IP allowlist accepted")
	}
	legacy := config
	legacy.ControllerHost = ""
	legacy.Controller = "https://controller.example.com"
	if err := legacy.Validate(); err != nil {
		t.Fatal("legacy domain configuration rejected", err)
	}
	for _, host := range []string{"controller.invalid\r\nInjected: value", "user@controller.invalid", "controller.invalid/path", "controller.invalid?x=1", "controller.invalid:70000"} {
		bad := config
		bad.ControllerHost = host
		if bad.Validate() == nil {
			t.Fatal("invalid Host accepted", host)
		}
	}
}
