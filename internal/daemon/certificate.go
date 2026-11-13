package daemon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func managementCertificate(dir string) (tls.Certificate, string, error) {
	certPath, keyPath := filepath.Join(dir, "management.crt"), filepath.Join(dir, "management.key")
	if _, e := os.Stat(certPath); os.IsNotExist(e) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return tls.Certificate{}, "", e
		}
		serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if e != nil {
			return tls.Certificate{}, "", e
		}
		template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Minging Agent Management"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if e != nil {
			return tls.Certificate{}, "", e
		}
		raw, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return tls.Certificate{}, "", e
		}
		if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600); e != nil {
			return tls.Certificate{}, "", e
		}
		if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			return tls.Certificate{}, "", e
		}
	}
	certificate, e := tls.LoadX509KeyPair(certPath, keyPath)
	if e != nil {
		return certificate, "", e
	}
	h := sha256.Sum256(certificate.Certificate[0])
	return certificate, hex.EncodeToString(h[:]), nil
}
