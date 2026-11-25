package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Authority is a local CA whose name constraints only allow it to issue
// certificates for the intercepted hosts. A leaked key can't be used to
// impersonate any other site.
type Authority struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     crypto.Signer

	mu    sync.Mutex
	leafs map[string]*tls.Certificate
}

// LoadOrCreateCA loads dir/ca.pem and dir/ca-key.pem, creating them when
// missing, expiring, or constrained to a different host set.
func LoadOrCreateCA(dir string, hosts []string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if a, err := loadCA(certPath, keyPath); err == nil && a.fits(hosts) {
		return a, nil
	}
	a, keyPEM, err := newCA(hosts)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, a.CertPEM, 0o644); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Authority) fits(hosts []string) bool {
	h := slices.Clone(hosts)
	p := slices.Clone(a.Cert.PermittedDNSDomains)
	slices.Sort(h)
	slices.Sort(p)
	return slices.Equal(h, p) && a.Cert.PermittedDNSDomainsCritical &&
		time.Until(a.Cert.NotAfter) > 30*24*time.Hour
}

func loadCA(certPath, keyPath string) (*Authority, error) {
	cp, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kp, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(cp)
	kb, _ := pem.Decode(kp)
	if cb == nil || kb == nil {
		return nil, errors.New("bad PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("CA key is not a signer")
	}
	return &Authority{Cert: cert, CertPEM: cp, key: signer, leafs: map[string]*tls.Certificate{}}, nil
}

func newCA(hosts []string) (*Authority, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:                serial(),
		Subject:                     pkix.Name{CommonName: "agy-sp local CA (cloudcode-pa only)", Organization: []string{"agy-sp"}},
		NotBefore:                   now.Add(-time.Hour),
		NotAfter:                    now.AddDate(5, 0, 0),
		IsCA:                        true,
		BasicConstraintsValid:       true,
		MaxPathLen:                  0,
		MaxPathLenZero:              true,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomains:         slices.Clone(hosts),
		PermittedDNSDomainsCritical: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	cert, _ := x509.ParseCertificate(der)
	kder, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	a := &Authority{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		leafs:   map[string]*tls.Certificate{},
	}
	return a, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kder}), nil
}

// Leaf returns (and caches) a short-lived server certificate for host.
func (a *Authority) Leaf(host string) (*tls.Certificate, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.leafs[host]; ok && time.Until(c.Leaf.NotAfter) > time.Hour {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(7 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("issue leaf for %s: %w", host, err)
	}
	leaf, _ := x509.ParseCertificate(der)
	c := &tls.Certificate{Certificate: [][]byte{der, a.Cert.Raw}, PrivateKey: key, Leaf: leaf}
	a.leafs[host] = c
	return c, nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// WriteFileAtomic is exported for the trust-bundle writer.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	return writeFileAtomic(path, data, mode)
}
