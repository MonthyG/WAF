package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type KeyEnvelope struct {
	Algorithm  string `json:"algorithm"`
	WrappedKey []byte `json:"wrapped_key"`
	IV         []byte `json:"iv"`
	Tag        []byte `json:"tag"`
	Ciphertext []byte `json:"ciphertext"`
}
type TLSBundle struct {
	Certificate string      `json:"cert_pem"`
	Key         KeyEnvelope `json:"key_encrypted"`
}

func ParseNodeKey(data []byte) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("invalid node key PEM")
	}
	var key *rsa.PrivateKey
	if block.Type == "RSA PRIVATE KEY" {
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = parsed
	} else {
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("node key must be RSA")
		}
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("node key must be at least 2048 bits")
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return key, nil
}

func (a *Agent) loadCertificate(b Bundle) (*tls.Certificate, error) {
	if b.TLS == nil {
		if b.HTTPRedirect {
			return nil, errors.New("HTTPS redirect requires a certificate")
		}
		return nil, nil
	}
	if a.PrivateKey == nil {
		return nil, errors.New("node encryption key is not configured")
	}
	e := b.TLS.Key
	if e.Algorithm != "RSA-OAEP-256+A256GCM" {
		return nil, errors.New("unsupported key envelope")
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, a.PrivateKey, e.WrappedKey, nil)
	if err != nil || len(key) != 32 {
		return nil, errors.New("cannot unwrap certificate key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(e.IV) != gcm.NonceSize() || len(e.Tag) != gcm.Overhead() {
		return nil, errors.New("invalid key envelope lengths")
	}
	data := append(append([]byte(nil), e.Ciphertext...), e.Tag...)
	plain, err := gcm.Open(nil, e.IV, data, []byte(fmt.Sprintf("%s:%d", b.SiteID, b.Revision)))
	if err != nil {
		return nil, errors.New("certificate key authentication failed")
	}
	defer clear(plain)
	cert, err := tls.X509KeyPair([]byte(b.TLS.Certificate), plain)
	if err != nil {
		return nil, errors.New("invalid certificate pair")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return nil, errors.New("certificate is not current")
	}
	if err := leaf.VerifyHostname(b.Hostname); err != nil {
		return nil, errors.New("certificate does not cover hostname")
	}
	cert.Leaf = leaf
	return &cert, nil
}

func (a *Agent) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	host := strings.TrimSuffix(strings.ToLower(hello.ServerName), ".")
	e := a.table.Load().hosts[host]
	if e == nil || e.certificate == nil || !time.Now().Before(e.certificate.Leaf.NotAfter) {
		return nil, errors.New("no current certificate for SNI")
	}
	return e.certificate, nil
}
