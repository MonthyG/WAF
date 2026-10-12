package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tlsFixture(t *testing.T, node *rsa.PrivateKey, b Bundle, hostname string, expires time.Time) *TLSBundle {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: hostname}, DNSNames: []string{hostname}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expires, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	aesKey := make([]byte, 32)
	rand.Read(aesKey)
	iv := make([]byte, 12)
	rand.Read(iv)
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	encrypted := gcm.Seal(nil, iv, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), []byte(fmt.Sprintf("%s:%d", b.SiteID, b.Revision)))
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &node.PublicKey, aesKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &TLSBundle{Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Key: KeyEnvelope{Algorithm: "RSA-OAEP-256+A256GCM", WrappedKey: wrapped, IV: iv, Ciphertext: encrypted[:len(encrypted)-16], Tag: encrypted[len(encrypted)-16:]}}
}

func TestTLSValidationAndAtomicReplacement(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer origin.Close()
	a := New("node", nil)
	a.PrivateKey = key
	defer a.Close()
	b := testBundle(origin.URL, 1)
	b.HTTPRedirect = true
	b.TLS = tlsFixture(t, key, b, b.Hostname, time.Now().Add(time.Hour))
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	original, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: b.Hostname})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"expired", "wrong-host", "revision-replay", "tampered", "bad-nonce"} {
		t.Run(kind, func(t *testing.T) {
			bad := b
			bad.Revision = 2
			hostname, expiry := b.Hostname, time.Now().Add(time.Hour)
			if kind == "expired" {
				expiry = time.Now().Add(-time.Minute)
			}
			if kind == "wrong-host" {
				hostname = "other.localhost"
			}
			bad.TLS = tlsFixture(t, key, bad, hostname, expiry)
			if kind == "revision-replay" {
				bad.TLS = b.TLS
			}
			if kind == "tampered" {
				bad.TLS.Key.Tag[0] ^= 1
			}
			if kind == "bad-nonce" {
				bad.TLS.Key.IV = nil
			}
			if a.Apply(Message{Op: "upsert", Bundle: bad}) == nil {
				t.Fatal("bad certificate accepted")
			}
			current, _ := a.GetCertificate(&tls.ClientHelloInfo{ServerName: b.Hostname})
			if current != original || a.Applied()[b.SiteID] != 1 {
				t.Fatal("failed replacement changed active certificate")
			}
		})
	}
	if _, err := a.GetCertificate(&tls.ClientHelloInfo{ServerName: "unknown.localhost"}); err == nil {
		t.Fatal("unknown SNI accepted")
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/path?q=1", nil))
	if w.Code != 308 || w.Header().Get("Location") != "https://shop.localhost/path?q=1" {
		t.Fatal("incorrect redirect", w.Code, w.Header())
	}
	req := httptest.NewRequest("GET", "https://shop.localhost/", nil)
	req.TLS = &tls.ConnectionState{ServerName: "other.localhost"}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, req)
	if w.Code != 421 {
		t.Fatal("domain fronting accepted")
	}
	b.Revision = 2
	b.TLS = tlsFixture(t, key, b, b.Hostname, time.Now().Add(time.Hour))
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	renewed, _ := a.GetCertificate(&tls.ClientHelloInfo{ServerName: b.Hostname})
	if renewed == original {
		t.Fatal("certificate not replaced")
	}
}

func TestHTTP01BeforeRedirectAndWAF(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a := New("node", nil)
	a.PrivateKey = key
	defer a.Close()
	b := testBundle("http://127.0.0.1:1", 1)
	b.HTTPRedirect = true
	b.TLS = tlsFixture(t, key, b, b.Hostname, time.Now().Add(time.Hour))
	token := strings.Repeat("a", 43)
	authorization := token + "." + strings.Repeat("b", 43)
	b.Challenges = []Challenge{{Token: token, Authorization: authorization, ExpiresAt: time.Now().Add(time.Minute)}}
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/.well-known/acme-challenge/"+token+"?attack=true", nil))
	if w.Code != 200 || w.Body.String() != authorization {
		t.Fatal("HTTP01 did not bypass WAF and redirect")
	}
	b.Revision = 2
	b.TLS = tlsFixture(t, key, b, b.Hostname, time.Now().Add(time.Hour))
	b.Challenges[0].ExpiresAt = time.Now().Add(-time.Minute)
	if err := a.Apply(Message{Op: "upsert", Bundle: b}); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, httptest.NewRequest("GET", "http://shop.localhost/.well-known/acme-challenge/"+token, nil))
	if w.Code != 404 {
		t.Fatal("expired challenge served")
	}
}
