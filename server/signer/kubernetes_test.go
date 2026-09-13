package signer

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParsePEMPrivateKey_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	priv, pub, err := parsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	if priv.Algorithm != "RS256" {
		t.Errorf("expected RS256, got %s", priv.Algorithm)
	}
	if pub.Algorithm != "RS256" {
		t.Errorf("expected RS256, got %s", pub.Algorithm)
	}
	if priv.KeyID == "" {
		t.Error("expected non-empty key ID")
	}
	if priv.KeyID != pub.KeyID {
		t.Error("private and public key IDs should match")
	}
}

func TestParsePEMPrivateKey_ECDSA(t *testing.T) {
	curves := []struct {
		curve elliptic.Curve
		alg   string
	}{
		{elliptic.P256(), "ES256"},
		{elliptic.P384(), "ES384"},
		{elliptic.P521(), "ES512"},
	}

	for _, tc := range curves {
		t.Run(tc.alg, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			ecBytes, err := x509.MarshalECPrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: ecBytes,
			})

			priv, pub, err := parsePEMPrivateKey(pemBytes)
			if err != nil {
				t.Fatal(err)
			}

			if priv.Algorithm != tc.alg {
				t.Errorf("expected %s, got %s", tc.alg, priv.Algorithm)
			}
			if pub.Algorithm != tc.alg {
				t.Errorf("expected %s, got %s", tc.alg, pub.Algorithm)
			}
		})
	}
}

func TestParsePEMPrivateKey_PKCS8(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	priv, pub, err := parsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	if priv.Algorithm != "RS256" {
		t.Errorf("expected RS256, got %s", priv.Algorithm)
	}
	if pub.Algorithm != "RS256" {
		t.Errorf("expected RS256, got %s", pub.Algorithm)
	}
}

func TestParsePEMPrivateKey_Ed25519(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8Bytes,
	})

	priv, pub, err := parsePEMPrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	if priv.Algorithm != "EdDSA" {
		t.Errorf("expected EdDSA, got %s", priv.Algorithm)
	}
	if pub.Algorithm != "EdDSA" {
		t.Errorf("expected EdDSA, got %s", pub.Algorithm)
	}
}

func TestParsePEMPrivateKey_Invalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte("")},
		{"not pem", []byte("not a pem block")},
		{"wrong block type", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")})},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parsePEMPrivateKey(tc.data)
			if err == nil {
				t.Error("expected error")
			}
		})
	}
}

func fakeSecretServer(t *testing.T, secretName, keyField string, keyPEM []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expectedPath := fmt.Sprintf("/api/v1/namespaces/default/secrets/%s", secretName)
		if r.URL.Path != expectedPath {
			http.NotFound(w, r)
			return
		}

		secret := map[string]interface{}{
			"data": map[string]string{
				keyField: base64.StdEncoding.EncodeToString(keyPEM),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(secret)
	}))
}

func TestKubernetesSignerSignAndValidate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	server := fakeSecretServer(t, "test-secret", "tls.key", keyPEM)
	defer server.Close()

	s := &kubernetesSigner{
		httpClient:      server.Client(),
		baseURL:         server.URL,
		secretName:      "test-secret",
		secretNamespace: "default",
		keyField:        "tls.key",
		pollInterval:    time.Minute,
		logger:          slog.New(slog.DiscardHandler),
	}

	if err := s.loadKey(); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	payload := []byte(`{"sub":"test-user"}`)
	signed, err := s.Sign(ctx, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signed == "" {
		t.Fatal("expected non-empty signed payload")
	}

	keys, err := s.ValidationKeys(ctx)
	if err != nil {
		t.Fatalf("ValidationKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 validation key, got %d", len(keys))
	}

	alg, err := s.Algorithm(ctx)
	if err != nil {
		t.Fatalf("Algorithm: %v", err)
	}
	if alg != "RS256" {
		t.Errorf("expected RS256, got %s", alg)
	}
}

func TestKubernetesSignerKeyRotation(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key1),
	})

	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key2PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key2),
	})

	currentPEM := key1PEM
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := map[string]interface{}{
			"data": map[string]string{
				"tls.key": base64.StdEncoding.EncodeToString(currentPEM),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(secret)
	}))
	defer server.Close()

	s := &kubernetesSigner{
		httpClient:      server.Client(),
		baseURL:         server.URL,
		secretName:      "test-secret",
		secretNamespace: "default",
		keyField:        "tls.key",
		pollInterval:    time.Minute,
		logger:          slog.New(slog.DiscardHandler),
	}

	// Load key1.
	if err := s.loadKey(); err != nil {
		t.Fatal(err)
	}

	keys, _ := s.ValidationKeys(context.Background())
	if len(keys) != 1 {
		t.Fatalf("expected 1 validation key, got %d", len(keys))
	}
	firstKeyID := keys[0].KeyID

	// Reload same key - should not add to prev keys.
	if err := s.loadKey(); err != nil {
		t.Fatal(err)
	}
	keys, _ = s.ValidationKeys(context.Background())
	if len(keys) != 1 {
		t.Fatalf("expected 1 validation key after no-op reload, got %d", len(keys))
	}

	// Switch to key2.
	currentPEM = key2PEM
	if err := s.loadKey(); err != nil {
		t.Fatal(err)
	}

	keys, _ = s.ValidationKeys(context.Background())
	if len(keys) != 2 {
		t.Fatalf("expected 2 validation keys after rotation, got %d", len(keys))
	}

	if keys[0].KeyID == firstKeyID {
		t.Error("current key should be the new key, not the old one")
	}
	if keys[1].KeyID != firstKeyID {
		t.Error("previous key should be the old key")
	}
}

func TestKubernetesSignerNoKeyLoaded(t *testing.T) {
	s := &kubernetesSigner{
		secretName:      "test",
		secretNamespace: "default",
		logger:          slog.New(slog.DiscardHandler),
	}

	ctx := context.Background()

	_, err := s.Sign(ctx, []byte("test"))
	if err == nil {
		t.Error("expected error when no key loaded")
	}

	_, err = s.ValidationKeys(ctx)
	if err == nil {
		t.Error("expected error when no key loaded")
	}

	_, err = s.Algorithm(ctx)
	if err == nil {
		t.Error("expected error when no key loaded")
	}
}

func TestKubernetesSignerMissingField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := map[string]interface{}{
			"data": map[string]string{
				"other-field": base64.StdEncoding.EncodeToString([]byte("not-a-key")),
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(secret)
	}))
	defer server.Close()

	s := &kubernetesSigner{
		httpClient:      server.Client(),
		baseURL:         server.URL,
		secretName:      "test-secret",
		secretNamespace: "default",
		keyField:        "tls.key",
		pollInterval:    time.Minute,
		logger:          slog.New(slog.DiscardHandler),
	}

	err := s.loadKey()
	if err == nil {
		t.Error("expected error for missing field")
	}
}

func TestKubernetesConfigOpen_Validation(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	t.Run("missing secretName", func(t *testing.T) {
		c := &KubernetesConfig{}
		_, err := c.Open(context.Background(), logger)
		if err == nil {
			t.Error("expected error for missing secretName")
		}
	})

	t.Run("invalid pollInterval", func(t *testing.T) {
		c := &KubernetesConfig{
			SecretName:   "test",
			PollInterval: "invalid",
		}
		_, err := c.Open(context.Background(), logger)
		if err == nil {
			t.Error("expected error for invalid pollInterval")
		}
	})
}
