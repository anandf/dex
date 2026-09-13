package signer

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/net/http2"
)

const (
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCAPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// KubernetesConfig holds configuration for the Kubernetes Secret signer.
type KubernetesConfig struct {
	// SecretName is the name of the Kubernetes Secret containing the signing key.
	SecretName string `json:"secretName"`
	// SecretNamespace is the namespace of the Secret. If empty, defaults to the pod's namespace.
	SecretNamespace string `json:"secretNamespace"`
	// KeyField is the data field in the Secret that contains the PEM-encoded private key.
	// Defaults to "tls.key".
	KeyField string `json:"keyField"`
	// PollInterval is how often to re-read the Secret for key changes. Defaults to "5m".
	PollInterval string `json:"pollInterval"`
	// InCluster uses in-cluster Kubernetes configuration. Defaults to true.
	InCluster *bool `json:"inCluster,omitempty"`
	// KubeConfigFile is the path to a kubeconfig file. Only used when InCluster is false.
	KubeConfigFile string `json:"kubeConfigFile,omitempty"`
}

// Open creates a new Kubernetes Secret signer.
func (c *KubernetesConfig) Open(_ context.Context, logger *slog.Logger) (Signer, error) {
	if c.SecretName == "" {
		return nil, fmt.Errorf("kubernetes signer: secretName is required")
	}
	if c.KeyField == "" {
		c.KeyField = "tls.key"
	}

	pollInterval := 5 * time.Minute
	if c.PollInterval != "" {
		var err error
		pollInterval, err = time.ParseDuration(c.PollInterval)
		if err != nil {
			return nil, fmt.Errorf("kubernetes signer: invalid pollInterval %q: %v", c.PollInterval, err)
		}
	}

	inCluster := c.InCluster == nil || *c.InCluster

	httpClient, baseURL, namespace, err := buildK8sClient(inCluster, c.KubeConfigFile)
	if err != nil {
		return nil, fmt.Errorf("kubernetes signer: %v", err)
	}

	secretNamespace := c.SecretNamespace
	if secretNamespace == "" {
		secretNamespace = namespace
	}
	if secretNamespace == "" {
		return nil, fmt.Errorf("kubernetes signer: could not determine namespace; set secretNamespace explicitly")
	}

	return &kubernetesSigner{
		httpClient:      httpClient,
		baseURL:         baseURL,
		secretName:      c.SecretName,
		secretNamespace: secretNamespace,
		keyField:        c.KeyField,
		pollInterval:    pollInterval,
		logger:          logger,
	}, nil
}

type kubernetesSigner struct {
	httpClient      *http.Client
	baseURL         string
	secretName      string
	secretNamespace string
	keyField        string
	pollInterval    time.Duration
	logger          *slog.Logger

	mu      sync.RWMutex
	privKey *jose.JSONWebKey
	pubKey  *jose.JSONWebKey
	// Previous public keys kept for verification during key transitions.
	prevPubKeys []*jose.JSONWebKey
}

func (k *kubernetesSigner) Start(ctx context.Context) {
	if err := k.loadKey(); err != nil {
		k.logger.Error("failed to load signing key from kubernetes secret", "err", err)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(k.pollInterval):
				if err := k.loadKey(); err != nil {
					k.logger.Error("failed to reload signing key from kubernetes secret", "err", err)
				}
			}
		}
	}()
}

func (k *kubernetesSigner) Sign(_ context.Context, payload []byte) (string, error) {
	k.mu.RLock()
	priv := k.privKey
	k.mu.RUnlock()

	if priv == nil {
		return "", fmt.Errorf("no signing key loaded from kubernetes secret %s/%s", k.secretNamespace, k.secretName)
	}

	alg, err := signatureAlgorithm(priv)
	if err != nil {
		return "", err
	}
	return signPayload(priv, alg, payload)
}

func (k *kubernetesSigner) ValidationKeys(_ context.Context) ([]*jose.JSONWebKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.pubKey == nil {
		return nil, fmt.Errorf("no public key loaded from kubernetes secret %s/%s", k.secretNamespace, k.secretName)
	}

	keys := make([]*jose.JSONWebKey, 0, 1+len(k.prevPubKeys))
	keys = append(keys, k.pubKey)
	keys = append(keys, k.prevPubKeys...)
	return keys, nil
}

func (k *kubernetesSigner) Algorithm(_ context.Context) (jose.SignatureAlgorithm, error) {
	k.mu.RLock()
	priv := k.privKey
	k.mu.RUnlock()

	if priv == nil {
		return "", fmt.Errorf("no signing key loaded from kubernetes secret %s/%s", k.secretNamespace, k.secretName)
	}
	return signatureAlgorithm(priv)
}

func (k *kubernetesSigner) loadKey() error {
	keyPEM, err := k.readSecretField()
	if err != nil {
		return fmt.Errorf("read secret %s/%s field %s: %v", k.secretNamespace, k.secretName, k.keyField, err)
	}

	priv, pub, err := parsePEMPrivateKey(keyPEM)
	if err != nil {
		return fmt.Errorf("parse private key from secret %s/%s: %v", k.secretNamespace, k.secretName, err)
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if k.pubKey != nil && k.pubKey.KeyID == pub.KeyID {
		return nil
	}

	if k.pubKey != nil {
		k.prevPubKeys = append(k.prevPubKeys, k.pubKey)
		// Keep at most 5 previous keys.
		if len(k.prevPubKeys) > 5 {
			k.prevPubKeys = k.prevPubKeys[len(k.prevPubKeys)-5:]
		}
	}

	k.privKey = priv
	k.pubKey = pub
	k.logger.Info("loaded signing key from kubernetes secret", "secret", k.secretName, "namespace", k.secretNamespace, "keyID", pub.KeyID)
	return nil
}

func (k *kubernetesSigner) readSecretField() ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", k.baseURL, k.secretNamespace, k.secretName)

	resp, err := k.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %v", url, err)
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET %s: %s %s", url, resp.Status, string(body))
	}

	var secret struct {
		Data map[string]string `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&secret); err != nil {
		return nil, fmt.Errorf("decode secret: %v", err)
	}

	encoded, ok := secret.Data[k.keyField]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s does not have field %q", k.secretNamespace, k.secretName, k.keyField)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode field %q: %v", k.keyField, err)
	}
	return decoded, nil
}

func parsePEMPrivateKey(data []byte) (priv *jose.JSONWebKey, pub *jose.JSONWebKey, err error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found")
	}

	var key crypto.PrivateKey
	var alg string

	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse PKCS1 private key: %v", err)
		}
		key = k
		alg = "RS256"
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse EC private key: %v", err)
		}
		key = k
		switch k.Curve {
		case elliptic.P256():
			alg = "ES256"
		case elliptic.P384():
			alg = "ES384"
		case elliptic.P521():
			alg = "ES512"
		default:
			return nil, nil, fmt.Errorf("unsupported EC curve")
		}
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse PKCS8 private key: %v", err)
		}
		key = k
		switch k.(type) {
		case *rsa.PrivateKey:
			alg = "RS256"
		case *ecdsa.PrivateKey:
			ec := k.(*ecdsa.PrivateKey)
			switch ec.Curve {
			case elliptic.P256():
				alg = "ES256"
			case elliptic.P384():
				alg = "ES384"
			case elliptic.P521():
				alg = "ES512"
			default:
				return nil, nil, fmt.Errorf("unsupported EC curve")
			}
		case ed25519.PrivateKey:
			alg = "EdDSA"
		default:
			return nil, nil, fmt.Errorf("unsupported key type %T in PKCS8", k)
		}
	default:
		return nil, nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}

	privJWK := &jose.JSONWebKey{
		Key:       key,
		Algorithm: alg,
		Use:       "sig",
	}
	pubJWK := &jose.JSONWebKey{
		Key:       publicKey(key),
		Algorithm: alg,
		Use:       "sig",
	}

	thumbprint, err := pubJWK.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("compute key thumbprint: %v", err)
	}
	keyID := base64.RawURLEncoding.EncodeToString(thumbprint)
	privJWK.KeyID = keyID
	pubJWK.KeyID = keyID

	return privJWK, pubJWK, nil
}

func publicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return k.Public()
	case *ecdsa.PrivateKey:
		return k.Public()
	case ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}

func buildK8sClient(inCluster bool, kubeConfigFile string) (*http.Client, string, string, error) {
	if !inCluster && kubeConfigFile == "" {
		return nil, "", "", fmt.Errorf("must specify either inCluster or kubeConfigFile")
	}

	var (
		serverURL string
		caData    []byte
		token     string
		namespace string
	)

	if inCluster {
		host := os.Getenv("KUBERNETES_SERVICE_HOST")
		port := os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, "", "", fmt.Errorf("KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT must be set")
		}
		serverURL = "https://" + net.JoinHostPort(host, port)

		var err error
		caData, err = os.ReadFile(saCAPath)
		if err != nil {
			return nil, "", "", fmt.Errorf("read CA cert: %v", err)
		}

		tokenBytes, err := os.ReadFile(saTokenPath)
		if err != nil {
			return nil, "", "", fmt.Errorf("read service account token: %v", err)
		}
		token = string(tokenBytes)

		nsBytes, err := os.ReadFile(saNamespacePath)
		if err != nil {
			ns := os.Getenv("KUBERNETES_POD_NAMESPACE")
			if ns == "" {
				return nil, "", "", fmt.Errorf("read namespace: %v", err)
			}
			namespace = ns
		} else {
			namespace = strings.TrimSpace(string(nsBytes))
		}
	} else {
		data, err := os.ReadFile(kubeConfigFile)
		if err != nil {
			return nil, "", "", fmt.Errorf("read kubeconfig: %v", err)
		}
		serverURL, caData, token, namespace, err = parseKubeConfig(data)
		if err != nil {
			return nil, "", "", fmt.Errorf("parse kubeconfig: %v", err)
		}
	}

	tlsConfig := &tls.Config{}
	if len(caData) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caData) {
			return nil, "", "", fmt.Errorf("failed to parse CA certificates")
		}
		tlsConfig.RootCAs = pool
	}

	httpTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if err := http2.ConfigureTransport(httpTransport); err != nil {
		return nil, "", "", fmt.Errorf("configure http2: %v", err)
	}

	var rt http.RoundTripper = httpTransport
	if inCluster {
		rt = &inClusterTokenTransport{
			base:      httpTransport,
			token:     token,
			tokenPath: saTokenPath,
			expiry:    time.Now().Add(30 * time.Second),
		}
	} else if token != "" {
		rt = &staticTokenTransport{base: httpTransport, token: token}
	}

	return &http.Client{Transport: rt, Timeout: 15 * time.Second}, serverURL, namespace, nil
}

type staticTokenTransport struct {
	base  http.RoundTripper
	token string
}

func (t *staticTokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(r2)
}

type inClusterTokenTransport struct {
	base      http.RoundTripper
	mu        sync.RWMutex
	token     string
	tokenPath string
	expiry    time.Time
}

func (t *inClusterTokenTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.refreshIfNeeded()
	t.mu.RLock()
	token := t.token
	t.mu.RUnlock()

	r2 := r.Clone(r.Context())
	r2.Header.Set("Authorization", "Bearer "+token)
	return t.base.RoundTrip(r2)
}

func (t *inClusterTokenTransport) refreshIfNeeded() {
	t.mu.RLock()
	expired := time.Now().After(t.expiry)
	t.mu.RUnlock()
	if !expired {
		return
	}

	data, err := os.ReadFile(t.tokenPath)
	if err != nil {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.token = string(data)
	t.expiry = time.Now().Add(30 * time.Second)
}

// parseKubeConfig extracts the current context's server, CA, token, and namespace
// from a kubeconfig YAML/JSON file.
func parseKubeConfig(data []byte) (serverURL string, caData []byte, token string, namespace string, err error) {
	var config struct {
		CurrentContext string `json:"current-context"`
		Clusters       []struct {
			Name    string `json:"name"`
			Cluster struct {
				Server                string `json:"server"`
				CertificateAuthority  string `json:"certificate-authority,omitempty"`
				CertificateAuthorData string `json:"certificate-authority-data,omitempty"`
			} `json:"cluster"`
		} `json:"clusters"`
		Contexts []struct {
			Name    string `json:"name"`
			Context struct {
				Cluster   string `json:"cluster"`
				User      string `json:"user"`
				Namespace string `json:"namespace,omitempty"`
			} `json:"context"`
		} `json:"contexts"`
		Users []struct {
			Name string `json:"name"`
			User struct {
				Token string `json:"token,omitempty"`
			} `json:"user"`
		} `json:"users"`
	}

	if err = json.Unmarshal(data, &config); err != nil {
		return "", nil, "", "", fmt.Errorf("unmarshal kubeconfig: %v", err)
	}

	ctxName := config.CurrentContext
	if ctxName == "" && len(config.Contexts) == 1 {
		ctxName = config.Contexts[0].Name
	}

	var clusterName, userName string
	for _, c := range config.Contexts {
		if c.Name == ctxName {
			clusterName = c.Context.Cluster
			userName = c.Context.User
			namespace = c.Context.Namespace
			break
		}
	}

	for _, c := range config.Clusters {
		if c.Name == clusterName {
			serverURL = c.Cluster.Server
			if c.Cluster.CertificateAuthorData != "" {
				caData, err = base64.StdEncoding.DecodeString(c.Cluster.CertificateAuthorData)
				if err != nil {
					return "", nil, "", "", fmt.Errorf("decode CA data: %v", err)
				}
			} else if c.Cluster.CertificateAuthority != "" {
				caData, err = os.ReadFile(c.Cluster.CertificateAuthority)
				if err != nil {
					return "", nil, "", "", fmt.Errorf("read CA file: %v", err)
				}
			}
			break
		}
	}

	for _, u := range config.Users {
		if u.Name == userName {
			token = u.User.Token
			break
		}
	}

	if serverURL == "" {
		return "", nil, "", "", fmt.Errorf("could not find server URL in kubeconfig")
	}

	return serverURL, caData, token, namespace, nil
}
