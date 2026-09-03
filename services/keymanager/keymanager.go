// Package keymanager provides production key-wrapping adapters for envelope
// encryption. It never accepts credential plaintext and never exposes Vault
// response bodies in errors.
package keymanager

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	DataKeyBytes       = 32
	maxVaultResponse   = 64 << 10
	maxVaultTokenBytes = 16 << 10
)

type Wrapper interface {
	KeyID() string
	WrapKey(context.Context, []byte, []byte) ([]byte, []byte, error)
}

type Unwrapper interface {
	KeyID() string
	UnwrapKey(context.Context, []byte, []byte, []byte) ([]byte, error)
}

type Manager interface {
	Wrapper
	Unwrapper
}

type Capability string

const (
	WrapOnly   Capability = "wrap"
	UnwrapOnly Capability = "unwrap"
	WrapUnwrap Capability = "wrap_unwrap"
)

type TokenSource interface {
	Token(context.Context) ([]byte, error)
}

type FileTokenSource struct {
	Path string
}

func (FileTokenSource) String() string   { return "FileTokenSource{Path:[redacted]}" }
func (FileTokenSource) GoString() string { return "keymanager.FileTokenSource{Path:[redacted]}" }

func (s FileTokenSource) Token(_ context.Context) ([]byte, error) {
	if !filepath.IsAbs(s.Path) {
		return nil, errors.New("Vault token file path must be absolute")
	}
	file, err := os.Open(s.Path)
	if err != nil {
		return nil, errors.New("open Vault token file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("Vault token file permissions are unsafe")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxVaultTokenBytes+1))
	if err != nil || len(contents) > maxVaultTokenBytes {
		wipe(contents)
		return nil, errors.New("read Vault token file")
	}
	contents = bytes.TrimSpace(contents)
	if len(contents) == 0 || bytes.IndexAny(contents, "\r\n\x00") >= 0 {
		wipe(contents)
		return nil, errors.New("Vault token file is invalid")
	}
	return contents, nil
}

type VaultConfig struct {
	Address                  string
	TransitMount             string
	KeyName                  string
	Namespace                string
	Environment              string
	Capability               Capability
	TLSCAFile                string
	TLSServerName            string
	RequestTimeout           time.Duration
	AllowInsecureDevelopment bool
}

func (VaultConfig) String() string   { return "VaultConfig{Address:[redacted]}" }
func (VaultConfig) GoString() string { return "keymanager.VaultConfig{Address:[redacted]}" }

var (
	vaultPathPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	vaultRequestIDPattern  = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)
	vaultCiphertextPattern = regexp.MustCompile(`^vault:v[1-9][0-9]*:[A-Za-z0-9_+/=-]+$`)
)

func (c VaultConfig) Validate() error {
	switch c.Environment {
	case "production", "development", "test":
	default:
		return errors.New("environment must be production, development, or test")
	}
	parsed, err := url.Parse(c.Address)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("Vault address is invalid")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return errors.New("Vault address must not contain a path")
	}
	if !vaultPathPattern.MatchString(c.TransitMount) || !vaultPathPattern.MatchString(c.KeyName) {
		return errors.New("Vault transit mount or key name is invalid")
	}
	if c.Namespace != "" && (strings.ContainsAny(c.Namespace, "\r\n\x00") || strings.HasPrefix(c.Namespace, "/") || strings.Contains(c.Namespace, "..")) {
		return errors.New("Vault namespace is invalid")
	}
	switch c.Capability {
	case WrapOnly, UnwrapOnly:
	case WrapUnwrap:
		if c.Environment == "production" {
			return errors.New("production Vault identity cannot combine wrap and unwrap capabilities")
		}
	default:
		return errors.New("Vault capability must be explicit")
	}
	if c.Environment == "production" {
		if parsed.Scheme != "https" || c.AllowInsecureDevelopment {
			return errors.New("production Vault requires HTTPS")
		}
	} else if parsed.Scheme != "https" && !(parsed.Scheme == "http" && c.AllowInsecureDevelopment) {
		return errors.New("Vault HTTP requires explicit development-only opt-in")
	} else if c.AllowInsecureDevelopment && c.Environment != "development" && c.Environment != "test" {
		return errors.New("Vault insecure mode is development-only")
	}
	if c.RequestTimeout < 0 || c.RequestTimeout > time.Minute {
		return errors.New("Vault request timeout is invalid")
	}
	return nil
}

type VaultTransit struct {
	baseURL     string
	mount       string
	keyName     string
	keyID       string
	namespace   string
	capability  Capability
	tokenSource TokenSource
	httpClient  *http.Client
}

func NewVaultTransit(config VaultConfig, tokenSource TokenSource) (*VaultTransit, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if tokenSource == nil {
		return nil, errors.New("Vault token source is required")
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 10 * time.Second
	}
	tlsConfig, err := vaultTLSConfig(config.TLSCAFile, config.TLSServerName)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: config.RequestTimeout, CheckRedirect: rejectVaultRedirect}
	address := strings.TrimRight(config.Address, "/")
	addressHash := sha256.Sum256([]byte(address))
	return &VaultTransit{
		baseURL: address, mount: config.TransitMount, keyName: config.KeyName,
		keyID:     "vault-transit:" + hex.EncodeToString(addressHash[:6]) + "/" + config.TransitMount + "/" + config.KeyName,
		namespace: config.Namespace, capability: config.Capability, tokenSource: tokenSource, httpClient: client,
	}, nil
}

func (v *VaultTransit) KeyID() string  { return v.keyID }
func (*VaultTransit) String() string   { return "VaultTransit{token:[redacted]}" }
func (*VaultTransit) GoString() string { return "keymanager.VaultTransit{token:[redacted]}" }

func (v *VaultTransit) WrapKey(ctx context.Context, dataKey, aad []byte) ([]byte, []byte, error) {
	if v.capability != WrapOnly && v.capability != WrapUnwrap {
		return nil, nil, errors.New("Vault identity is not permitted to wrap keys")
	}
	if len(dataKey) != DataKeyBytes || ValidateEncryptionContext(aad) != nil {
		return nil, nil, errors.New("data key and encryption context are required")
	}
	request := map[string]string{
		"plaintext": base64.StdEncoding.EncodeToString(dataKey),
		"context":   base64.StdEncoding.EncodeToString(aad),
	}
	var response struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := v.post(ctx, "encrypt", request, &response); err != nil {
		return nil, nil, err
	}
	if len(response.Data.Ciphertext) > maxVaultResponse || !vaultCiphertextPattern.MatchString(response.Data.Ciphertext) {
		return nil, nil, errors.New("Vault returned an invalid wrapped key")
	}
	return []byte(response.Data.Ciphertext), nil, nil
}

func (v *VaultTransit) UnwrapKey(ctx context.Context, wrappedKey, nonce, aad []byte) ([]byte, error) {
	if v.capability != UnwrapOnly && v.capability != WrapUnwrap {
		return nil, errors.New("Vault identity is not permitted to unwrap keys")
	}
	if len(nonce) != 0 || len(wrappedKey) == 0 || len(wrappedKey) > maxVaultResponse || ValidateEncryptionContext(aad) != nil || !vaultCiphertextPattern.Match(wrappedKey) {
		return nil, errors.New("wrapped key or encryption context is invalid")
	}
	request := map[string]string{
		"ciphertext": string(wrappedKey),
		"context":    base64.StdEncoding.EncodeToString(aad),
	}
	var response struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := v.post(ctx, "decrypt", request, &response); err != nil {
		return nil, err
	}
	dataKey, err := base64.StdEncoding.Strict().DecodeString(response.Data.Plaintext)
	if err != nil || len(dataKey) != DataKeyBytes {
		wipe(dataKey)
		return nil, errors.New("Vault returned an invalid data key")
	}
	return dataKey, nil
}

func (v *VaultTransit) post(ctx context.Context, operation string, payload any, destination any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return errors.New("encode Vault request")
	}
	defer wipe(body)
	requestURL := fmt.Sprintf("%s/v1/%s/%s/%s", v.baseURL, v.mount, operation, v.keyName)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("create Vault request")
	}
	token, err := v.tokenSource.Token(ctx)
	if err != nil {
		return errors.New("load Vault authentication token")
	}
	defer wipe(token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Vault-Token", string(token))
	if v.namespace != "" {
		request.Header.Set("X-Vault-Namespace", v.namespace)
	}
	response, err := v.httpClient.Do(request)
	request.Header.Del("X-Vault-Token")
	if err != nil {
		return errors.New("Vault request failed")
	}
	defer response.Body.Close()
	contents, readErr := io.ReadAll(io.LimitReader(response.Body, maxVaultResponse+1))
	if readErr != nil || len(contents) > maxVaultResponse {
		wipe(contents)
		return errors.New("Vault response is invalid or too large")
	}
	defer wipe(contents)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		requestID := response.Header.Get("X-Vault-Request")
		if vaultRequestIDPattern.MatchString(requestID) {
			return fmt.Errorf("Vault request rejected with status %d (request %s)", response.StatusCode, requestID)
		}
		return fmt.Errorf("Vault request rejected with status %d", response.StatusCode)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(destination); err != nil {
		return errors.New("decode Vault response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Vault response contains trailing data")
	}
	return nil
}

func rejectVaultRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func vaultTLSConfig(caFile, serverName string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caFile == "" {
		return config, nil
	}
	contents, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("read Vault TLS CA file")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("Vault TLS CA file has no certificates")
	}
	config.RootCAs = roots
	return config, nil
}

// MemoryManager is a test/development key wrapper. Production construction is
// rejected explicitly; keys are never persisted.
type MemoryManager struct {
	mu     sync.RWMutex
	keyID  string
	master []byte
}

func NewMemoryManager(environment, keyID string, master []byte) (*MemoryManager, error) {
	if environment != "development" && environment != "test" {
		return nil, errors.New("memory key manager is forbidden in production")
	}
	if keyID == "" || len(master) != DataKeyBytes {
		return nil, errors.New("memory key manager requires an id and 32-byte key")
	}
	return &MemoryManager{keyID: keyID, master: append([]byte(nil), master...)}, nil
}

func (m *MemoryManager) KeyID() string  { return m.keyID }
func (*MemoryManager) String() string   { return "MemoryManager{key:[redacted]}" }
func (*MemoryManager) GoString() string { return "keymanager.MemoryManager{key:[redacted]}" }

func (m *MemoryManager) WrapKey(_ context.Context, dataKey, aad []byte) ([]byte, []byte, error) {
	if len(dataKey) != DataKeyBytes || ValidateEncryptionContext(aad) != nil {
		return nil, nil, errors.New("data key and encryption context are required")
	}
	gcm, err := m.aead()
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, errors.New("generate wrapping nonce")
	}
	return gcm.Seal(nil, nonce, dataKey, aad), nonce, nil
}

func (m *MemoryManager) UnwrapKey(_ context.Context, wrappedKey, nonce, aad []byte) ([]byte, error) {
	gcm, err := m.aead()
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() || len(wrappedKey) < gcm.Overhead() || ValidateEncryptionContext(aad) != nil {
		return nil, errors.New("wrapped key is malformed")
	}
	plaintext, err := gcm.Open(nil, nonce, wrappedKey, aad)
	if err != nil || len(plaintext) != DataKeyBytes {
		wipe(plaintext)
		return nil, errors.New("wrapped key authentication failed")
	}
	return plaintext, nil
}

func (m *MemoryManager) aead() (cipher.AEAD, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	block, err := aes.NewCipher(m.master)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
