package connectorprotocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	HeaderProtocol  = "X-Vpsmgr-Protocol"
	HeaderKeyID     = "X-Vpsmgr-Key-Id"
	HeaderTimestamp = "X-Vpsmgr-Timestamp"
	HeaderNonce     = "X-Vpsmgr-Nonce"
	HeaderSignature = "X-Vpsmgr-Signature"

	minimumKeyBytes = 32
	defaultMaxSkew  = 30 * time.Second
	defaultNonces   = 10_000
)

type SignerConfig struct {
	KeyID string
	Key   []byte
	Now   func() time.Time
}

type Signer struct {
	keyID string
	key   []byte
	now   func() time.Time
}

func NewSigner(cfg SignerConfig) (*Signer, error) {
	if err := validateKey(cfg.KeyID, cfg.Key); err != nil {
		return nil, err
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Signer{keyID: cfg.KeyID, key: append([]byte(nil), cfg.Key...), now: now}, nil
}

// Sign adds protocol authentication headers. The caller must pass exactly the
// byte sequence that will be used as the HTTP request body.
func (s *Signer) Sign(request *http.Request, body []byte) error {
	if request == nil || request.URL == nil {
		return errors.New("request URL is required")
	}
	nonceBytes := make([]byte, 24)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generate request nonce: %w", err)
	}
	timestamp := strconv.FormatInt(s.now().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	signature := computeMAC(s.key, canonicalRequest(request.Method, request.URL.RequestURI(), s.keyID, timestamp, nonce, body))
	request.Header.Set(HeaderProtocol, ProtocolVersion)
	request.Header.Set(HeaderKeyID, s.keyID)
	request.Header.Set(HeaderTimestamp, timestamp)
	request.Header.Set(HeaderNonce, nonce)
	request.Header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

type VerifierConfig struct {
	KeyID     string
	Key       []byte
	MaxSkew   time.Duration
	MaxNonces int
	Now       func() time.Time
}

type Verifier struct {
	keyID     string
	key       []byte
	maxSkew   time.Duration
	maxNonces int
	now       func() time.Time
	mu        sync.Mutex
	nonces    map[string]time.Time
}

func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	if err := validateKey(cfg.KeyID, cfg.Key); err != nil {
		return nil, err
	}
	if cfg.MaxSkew <= 0 {
		cfg.MaxSkew = defaultMaxSkew
	}
	if cfg.MaxSkew > 5*time.Minute {
		return nil, errors.New("HMAC time window must not exceed five minutes")
	}
	if cfg.MaxNonces <= 0 {
		cfg.MaxNonces = defaultNonces
	}
	if cfg.MaxNonces > 1_000_000 {
		return nil, errors.New("nonce cache limit is too large")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{
		keyID: cfg.KeyID, key: append([]byte(nil), cfg.Key...), maxSkew: cfg.MaxSkew,
		maxNonces: cfg.MaxNonces, now: cfg.Now, nonces: make(map[string]time.Time),
	}, nil
}

type VerifyError struct{ Code string }

func (e *VerifyError) Error() string { return "connector authentication failed: " + e.Code }

// Verify checks protocol version, timestamp, nonce, body integrity and replay.
// A nonce is recorded only after a valid MAC, preventing unauthenticated cache
// poisoning. Exactly one value is required for every authentication header.
func (v *Verifier) Verify(request *http.Request, body []byte) error {
	if request == nil || request.URL == nil {
		return verifyError("invalid_request")
	}
	protocol, ok := singleHeader(request.Header, HeaderProtocol)
	if !ok || protocol != ProtocolVersion {
		return verifyError("invalid_protocol")
	}
	keyID, ok := singleHeader(request.Header, HeaderKeyID)
	if !ok || keyID != v.keyID {
		return verifyError("invalid_key_id")
	}
	timestampText, ok := singleHeader(request.Header, HeaderTimestamp)
	if !ok {
		return verifyError("invalid_timestamp")
	}
	timestamp, err := strconv.ParseInt(timestampText, 10, 64)
	if err != nil {
		return verifyError("invalid_timestamp")
	}
	now := v.now()
	requestTime := time.Unix(timestamp, 0)
	if requestTime.Before(now.Add(-v.maxSkew)) || requestTime.After(now.Add(v.maxSkew)) {
		return verifyError("stale_request")
	}
	nonce, ok := singleHeader(request.Header, HeaderNonce)
	if !ok {
		return verifyError("invalid_nonce")
	}
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(nonceBytes) < 16 || len(nonceBytes) > 64 {
		return verifyError("invalid_nonce")
	}
	signatureText, ok := singleHeader(request.Header, HeaderSignature)
	if !ok {
		return verifyError("invalid_signature")
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText)
	if err != nil || len(signature) != sha256.Size {
		return verifyError("invalid_signature")
	}
	want := computeMAC(v.key, canonicalRequest(request.Method, request.URL.RequestURI(), keyID, timestampText, nonce, body))
	if subtle.ConstantTimeCompare(want, signature) != 1 {
		return verifyError("invalid_signature")
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	for cachedNonce, expiresAt := range v.nonces {
		if !expiresAt.After(now) {
			delete(v.nonces, cachedNonce)
		}
	}
	cacheKey := keyID + "\x00" + nonce
	if _, exists := v.nonces[cacheKey]; exists {
		return verifyError("replayed_request")
	}
	if len(v.nonces) >= v.maxNonces {
		return verifyError("replay_cache_full")
	}
	v.nonces[cacheKey] = now.Add(2 * v.maxSkew)
	return nil
}

func canonicalRequest(method, requestURI, keyID, timestamp, nonce string, body []byte) []byte {
	digest := sha256.Sum256(body)
	canonical := strings.Join([]string{
		"VPSMGR-HMAC-SHA256", ProtocolVersion, keyID, timestamp, nonce,
		strings.ToUpper(method), requestURI, hex.EncodeToString(digest[:]),
	}, "\n")
	return []byte(canonical)
}

func computeMAC(key, canonical []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(canonical)
	return mac.Sum(nil)
}

func validateKey(keyID string, key []byte) error {
	if len(keyID) < 1 || len(keyID) > 64 {
		return errors.New("HMAC key ID must contain 1 to 64 characters")
	}
	for _, value := range keyID {
		if !((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
			(value >= '0' && value <= '9') || value == '.' || value == '_' || value == '-') {
			return errors.New("HMAC key ID contains an invalid character")
		}
	}
	if len(key) < minimumKeyBytes {
		return fmt.Errorf("HMAC key must contain at least %d decoded bytes", minimumKeyBytes)
	}
	return nil
}

func singleHeader(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" || values[0] != strings.TrimSpace(values[0]) {
		return "", false
	}
	return values[0], true
}

func verifyError(code string) error { return &VerifyError{Code: code} }
