// Package identity verifies short-lived Ed25519 assertions from the trusted
// Web identity bridge. Assertions are consumed once and exchanged for an
// ordinary control-plane session; they are never accepted as API bearer tokens.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"vpsmanager/services/control-plane/internal/auth"
)

const (
	maxAssertionBytes = 12 << 10
	maxAssertionTTL   = 60 * time.Second
	defaultClockSkew  = 5 * time.Second
)

type Config struct {
	Issuer    string
	Audience  string
	KeyID     string
	PublicKey ed25519.PublicKey
	ClockSkew time.Duration
	Now       func() time.Time
}

// Claims is the complete trusted identity and authorization scope carried by
// the bridge. Unknown JSON fields are rejected so an unsupported security
// field cannot be silently ignored.
type Claims struct {
	Issuer   string    `json:"iss"`
	Audience string    `json:"aud"`
	Subject  string    `json:"sub"`
	Role     auth.Role `json:"role"`
	AllHosts bool      `json:"allHosts"`
	HostIDs  []string  `json:"hostIds,omitempty"`
	IssuedAt int64     `json:"iat"`
	Expires  int64     `json:"exp"`
	JWTID    string    `json:"jti"`
}

type header struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

// Verifier is race-safe. It retains only SHA-256 digests of consumed JWT IDs
// until the assertions expire.
type Verifier struct {
	issuer   string
	audience string
	keyID    string
	key      ed25519.PublicKey
	skew     time.Duration
	now      func() time.Time
	mu       sync.Mutex
	consumed map[[sha256.Size]byte]time.Time
}

func NewVerifier(config Config) (*Verifier, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.Audience = strings.TrimSpace(config.Audience)
	config.KeyID = strings.TrimSpace(config.KeyID)
	if config.Issuer == "" || len(config.Issuer) > 256 || config.Audience == "" || len(config.Audience) > 256 {
		return nil, errors.New("identity issuer and audience are required")
	}
	if config.KeyID == "" || len(config.KeyID) > 128 || strings.ContainsAny(config.KeyID, "\r\n") {
		return nil, errors.New("identity key id is invalid")
	}
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("identity Ed25519 public key is invalid")
	}
	if config.ClockSkew == 0 {
		config.ClockSkew = defaultClockSkew
	}
	if config.ClockSkew < 0 || config.ClockSkew > 15*time.Second {
		return nil, errors.New("identity clock skew must be between zero and 15 seconds")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Verifier{
		issuer: config.Issuer, audience: config.Audience, keyID: config.KeyID,
		key: append(ed25519.PublicKey(nil), config.PublicKey...), skew: config.ClockSkew,
		now: config.Now, consumed: make(map[[sha256.Size]byte]time.Time),
	}, nil
}

func (v *Verifier) Verify(assertion string) (auth.Principal, error) {
	if len(assertion) == 0 || len(assertion) > maxAssertionBytes || strings.TrimSpace(assertion) != assertion {
		return auth.Principal{}, errors.New("identity assertion is invalid")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return auth.Principal{}, errors.New("identity assertion is malformed")
	}
	headerBytes, err := decodeSegment(parts[0], 1024)
	if err != nil {
		return auth.Principal{}, errors.New("identity assertion header is invalid")
	}
	var parsedHeader header
	if err := decodeOne(headerBytes, &parsedHeader); err != nil || parsedHeader.Algorithm != "EdDSA" || parsedHeader.Type != "VPSMGR+JWT" || !constantStringEqual(parsedHeader.KeyID, v.keyID) {
		return auth.Principal{}, errors.New("identity assertion header is not accepted")
	}
	signature, err := decodeSegment(parts[2], ed25519.SignatureSize)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return auth.Principal{}, errors.New("identity assertion signature is invalid")
	}
	if !ed25519.Verify(v.key, []byte(parts[0]+"."+parts[1]), signature) {
		return auth.Principal{}, errors.New("identity assertion signature verification failed")
	}
	payload, err := decodeSegment(parts[1], 8<<10)
	if err != nil {
		return auth.Principal{}, errors.New("identity assertion payload is invalid")
	}
	var claims Claims
	if err := decodeOne(payload, &claims); err != nil {
		return auth.Principal{}, errors.New("identity assertion claims are invalid")
	}
	if err := v.validateClaims(claims); err != nil {
		return auth.Principal{}, err
	}
	if !v.consume(claims.JWTID, time.Unix(claims.Expires, 0)) {
		return auth.Principal{}, errors.New("identity assertion was already consumed")
	}
	return auth.Principal{
		Subject: claims.Subject, Role: claims.Role, AllHosts: claims.AllHosts,
		HostIDs: append([]string(nil), claims.HostIDs...),
	}, nil
}

func (v *Verifier) validateClaims(claims Claims) error {
	if !constantStringEqual(claims.Issuer, v.issuer) || !constantStringEqual(claims.Audience, v.audience) {
		return errors.New("identity assertion issuer or audience is not accepted")
	}
	if strings.TrimSpace(claims.Subject) != claims.Subject || len(claims.Subject) < 1 || len(claims.Subject) > 128 || !auth.ValidRole(claims.Role) {
		return errors.New("identity assertion principal is invalid")
	}
	if strings.TrimSpace(claims.JWTID) != claims.JWTID || len(claims.JWTID) < 16 || len(claims.JWTID) > 128 {
		return errors.New("identity assertion id is invalid")
	}
	if claims.AllHosts && len(claims.HostIDs) != 0 || len(claims.HostIDs) > 256 {
		return errors.New("identity assertion host scope is invalid")
	}
	seen := make(map[string]struct{}, len(claims.HostIDs))
	for _, hostID := range claims.HostIDs {
		if !strings.HasPrefix(hostID, "host_") || len(hostID) > 128 || strings.TrimSpace(hostID) != hostID {
			return errors.New("identity assertion host scope is invalid")
		}
		if _, exists := seen[hostID]; exists {
			return errors.New("identity assertion host scope contains duplicates")
		}
		seen[hostID] = struct{}{}
	}
	issued := time.Unix(claims.IssuedAt, 0)
	expires := time.Unix(claims.Expires, 0)
	now := v.now()
	if claims.IssuedAt <= 0 || claims.Expires <= 0 || !expires.After(issued) || expires.Sub(issued) > maxAssertionTTL {
		return errors.New("identity assertion lifetime is invalid")
	}
	if issued.After(now.Add(v.skew)) || !expires.After(now.Add(-v.skew)) {
		return errors.New("identity assertion is outside its validity window")
	}
	return nil
}

func (v *Verifier) consume(id string, expires time.Time) bool {
	digest := sha256.Sum256([]byte(id))
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for key, deadline := range v.consumed {
		if !deadline.After(now.Add(-v.skew)) {
			delete(v.consumed, key)
		}
	}
	if _, exists := v.consumed[digest]; exists {
		return false
	}
	v.consumed[digest] = expires.Add(v.skew)
	return true
}

func decodeSegment(value string, limit int) ([]byte, error) {
	if strings.Contains(value, "=") {
		return nil, errors.New("padded base64url is not accepted")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) > limit {
		return nil, errors.New("base64url segment is invalid")
	}
	return decoded, nil
}

func decodeOne(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func constantStringEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
