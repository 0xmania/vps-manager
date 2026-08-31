// Package stepup issues short-lived, single-use authorization tickets after an
// external factor verifier has confirmed recent strong authentication.
package stepup

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	defaultTTL       = 2 * time.Minute
	maximumTTL       = 5 * time.Minute
	maximumFreshness = 2 * time.Minute
	defaultCapacity  = 4096
)

type Action string

const (
	ActionWebSSHStart        Action = "web_ssh_start"
	ActionCredentialRotate   Action = "credential_rotate"
	ActionCredentialDelete   Action = "credential_delete"
	ActionWorkerDeploy       Action = "worker_deploy"
	ActionWorkerRollback     Action = "worker_rollback"
	ActionServiceRestart     Action = "service_restart"
	ActionProcessTerminate   Action = "process_terminate"
	ActionHostReboot         Action = "host_reboot"
	ActionBreakglassActivate Action = "breakglass_activate"
)

var allowedActions = map[Action]struct{}{
	ActionWebSSHStart: {}, ActionCredentialRotate: {}, ActionCredentialDelete: {},
	ActionWorkerDeploy: {}, ActionWorkerRollback: {}, ActionServiceRestart: {},
	ActionProcessTerminate: {}, ActionHostReboot: {}, ActionBreakglassActivate: {},
}

type VerifiedFactor struct {
	Subject        string
	SessionID      string
	VerifiedAt     time.Time
	AssuranceLevel int
	Methods        []string
}

type FactorVerifier interface {
	Verify(context.Context, string, string, []byte) (VerifiedFactor, error)
}

type IssueRequest struct {
	Subject          string
	SessionID        string
	Action           Action
	TargetID         string
	ParametersSHA256 string
	Reason           string
	Assertion        []byte
	TTL              time.Duration
}

type Binding struct {
	Subject          string
	SessionID        string
	Action           Action
	TargetID         string
	ParametersSHA256 string
	Reason           string
}

type Ticket struct {
	Value     string    `json:"ticket"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (Ticket) String() string   { return "[step-up ticket]" }
func (Ticket) GoString() string { return "stepup.Ticket{[redacted]}" }

type Config struct {
	Verifier FactorVerifier
	Capacity int
	Now      func() time.Time
}

type entry struct {
	bindingDigest [sha256.Size]byte
	expiresAt     time.Time
	sessionDigest [sha256.Size]byte
}

type Manager struct {
	verifier FactorVerifier
	capacity int
	now      func() time.Time
	mu       sync.Mutex
	tickets  map[[sha256.Size]byte]entry
}

func New(config Config) (*Manager, error) {
	if config.Verifier == nil {
		return nil, errors.New("step-up factor verifier is required")
	}
	if config.Capacity == 0 {
		config.Capacity = defaultCapacity
	}
	if config.Capacity < 1 || config.Capacity > 65536 {
		return nil, errors.New("step-up ticket capacity is invalid")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Manager{
		verifier: config.Verifier, capacity: config.Capacity, now: config.Now,
		tickets: make(map[[sha256.Size]byte]entry),
	}, nil
}

func (m *Manager) Issue(ctx context.Context, request IssueRequest) (Ticket, error) {
	if ctx == nil {
		wipe(request.Assertion)
		return Ticket{}, errors.New("step-up context is required")
	}
	defer wipe(request.Assertion)
	if err := validateBinding(Binding{
		Subject: request.Subject, SessionID: request.SessionID, Action: request.Action,
		TargetID: request.TargetID, ParametersSHA256: request.ParametersSHA256, Reason: request.Reason,
	}); err != nil {
		return Ticket{}, err
	}
	if len(request.Assertion) < 16 || len(request.Assertion) > 16<<10 {
		return Ticket{}, errors.New("step-up assertion is invalid")
	}
	if request.TTL == 0 {
		request.TTL = defaultTTL
	}
	if request.TTL <= 0 || request.TTL > maximumTTL {
		return Ticket{}, errors.New("step-up ticket lifetime is invalid")
	}
	verified, err := m.verifier.Verify(ctx, request.Subject, request.SessionID, request.Assertion)
	if err != nil {
		return Ticket{}, errors.New("step-up verification failed")
	}
	now := m.now().UTC()
	if !constantEqual(verified.Subject, request.Subject) || !constantEqual(verified.SessionID, request.SessionID) ||
		verified.AssuranceLevel < 2 || len(verified.Methods) == 0 || verified.VerifiedAt.IsZero() ||
		verified.VerifiedAt.After(now.Add(15*time.Second)) || now.Sub(verified.VerifiedAt) > maximumFreshness {
		return Ticket{}, errors.New("step-up verification is not fresh or sufficiently strong")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Ticket{}, errors.New("generate step-up ticket")
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	ticketDigest := sha256.Sum256(raw)
	wipe(raw)
	binding := Binding{
		Subject: request.Subject, SessionID: request.SessionID, Action: request.Action,
		TargetID: request.TargetID, ParametersSHA256: request.ParametersSHA256, Reason: request.Reason,
	}
	stored := entry{
		bindingDigest: digestBinding(binding), expiresAt: now.Add(request.TTL),
		sessionDigest: sha256.Sum256([]byte(request.SessionID)),
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	if len(m.tickets) >= m.capacity {
		return Ticket{}, errors.New("step-up ticket capacity reached")
	}
	if _, exists := m.tickets[ticketDigest]; exists {
		return Ticket{}, errors.New("step-up ticket collision")
	}
	m.tickets[ticketDigest] = stored
	return Ticket{Value: value, ExpiresAt: stored.expiresAt}, nil
}

// Consume removes a ticket before checking its binding. A leaked ticket cannot
// be probed against multiple targets or parameters.
func (m *Manager) Consume(value string, binding Binding) bool {
	if len(value) < 32 || len(value) > 128 || validateBinding(binding) != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 {
		wipe(raw)
		return false
	}
	digest := sha256.Sum256(raw)
	wipe(raw)
	now := m.now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	stored, exists := m.tickets[digest]
	if !exists {
		return false
	}
	delete(m.tickets, digest)
	if !stored.expiresAt.After(now) {
		return false
	}
	got := digestBinding(binding)
	return subtle.ConstantTimeCompare(got[:], stored.bindingDigest[:]) == 1
}

func (m *Manager) RevokeSession(sessionID string) int {
	digest := sha256.Sum256([]byte(sessionID))
	removed := 0
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, stored := range m.tickets {
		if subtle.ConstantTimeCompare(digest[:], stored.sessionDigest[:]) == 1 {
			delete(m.tickets, key)
			removed++
		}
	}
	return removed
}

// DigestParameters computes the required lowercase digest over canonical,
// secret-free action parameters.
func DigestParameters(canonical []byte) (string, error) {
	if len(canonical) == 0 || len(canonical) > 64<<10 {
		return "", errors.New("canonical parameters are invalid")
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

func validateBinding(binding Binding) error {
	if strings.TrimSpace(binding.Subject) != binding.Subject || len(binding.Subject) < 1 || len(binding.Subject) > 128 ||
		strings.TrimSpace(binding.SessionID) != binding.SessionID || len(binding.SessionID) < 8 || len(binding.SessionID) > 128 ||
		strings.TrimSpace(binding.TargetID) != binding.TargetID || len(binding.TargetID) < 1 || len(binding.TargetID) > 128 {
		return errors.New("step-up principal or target binding is invalid")
	}
	if _, ok := allowedActions[binding.Action]; !ok {
		return errors.New("step-up action is invalid")
	}
	if len(binding.ParametersSHA256) != sha256.Size*2 || strings.ToLower(binding.ParametersSHA256) != binding.ParametersSHA256 {
		return errors.New("step-up parameter digest is invalid")
	}
	if _, err := hex.DecodeString(binding.ParametersSHA256); err != nil {
		return errors.New("step-up parameter digest is invalid")
	}
	if strings.TrimSpace(binding.Reason) != binding.Reason || len(binding.Reason) < 8 || len(binding.Reason) > 500 {
		return errors.New("step-up reason is invalid")
	}
	for _, character := range binding.Reason {
		if character == '\n' || character == '\r' || character == 0 || unicode.IsControl(character) {
			return errors.New("step-up reason contains control characters")
		}
	}
	return nil
}

func digestBinding(binding Binding) [sha256.Size]byte {
	return sha256.Sum256([]byte(strings.Join([]string{
		binding.Subject, binding.SessionID, string(binding.Action), binding.TargetID,
		binding.ParametersSHA256, binding.Reason,
	}, "\x00")))
}

func (m *Manager) pruneLocked(now time.Time) {
	for key, stored := range m.tickets {
		if !stored.expiresAt.After(now) {
			delete(m.tickets, key)
		}
	}
}

func constantEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func wipe(value []byte) {
	clear(value)
}
