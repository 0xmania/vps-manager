// Package auth implements the temporary, explicit development-session provider
// and the authorization policy shared by HTTP handlers.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"
)

type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
	RoleAuditor  Role = "auditor"
)

type Permission string

const (
	HostsRead             Permission = "hosts:read"
	HostsWrite            Permission = "hosts:write"
	HostsDelete           Permission = "hosts:delete"
	HostKeyPin            Permission = "host_key:pin"
	HostKeyReplace        Permission = "host_key:replace"
	CredentialsManage     Permission = "credentials:manage"
	JobsRead              Permission = "jobs:read"
	SnapshotsRun          Permission = "snapshots:run"
	CommandsRun           Permission = "commands:run"
	AnomalyScansRun       Permission = "anomaly_scans:run"
	TerminalSessionsOpen  Permission = "terminal_sessions:open"
	RunbooksPreview       Permission = "runbooks:preview"
	RunbooksExecute       Permission = "runbooks:execute"
	JobsCancel            Permission = "jobs:cancel"
	WorkersRead           Permission = "cloudflare_workers:read"
	WorkersWrite          Permission = "cloudflare_workers:write"
	WorkerTokensManage    Permission = "cloudflare_worker_tokens:manage"
	WorkerDeploymentsPlan Permission = "cloudflare_worker_deployments:plan"
	WorkerDeploymentsRun  Permission = "cloudflare_worker_deployments:execute"
	AuditRead             Permission = "audit:read"
	SessionRevokeSelf     Permission = "session:revoke_self"
)

var grants = map[Role]map[Permission]struct{}{
	RoleViewer: {
		HostsRead: {}, JobsRead: {}, WorkersRead: {}, SessionRevokeSelf: {},
	},
	RoleOperator: {
		HostsRead: {}, HostsWrite: {}, HostKeyPin: {}, JobsRead: {}, SnapshotsRun: {}, CommandsRun: {},
		AnomalyScansRun: {}, TerminalSessionsOpen: {}, RunbooksPreview: {}, RunbooksExecute: {}, JobsCancel: {},
		WorkersRead: {}, WorkersWrite: {}, WorkerDeploymentsPlan: {}, SessionRevokeSelf: {},
	},
	RoleAdmin: {
		HostsRead: {}, HostsWrite: {}, HostsDelete: {}, HostKeyPin: {}, HostKeyReplace: {},
		CredentialsManage: {}, JobsRead: {}, SnapshotsRun: {}, CommandsRun: {}, AnomalyScansRun: {},
		TerminalSessionsOpen: {}, RunbooksPreview: {}, RunbooksExecute: {}, JobsCancel: {},
		WorkersRead: {}, WorkersWrite: {}, WorkerTokensManage: {}, WorkerDeploymentsPlan: {}, WorkerDeploymentsRun: {},
		AuditRead: {}, SessionRevokeSelf: {},
	},
	RoleAuditor: {
		HostsRead: {}, JobsRead: {}, WorkersRead: {}, AuditRead: {}, SessionRevokeSelf: {},
	},
}

func ValidRole(role Role) bool {
	_, ok := grants[role]
	return ok
}

func Allowed(role Role, permission Permission) bool {
	permissions, ok := grants[role]
	if !ok {
		return false
	}
	_, ok = permissions[permission]
	return ok
}

type Principal struct {
	Subject   string   `json:"subject"`
	Role      Role     `json:"role"`
	AllHosts  bool     `json:"allHosts"`
	HostIDs   []string `json:"hostIds,omitempty"`
	SessionID string   `json:"-"`
}

type Session struct {
	Principal Principal `json:"principal"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type storedSession struct {
	Session
	tokenHash [sha256.Size]byte
	revoked   bool
}

// Sessions stores only SHA-256 token digests, not reusable bearer tokens.
type Sessions struct {
	mu       sync.RWMutex
	sessions map[[sha256.Size]byte]storedSession
	now      func() time.Time
}

func NewSessions() *Sessions {
	return &Sessions{sessions: make(map[[sha256.Size]byte]storedSession), now: time.Now}
}

func (s *Sessions) Issue(principal Principal, ttl time.Duration) (token string, session Session, err error) {
	if strings.TrimSpace(principal.Subject) == "" || !ValidRole(principal.Role) {
		return "", Session{}, errors.New("valid session subject and role are required")
	}
	if ttl <= 0 || ttl > 8*time.Hour {
		return "", Session{}, errors.New("session ttl must be between zero and eight hours")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", Session{}, err
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	sessionIDRaw := make([]byte, 16)
	if _, err := rand.Read(sessionIDRaw); err != nil {
		return "", Session{}, err
	}
	principal.SessionID = "session_" + base64.RawURLEncoding.EncodeToString(sessionIDRaw)
	principal.HostIDs = deduplicate(principal.HostIDs)
	hash := sha256.Sum256([]byte(token))
	session = Session{Principal: principal, ExpiresAt: s.now().UTC().Add(ttl)}
	s.mu.Lock()
	s.sessions[hash] = storedSession{Session: session, tokenHash: hash}
	s.mu.Unlock()
	return token, session, nil
}

func (s *Sessions) Authenticate(authorization string) (Principal, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authorization, prefix) {
		return Principal{}, false
	}
	token := strings.TrimSpace(strings.TrimPrefix(authorization, prefix))
	if token == "" {
		return Principal{}, false
	}
	hash := sha256.Sum256([]byte(token))
	s.mu.RLock()
	stored, ok := s.sessions[hash]
	s.mu.RUnlock()
	if !ok || stored.revoked || subtle.ConstantTimeCompare(hash[:], stored.tokenHash[:]) != 1 {
		return Principal{}, false
	}
	if !s.now().Before(stored.ExpiresAt) {
		s.mu.Lock()
		delete(s.sessions, hash)
		s.mu.Unlock()
		return Principal{}, false
	}
	return stored.Principal, true
}

func (s *Sessions) Revoke(authorization string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(authorization, prefix) {
		return false
	}
	hash := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(authorization, prefix))))
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.sessions[hash]
	if !ok {
		return false
	}
	stored.revoked = true
	s.sessions[hash] = stored
	return true
}

// AuthorizeSession re-checks revocation, expiry, role, and object scope. It is
// intended for queued work immediately before an external side effect.
func (s *Sessions) AuthorizeSession(sessionID string, permission Permission, hostID string) (Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, stored := range s.sessions {
		if stored.Principal.SessionID != sessionID || stored.revoked || !s.now().Before(stored.ExpiresAt) {
			continue
		}
		principal := stored.Principal
		return principal, Allowed(principal.Role, permission) && CanAccessHost(principal, hostID)
	}
	return Principal{}, false
}

func CanAccessHost(principal Principal, hostID string) bool {
	if principal.AllHosts {
		return true
	}
	for _, allowed := range principal.HostIDs {
		if subtle.ConstantTimeCompare([]byte(allowed), []byte(hostID)) == 1 && len(allowed) == len(hostID) {
			return true
		}
	}
	return false
}

func deduplicate(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// SecureTokenEqual compares bootstrap tokens without a timing-sensitive string
// equality operation. Both values must be at least 32 bytes.
func SecureTokenEqual(got, want string) bool {
	if len(got) < 32 || len(want) < 32 || len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
