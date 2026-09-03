package persistence

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrLeaseHeld = errors.New("task lease is already held")
	ErrLeaseLost = errors.New("task lease is no longer owned")
)

const maxCoordinatorReferenceBytes = 512

type Lease struct {
	key      string
	token    string
	expires  time.Time
	resource string
}

func (Lease) String() string         { return "Lease{token:[redacted]}" }
func (Lease) GoString() string       { return "persistence.Lease{token:[redacted]}" }
func (l Lease) Resource() string     { return l.resource }
func (l Lease) ExpiresAt() time.Time { return l.expires }

type Coordinator interface {
	AcquireLease(context.Context, string, string, time.Duration) (Lease, error)
	RenewLease(context.Context, Lease, time.Duration) (Lease, error)
	ReleaseLease(context.Context, Lease) error
	PutIdempotency(context.Context, string, string, time.Duration) (bool, error)
	GetIdempotency(context.Context, string) (string, bool, error)
	RequestCancellation(context.Context, string, time.Duration) error
	CancellationRequested(context.Context, string) (bool, error)
}

type RedisConfig struct {
	URL                      string
	InstallationID           string
	Environment              string
	ExpectedUsername         string
	TLSCAFile                string
	TLSServerName            string
	AllowInsecureDevelopment bool
}

func (RedisConfig) String() string   { return "RedisConfig{URL:[redacted]}" }
func (RedisConfig) GoString() string { return "persistence.RedisConfig{URL:[redacted]}" }

func (c RedisConfig) Validate() error {
	if err := validateEnvironment(c.Environment); err != nil {
		return err
	}
	if err := validateIdentifier("installation id", c.InstallationID); err != nil {
		return err
	}
	if strings.TrimSpace(c.URL) == "" {
		return errors.New("Redis URL is required")
	}
	secure := strings.HasPrefix(c.URL, "rediss://")
	insecure := strings.HasPrefix(c.URL, "redis://")
	if !secure && !insecure {
		return errors.New("Redis URL must use rediss scheme")
	}
	if c.Environment == "production" {
		if !secure || c.AllowInsecureDevelopment {
			return errors.New("production Redis requires TLS")
		}
		if c.ExpectedUsername == "" || c.ExpectedUsername == "default" {
			return errors.New("production Redis requires a dedicated ACL username")
		}
	} else if insecure && !c.AllowInsecureDevelopment {
		return errors.New("plaintext Redis requires explicit development-only opt-in")
	} else if c.AllowInsecureDevelopment && c.Environment != "development" && c.Environment != "test" {
		return errors.New("Redis insecure mode is development-only")
	}
	return nil
}

type RedisCoordinator struct {
	client redis.UniversalClient
	prefix string
}

func (*RedisCoordinator) String() string   { return "RedisCoordinator{client:[redacted]}" }
func (*RedisCoordinator) GoString() string { return "persistence.RedisCoordinator{client:[redacted]}" }

func OpenRedis(ctx context.Context, config RedisConfig) (*RedisCoordinator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	options, err := redis.ParseURL(config.URL)
	if err != nil {
		return nil, errors.New("parse Redis configuration")
	}
	if strings.HasPrefix(config.URL, "rediss://") {
		tlsConfig, err := secureTLSConfig(config.TLSCAFile, config.TLSServerName)
		if err != nil {
			return nil, err
		}
		options.TLSConfig = tlsConfig
	}
	if config.ExpectedUsername != "" && options.Username != config.ExpectedUsername {
		return nil, errors.New("Redis URL username does not match expected ACL identity")
	}
	client := redis.NewClient(options)
	coordinator := &RedisCoordinator{client: client, prefix: coordinatorPrefix(config.InstallationID)}
	if err := coordinator.VerifyRuntime(ctx); err != nil {
		_ = client.Close()
		return nil, err
	}
	return coordinator, nil
}

func (r *RedisCoordinator) Close() error { return r.client.Close() }

// VerifyRuntime proves the identity has only the primitives the adapter needs.
// The deployment ACL must still explicitly deny administrative commands.
func (r *RedisCoordinator) VerifyRuntime(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return errors.New("ping Redis")
	}
	probe := "startup_probe_" + randomReference()
	lease, err := r.AcquireLease(ctx, probe, "startup_probe", time.Minute)
	if err != nil {
		return errors.New("verify Redis lease acquisition")
	}
	defer r.client.Del(context.WithoutCancel(ctx), lease.key)
	if _, err := r.RenewLease(ctx, lease, time.Minute); err != nil {
		return errors.New("verify Redis lease renewal")
	}
	if err := r.ReleaseLease(ctx, lease); err != nil {
		return errors.New("verify Redis lease release")
	}
	cancelKey := r.key("cancel", probe)
	defer r.client.Del(context.WithoutCancel(ctx), cancelKey)
	if err := r.RequestCancellation(ctx, probe, time.Minute); err != nil {
		return errors.New("verify Redis cancellation write")
	}
	requested, err := r.CancellationRequested(ctx, probe)
	if err != nil || !requested {
		return errors.New("verify Redis cancellation read")
	}
	return nil
}

var renewLeaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0`)

var releaseLeaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0`)

func (r *RedisCoordinator) AcquireLease(ctx context.Context, resource, owner string, ttl time.Duration) (Lease, error) {
	if err := validateCoordinatorInput(resource, owner, ttl); err != nil {
		return Lease{}, err
	}
	token, err := randomToken()
	if err != nil {
		return Lease{}, errors.New("generate task lease token")
	}
	key := r.key("lease", resource)
	ok, err := r.client.SetNX(ctx, key, token, ttl).Result()
	if err != nil {
		return Lease{}, errors.New("acquire Redis task lease")
	}
	if !ok {
		return Lease{}, ErrLeaseHeld
	}
	return Lease{key: key, token: token, resource: resource, expires: time.Now().UTC().Add(ttl)}, nil
}

func (r *RedisCoordinator) RenewLease(ctx context.Context, lease Lease, ttl time.Duration) (Lease, error) {
	if lease.key == "" || lease.token == "" || !strings.HasPrefix(lease.key, r.prefix+"lease:") || ttl < time.Second || ttl > 24*time.Hour {
		return Lease{}, errors.New("lease and positive TTL are required")
	}
	result, err := renewLeaseScript.Run(ctx, r.client, []string{lease.key}, lease.token, ttl.Milliseconds()).Int64()
	if err != nil {
		return Lease{}, errors.New("renew Redis task lease")
	}
	if result != 1 {
		return Lease{}, ErrLeaseLost
	}
	lease.expires = time.Now().UTC().Add(ttl)
	return lease, nil
}

func (r *RedisCoordinator) ReleaseLease(ctx context.Context, lease Lease) error {
	if lease.key == "" || lease.token == "" || !strings.HasPrefix(lease.key, r.prefix+"lease:") {
		return errors.New("lease is required")
	}
	result, err := releaseLeaseScript.Run(ctx, r.client, []string{lease.key}, lease.token).Int64()
	if err != nil {
		return errors.New("release Redis task lease")
	}
	if result != 1 {
		return ErrLeaseLost
	}
	return nil
}

func (r *RedisCoordinator) PutIdempotency(ctx context.Context, key, resultReference string, ttl time.Duration) (bool, error) {
	if err := validateCoordinatorInput(key, resultReference, ttl); err != nil {
		return false, err
	}
	if err := validateIdentifier("idempotency result reference", resultReference); err != nil {
		return false, err
	}
	created, err := r.client.SetNX(ctx, r.key("idempotency", key), resultReference, ttl).Result()
	if err != nil {
		return false, errors.New("write Redis idempotency record")
	}
	return created, nil
}

func (r *RedisCoordinator) GetIdempotency(ctx context.Context, key string) (string, bool, error) {
	if err := validateReference(key); err != nil {
		return "", false, err
	}
	value, err := r.client.Get(ctx, r.key("idempotency", key)).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, errors.New("read Redis idempotency record")
	}
	return value, true, nil
}

func (r *RedisCoordinator) RequestCancellation(ctx context.Context, jobID string, ttl time.Duration) error {
	if err := validateCoordinatorInput(jobID, jobID, ttl); err != nil {
		return err
	}
	if err := r.client.Set(ctx, r.key("cancel", jobID), "1", ttl).Err(); err != nil {
		return errors.New("write Redis cancellation signal")
	}
	return nil
}

func (r *RedisCoordinator) CancellationRequested(ctx context.Context, jobID string) (bool, error) {
	if err := validateReference(jobID); err != nil {
		return false, err
	}
	value, err := r.client.Exists(ctx, r.key("cancel", jobID)).Result()
	if err != nil {
		return false, errors.New("read Redis cancellation signal")
	}
	return value == 1, nil
}

func (r *RedisCoordinator) key(kind, reference string) string {
	hash := sha256.Sum256([]byte(reference))
	return r.prefix + kind + ":" + hex.EncodeToString(hash[:])
}

func coordinatorPrefix(installationID string) string {
	hash := sha256.Sum256([]byte(installationID))
	return "vpsmgr:" + hex.EncodeToString(hash[:8]) + ":"
}

func validateCoordinatorInput(first, second string, ttl time.Duration) error {
	if err := validateReference(first); err != nil {
		return err
	}
	if err := validateReference(second); err != nil {
		return err
	}
	if ttl < time.Second || ttl > 24*time.Hour {
		return errors.New("coordinator TTL must be between one second and 24 hours")
	}
	return nil
}

func validateReference(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > maxCoordinatorReferenceBytes || strings.ContainsAny(value, "\r\n\x00") {
		return errors.New("coordinator reference is invalid")
	}
	return nil
}

func randomToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomReference() string {
	value, err := randomToken()
	if err != nil {
		return fmt.Sprint(time.Now().UnixNano())
	}
	return value
}

func secureTLSConfig(caFile, serverName string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caFile == "" {
		return config, nil
	}
	contents, err := os.ReadFile(caFile)
	if err != nil {
		return nil, errors.New("read TLS CA file")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(contents) {
		return nil, errors.New("TLS CA file has no certificates")
	}
	config.RootCAs = roots
	return config, nil
}

type memoryLease struct {
	token    string
	owner    string
	expires  time.Time
	resource string
}

type memoryValue struct {
	value   string
	expires time.Time
}

// MemoryCoordinator provides process-local coordination for development mode.
type MemoryCoordinator struct {
	mu          sync.Mutex
	leases      map[string]memoryLease
	idempotency map[string]memoryValue
	cancel      map[string]time.Time
	now         func() time.Time
}

func NewMemoryCoordinator() *MemoryCoordinator {
	return &MemoryCoordinator{
		leases: make(map[string]memoryLease), idempotency: make(map[string]memoryValue), cancel: make(map[string]time.Time),
		now: time.Now,
	}
}

func (m *MemoryCoordinator) AcquireLease(_ context.Context, resource, owner string, ttl time.Duration) (Lease, error) {
	if err := validateCoordinatorInput(resource, owner, ttl); err != nil {
		return Lease{}, err
	}
	token, err := randomToken()
	if err != nil {
		return Lease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if current, exists := m.leases[resource]; exists && current.expires.After(now) {
		return Lease{}, ErrLeaseHeld
	}
	expires := now.Add(ttl)
	m.leases[resource] = memoryLease{token: token, owner: owner, expires: expires, resource: resource}
	return Lease{key: resource, token: token, expires: expires, resource: resource}, nil
}

func (m *MemoryCoordinator) RenewLease(_ context.Context, lease Lease, ttl time.Duration) (Lease, error) {
	if ttl < time.Second || ttl > 24*time.Hour {
		return Lease{}, errors.New("positive TTL is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	current, exists := m.leases[lease.resource]
	if !exists || current.token != lease.token || !current.expires.After(now) {
		return Lease{}, ErrLeaseLost
	}
	current.expires = now.Add(ttl)
	m.leases[lease.resource] = current
	lease.expires = current.expires
	return lease, nil
}

func (m *MemoryCoordinator) ReleaseLease(_ context.Context, lease Lease) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.leases[lease.resource]
	if !exists || current.token != lease.token {
		return ErrLeaseLost
	}
	delete(m.leases, lease.resource)
	return nil
}

func (m *MemoryCoordinator) PutIdempotency(_ context.Context, key, resultReference string, ttl time.Duration) (bool, error) {
	if err := validateCoordinatorInput(key, resultReference, ttl); err != nil {
		return false, err
	}
	if err := validateIdentifier("idempotency result reference", resultReference); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now().UTC()
	if current, exists := m.idempotency[key]; exists && current.expires.After(now) {
		return false, nil
	}
	m.idempotency[key] = memoryValue{value: resultReference, expires: now.Add(ttl)}
	return true, nil
}

func (m *MemoryCoordinator) GetIdempotency(_ context.Context, key string) (string, bool, error) {
	if err := validateReference(key); err != nil {
		return "", false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.idempotency[key]
	if !exists || !current.expires.After(m.now().UTC()) {
		delete(m.idempotency, key)
		return "", false, nil
	}
	return current.value, true, nil
}

func (m *MemoryCoordinator) RequestCancellation(_ context.Context, jobID string, ttl time.Duration) error {
	if err := validateCoordinatorInput(jobID, jobID, ttl); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancel[jobID] = m.now().UTC().Add(ttl)
	return nil
}

func (m *MemoryCoordinator) CancellationRequested(_ context.Context, jobID string) (bool, error) {
	if err := validateReference(jobID); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	expires, exists := m.cancel[jobID]
	if !exists || !expires.After(m.now().UTC()) {
		delete(m.cancel, jobID)
		return false, nil
	}
	return true, nil
}
