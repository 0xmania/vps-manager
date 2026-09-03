// Package sshconnector provides the narrow SSH execution boundary used by the
// control plane. It has no trust-on-first-use or arbitrary-command mode.
package sshconnector

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrHostKeyRequired = errors.New("a pinned host key is required")
	ErrHostKeyMismatch = errors.New("ssh host key does not match the pinned key")
	ErrOutputLimit     = errors.New("ssh command output exceeded the configured limit")
	ErrTargetDenied    = errors.New("ssh target is denied by network policy")
	errProbeComplete   = errors.New("host key probe complete")
)

type CommandID string

const CommandRuntimeSnapshot CommandID = "runtime_snapshot_v1"

// Command is opaque outside this package. Callers cannot turn user input into
// a remote shell program; reviewed commands must be added to this catalog.
type Command struct {
	id     CommandID
	script string
}

func (c Command) ID() CommandID { return c.id }

func RuntimeSnapshotCommand() Command {
	return Command{id: CommandRuntimeSnapshot, script: `LC_ALL=C
printf 'hostname\t'; hostname 2>/dev/null || true
printf 'kernel\t'; uname -sr 2>/dev/null || true
awk '{printf "uptime\t%.0f\n", $1}' /proc/uptime 2>/dev/null || true
awk '{printf "load\t%s\t%s\t%s\n", $1, $2, $3}' /proc/loadavg 2>/dev/null || true
awk '/^MemTotal:/ {total=$2} /^MemAvailable:/ {available=$2} END {printf "memory_kib\t%.0f\t%.0f\n", total, available}' /proc/meminfo 2>/dev/null || true
awk -F: '/^model name[[:space:]]*:/ {sub(/^[[:space:]]+/, "", $2); printf "cpu_model\t%s\n", $2; exit}' /proc/cpuinfo 2>/dev/null || true
awk '/^processor[[:space:]]*:/ {count++} END {printf "cpu_logical\t%.0f\n", count}' /proc/cpuinfo 2>/dev/null || true
df -P -B1 2>/dev/null | awk 'NR > 1 && $2 ~ /^[0-9]+$/ {mount=$6; for (i=7; i<=NF; i++) mount=mount " " $i; printf "filesystem\t%s\t%s\t%s\t%s\n", mount, $2, $3, $4}' || true
`}
}

// Config contains connection policy. Private key material is provided through
// ssh.AuthMethod; Client does not retain it after Run returns.
type Config struct {
	Address        string
	Port           int
	User           string
	Auth           ssh.AuthMethod
	PinnedHostKey  ssh.PublicKey
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
	MaxOutputBytes int64
	// AllowPrivateTargets is an explicit development/on-premises escape hatch.
	// The safe default rejects private and reserved destination ranges.
	AllowPrivateTargets bool
}

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

type HostKeyObservation struct {
	Algorithm         string
	FingerprintSHA256 string
	PublicKey         string
	ResolvedAddress   string
}

type Client struct{}

func New() *Client { return &Client{} }

// ProbeHostKey performs only TCP connect and SSH key exchange. Its callback
// aborts as soon as the server host key is seen, before client
// authentication and without opening a session or running code. The result is
// untrusted until independently verified and explicitly pinned.
func (c *Client) ProbeHostKey(ctx context.Context, address string, port int, allowPrivate bool) (HostKeyObservation, error) {
	if strings.TrimSpace(address) == "" || port < 1 || port > 65535 {
		return HostKeyObservation{}, errors.New("valid SSH target address and port are required")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	targetIP, err := resolveTarget(probeCtx, address, allowPrivate)
	if err != nil {
		return HostKeyObservation{}, err
	}
	dialAddress := net.JoinHostPort(targetIP.String(), strconv.Itoa(port))
	hostIdentity := net.JoinHostPort(address, strconv.Itoa(port))
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", dialAddress)
	if err != nil {
		return HostKeyObservation{}, fmt.Errorf("SSH probe TCP connection failed: %w", err)
	}
	defer connection.Close()
	stopContextClose := context.AfterFunc(probeCtx, func() { _ = connection.Close() })
	defer stopContextClose()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))

	var observed ssh.PublicKey
	config := &ssh.ClientConfig{
		User: "host-key-probe",
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			observed = key
			return errProbeComplete
		},
		Timeout: 10 * time.Second,
	}
	sshConnection, channels, requests, handshakeErr := ssh.NewClientConn(connection, hostIdentity, config)
	if sshConnection != nil {
		_ = sshConnection.Close()
	}
	if channels != nil || requests != nil {
		return HostKeyObservation{}, errors.New("SSH host-key probe did not stop after key exchange")
	}
	if observed == nil {
		if handshakeErr == nil {
			return HostKeyObservation{}, errors.New("SSH host-key probe returned no key")
		}
		return HostKeyObservation{}, fmt.Errorf("SSH host-key probe failed before key observation: %w", handshakeErr)
	}
	return HostKeyObservation{
		Algorithm: observed.Type(), FingerprintSHA256: ssh.FingerprintSHA256(observed),
		PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(observed))), ResolvedAddress: targetIP.String(),
	}, nil
}

func ParsePinnedHostKey(encoded string) (ssh.PublicKey, error) {
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(encoded) + "\n"))
	if err != nil {
		return nil, fmt.Errorf("parse pinned host key: %w", err)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("pinned host key must contain exactly one key")
	}
	return key, nil
}

func PinnedHostKeyCallback(pinned ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, remote ssh.PublicKey) error {
		if pinned == nil {
			return ErrHostKeyRequired
		}
		want, got := pinned.Marshal(), remote.Marshal()
		if len(want) != len(got) || subtle.ConstantTimeCompare(want, got) != 1 {
			return ErrHostKeyMismatch
		}
		return nil
	}
}

// Run executes one catalog command with connect, execution, and combined
// stdout/stderr bounds. DNS is resolved once and the connection is pinned to
// the policy-checked address to prevent DNS rebinding between checks and dial.
func (c *Client) Run(ctx context.Context, cfg Config, command Command) (Result, error) {
	if err := validateConfig(cfg); err != nil {
		return Result{}, err
	}
	if command.id == "" || strings.TrimSpace(command.script) == "" {
		return Result{}, errors.New("catalog command is required")
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	if cfg.CommandTimeout <= 0 {
		cfg.CommandTimeout = 30 * time.Second
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 1 << 20
	}

	connectCtx, cancelConnect := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancelConnect()
	targetIP, err := resolveTarget(connectCtx, cfg.Address, cfg.AllowPrivateTargets)
	if err != nil {
		return Result{}, err
	}
	dialAddress := net.JoinHostPort(targetIP.String(), strconv.Itoa(cfg.Port))
	hostIdentity := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))
	netConn, err := (&net.Dialer{}).DialContext(connectCtx, "tcp", dialAddress)
	if err != nil {
		return Result{}, fmt.Errorf("ssh tcp connection failed: %w", err)
	}
	defer netConn.Close()

	_ = netConn.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
	sshCfg := &ssh.ClientConfig{
		User: cfg.User, Auth: []ssh.AuthMethod{cfg.Auth},
		HostKeyCallback: PinnedHostKeyCallback(cfg.PinnedHostKey), Timeout: cfg.ConnectTimeout,
	}
	conn, chans, reqs, err := ssh.NewClientConn(netConn, hostIdentity, sshCfg)
	if err != nil {
		return Result{}, fmt.Errorf("ssh handshake failed: %w", err)
	}
	_ = netConn.SetDeadline(time.Time{})
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	commandCtx, cancelCommand := context.WithTimeout(ctx, cfg.CommandTimeout)
	defer cancelCommand()
	return runSession(commandCtx, client, command.script, cfg.MaxOutputBytes)
}

type sessionClient interface {
	NewSession() (*ssh.Session, error)
	Close() error
}

func runSession(ctx context.Context, client sessionClient, command string, maxBytes int64) (Result, error) {
	started := time.Now()
	session, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("create ssh session: %w", err)
	}
	defer session.Close()

	budget := newOutputBudget(maxBytes)
	stdout, stderr := newBoundedBuffer(budget), newBoundedBuffer(budget)
	session.Stdout, session.Stderr = stdout, stderr
	if err := session.Start(command); err != nil {
		return Result{}, fmt.Errorf("start ssh command: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()

	var waitErr error
	select {
	case waitErr = <-done:
	case <-budget.exceeded:
		_ = client.Close()
		boundedWait(done)
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: -1, Duration: time.Since(started)}, ErrOutputLimit
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = client.Close()
		boundedWait(done)
		return Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: -1, Duration: time.Since(started)}, fmt.Errorf("ssh command stopped: %w", ctx.Err())
	}

	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: 0, Duration: time.Since(started)}
	if waitErr != nil {
		var exitErr *ssh.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitStatus()
			return result, fmt.Errorf("remote command exited with status %d", result.ExitCode)
		}
		result.ExitCode = -1
		return result, fmt.Errorf("wait for ssh command: %w", waitErr)
	}
	return result, nil
}

func boundedWait(done <-chan error) {
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Address) == "" {
		return errors.New("ssh address is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return errors.New("ssh port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.User) == "" {
		return errors.New("ssh user is required")
	}
	if cfg.Auth == nil {
		return errors.New("ssh authentication method is required")
	}
	if cfg.PinnedHostKey == nil {
		return ErrHostKeyRequired
	}
	return nil
}

type outputBudget struct {
	mu        sync.Mutex
	remaining int64
	exceeded  chan struct{}
	once      sync.Once
}

func newOutputBudget(max int64) *outputBudget {
	return &outputBudget{remaining: max, exceeded: make(chan struct{})}
}

type boundedBuffer struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	budget *outputBudget
}

func newBoundedBuffer(budget *outputBudget) *boundedBuffer { return &boundedBuffer{budget: budget} }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.budget.mu.Lock()
	allowed := int64(len(p))
	if allowed > b.budget.remaining {
		allowed = b.budget.remaining
	}
	b.budget.remaining -= allowed
	overflow := allowed < int64(len(p))
	b.budget.mu.Unlock()

	b.mu.Lock()
	if allowed > 0 {
		_, _ = b.buf.Write(p[:allowed])
	}
	b.mu.Unlock()
	if overflow {
		b.budget.once.Do(func() { close(b.budget.exceeded) })
		return int(allowed), ErrOutputLimit
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}

var _ io.Writer = (*boundedBuffer)(nil)

func resolveTarget(ctx context.Context, address string, allowPrivate bool) (netip.Addr, error) {
	var candidates []netip.Addr
	if parsed, err := netip.ParseAddr(address); err == nil {
		candidates = []netip.Addr{parsed.Unmap()}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", address)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("resolve ssh target: %w", err)
		}
		for _, candidate := range resolved {
			candidates = append(candidates, candidate.Unmap())
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, errors.New("ssh target resolved to no addresses")
	}
	for _, candidate := range candidates {
		if !targetAllowed(candidate, allowPrivate) {
			return netip.Addr{}, fmt.Errorf("%w: resolved address is not permitted", ErrTargetDenied)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Less(candidates[j]) })
	return candidates[0], nil
}

var deniedPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:2::/48"),
}

func targetAllowed(address netip.Addr, allowPrivate bool) bool {
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLoopback() {
		return false
	}
	if allowPrivate {
		return address.IsGlobalUnicast() || address.IsPrivate()
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, prefix := range deniedPublicPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

// ValidateTargetLiteral applies the destination policy when address is an IP
// literal. DNS names are resolved and checked atomically by Run.
func ValidateTargetLiteral(address string, allowPrivate bool) error {
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		return nil
	}
	if !targetAllowed(parsed, allowPrivate) {
		return ErrTargetDenied
	}
	return nil
}
