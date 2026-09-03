// Package webssh opens SSH PTY sessions without forwarding, file-transfer,
// environment, subsystem, or arbitrary exec APIs.
package webssh

import (
	"context"
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

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/connector/sshconnector"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Address             string
	Port                int
	User                string
	Auth                ssh.AuthMethod
	PinnedHostKey       ssh.PublicKey
	InitialSize         connectorprotocol.TerminalSize
	ConnectTimeout      time.Duration
	AllowPrivateTargets bool
}

type Session interface {
	ReadOutput([]byte) (int, error)
	WriteInput([]byte) (int, error)
	Resize(connectorprotocol.TerminalSize) error
	Wait() error
	Close() error
}

type Runner interface {
	OpenPTY(context.Context, Config) (Session, error)
}

type Client struct{}

func New() *Client { return &Client{} }

func (c *Client) OpenPTY(ctx context.Context, cfg Config) (Session, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 10 * time.Second
	}
	connectCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()
	targetIP, err := resolveTarget(connectCtx, cfg.Address, cfg.AllowPrivateTargets)
	if err != nil {
		return nil, err
	}
	dialAddress := net.JoinHostPort(targetIP.String(), strconv.Itoa(cfg.Port))
	hostIdentity := net.JoinHostPort(cfg.Address, strconv.Itoa(cfg.Port))
	netConnection, err := (&net.Dialer{}).DialContext(connectCtx, "tcp", dialAddress)
	if err != nil {
		return nil, fmt.Errorf("web SSH TCP connection failed: %w", err)
	}
	closeOnContext := context.AfterFunc(connectCtx, func() { _ = netConnection.Close() })
	defer closeOnContext()
	defer func() {
		if err != nil {
			_ = netConnection.Close()
		}
	}()
	_ = netConnection.SetDeadline(time.Now().Add(cfg.ConnectTimeout))
	sshConfig := &ssh.ClientConfig{
		User: cfg.User, Auth: []ssh.AuthMethod{cfg.Auth},
		HostKeyCallback: sshconnector.PinnedHostKeyCallback(cfg.PinnedHostKey), Timeout: cfg.ConnectTimeout,
	}
	connection, channels, requests, err := ssh.NewClientConn(netConnection, hostIdentity, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("web SSH handshake failed: %w", err)
	}
	_ = netConnection.SetDeadline(time.Time{})
	client := ssh.NewClient(connection, channels, requests)
	sshSession, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("create web SSH session: %w", err)
	}
	stdin, err := sshSession.StdinPipe()
	if err != nil {
		_ = sshSession.Close()
		_ = client.Close()
		return nil, fmt.Errorf("open web SSH input: %w", err)
	}
	outputReader, outputWriter := io.Pipe()
	serializedOutput := &lockedWriter{writer: outputWriter}
	sshSession.Stdout = serializedOutput
	sshSession.Stderr = serializedOutput
	modes := ssh.TerminalModes{
		ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sshSession.RequestPty(
		"xterm-256color", int(cfg.InitialSize.Rows), int(cfg.InitialSize.Columns), modes,
	); err != nil {
		_ = outputReader.Close()
		_ = outputWriter.Close()
		_ = sshSession.Close()
		_ = client.Close()
		return nil, fmt.Errorf("request web SSH PTY: %w", err)
	}
	if err := sshSession.Shell(); err != nil {
		_ = outputReader.Close()
		_ = outputWriter.Close()
		_ = sshSession.Close()
		_ = client.Close()
		return nil, fmt.Errorf("start web SSH shell: %w", err)
	}
	session := &ptySession{
		client: client, session: sshSession, input: stdin,
		outputReader: outputReader, outputWriter: outputWriter,
	}
	session.stopContextClose = context.AfterFunc(ctx, func() { _ = session.Close() })
	return session, nil
}

type ptySession struct {
	client           *ssh.Client
	session          *ssh.Session
	input            io.WriteCloser
	outputReader     *io.PipeReader
	outputWriter     *io.PipeWriter
	stopContextClose func() bool
	closeOnce        sync.Once
	waitOnce         sync.Once
	waitErr          error
}

func (s *ptySession) ReadOutput(buffer []byte) (int, error) { return s.outputReader.Read(buffer) }

func (s *ptySession) WriteInput(value []byte) (int, error) { return s.input.Write(value) }

func (s *ptySession) Resize(size connectorprotocol.TerminalSize) error {
	if err := validateSize(size); err != nil {
		return err
	}
	return s.session.WindowChange(int(size.Rows), int(size.Columns))
}

func (s *ptySession) Wait() error {
	s.waitOnce.Do(func() {
		s.waitErr = s.session.Wait()
		_ = s.outputWriter.Close()
	})
	return s.waitErr
}

func (s *ptySession) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		if s.stopContextClose != nil {
			s.stopContextClose()
		}
		_ = s.input.Close()
		_ = s.outputWriter.Close()
		_ = s.outputReader.Close()
		if err := s.session.Close(); err != nil && !errors.Is(err, io.EOF) {
			closeErr = err
		}
		if err := s.client.Close(); closeErr == nil && err != nil {
			closeErr = err
		}
	})
	return closeErr
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *lockedWriter) Write(value []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(value)
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Address) == "" || len(cfg.Address) > 253 {
		return errors.New("web SSH address is required")
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return errors.New("web SSH port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.User) == "" || len(cfg.User) > 64 {
		return errors.New("web SSH user is required")
	}
	if cfg.Auth == nil {
		return errors.New("web SSH authentication method is required")
	}
	if cfg.PinnedHostKey == nil {
		return sshconnector.ErrHostKeyRequired
	}
	return validateSize(cfg.InitialSize)
}

func validateSize(size connectorprotocol.TerminalSize) error {
	if size.Columns < 20 || size.Columns > 500 || size.Rows < 5 || size.Rows > 300 ||
		size.WidthPixels > 10_000 || size.HeightPixels > 10_000 {
		return errors.New("web SSH terminal size is outside the allowed range")
	}
	return nil
}

func resolveTarget(ctx context.Context, address string, allowPrivate bool) (netip.Addr, error) {
	var candidates []netip.Addr
	if parsed, err := netip.ParseAddr(address); err == nil {
		candidates = []netip.Addr{parsed.Unmap()}
	} else {
		resolved, err := net.DefaultResolver.LookupNetIP(ctx, "ip", address)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("resolve web SSH target: %w", err)
		}
		for _, candidate := range resolved {
			candidates = append(candidates, candidate.Unmap())
		}
	}
	if len(candidates) == 0 {
		return netip.Addr{}, errors.New("web SSH target resolved to no addresses")
	}
	for _, candidate := range candidates {
		if err := sshconnector.ValidateTargetLiteral(candidate.String(), allowPrivate); err != nil {
			return netip.Addr{}, fmt.Errorf("%w: resolved address is not permitted", sshconnector.ErrTargetDenied)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Less(candidates[j]) })
	return candidates[0], nil
}
