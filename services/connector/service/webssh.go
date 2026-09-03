package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/connector/sshconnector"
	websshtransport "vpsmanager/services/connector/webssh"
)

const (
	defaultWebSSHTicketTTL            = 30 * time.Second
	defaultWebSSHHandshakeTimeout     = 5 * time.Second
	defaultWebSSHIdleTimeout          = 10 * time.Minute
	defaultWebSSHAbsoluteTimeout      = time.Hour
	defaultWebSSHConcurrent           = 4
	defaultWebSSHOutstandingTickets   = 128
	defaultWebSSHInputMessageBytes    = 16 << 10
	defaultWebSSHOutputMessageBytes   = 16 << 10
	defaultWebSSHInputBytesPerSecond  = 64 << 10
	defaultWebSSHOutputBytesPerSecond = 256 << 10
)

type WebSSHOptions struct {
	AllowedOrigins        []string
	TicketTTL             time.Duration
	HandshakeTimeout      time.Duration
	IdleTimeout           time.Duration
	AbsoluteTimeout       time.Duration
	MaxConcurrent         int
	MaxOutstandingTickets int
	MaxInputMessageBytes  int
	MaxOutputMessageBytes int
	InputBytesPerSecond   int64
	OutputBytesPerSecond  int64
	AllowPrivateTargets   bool
	ConnectTimeout        time.Duration
	Now                   func() time.Time
	Runner                websshtransport.Runner
}

type webSSHManager struct {
	enabled               bool
	origins               map[string]struct{}
	ticketTTL             time.Duration
	handshakeTimeout      time.Duration
	idleTimeout           time.Duration
	absoluteTimeout       time.Duration
	maxTickets            int
	maxConsumed           int
	maxInputMessageBytes  int
	maxOutputMessageBytes int
	inputBytesPerSecond   int64
	outputBytesPerSecond  int64
	allowPrivateTargets   bool
	connectTimeout        time.Duration
	now                   func() time.Time
	runner                websshtransport.Runner
	concurrency           chan struct{}
	connections           chan struct{}
	ctx                   context.Context
	cancel                context.CancelFunc
	mu                    sync.Mutex
	tickets               map[[sha256.Size]byte]*webSSHTicket
	consumed              map[[sha256.Size]byte]time.Time
	wait                  sync.WaitGroup
	closed                bool
}

type webSSHTicket struct {
	sessionID     string
	binding       connectorprotocol.WebSSHBinding
	target        connectorprotocol.Target
	pinnedHostKey string
	credential    connectorprotocol.Credential
	initialSize   connectorprotocol.TerminalSize
	expiresAt     time.Time
}

func newWebSSHManager(options WebSSHOptions) (*webSSHManager, error) {
	manager := &webSSHManager{enabled: len(options.AllowedOrigins) > 0}
	if !manager.enabled {
		return manager, nil
	}
	origins, err := normalizeOrigins(options.AllowedOrigins)
	if err != nil {
		return nil, err
	}
	if options.TicketTTL <= 0 {
		options.TicketTTL = defaultWebSSHTicketTTL
	}
	if options.TicketTTL > time.Minute {
		return nil, errors.New("web SSH ticket TTL must not exceed one minute")
	}
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = defaultWebSSHHandshakeTimeout
	}
	if options.HandshakeTimeout > 15*time.Second {
		return nil, errors.New("web SSH handshake timeout must not exceed 15 seconds")
	}
	if options.IdleTimeout <= 0 {
		options.IdleTimeout = defaultWebSSHIdleTimeout
	}
	if options.IdleTimeout > time.Hour {
		return nil, errors.New("web SSH idle timeout must not exceed one hour")
	}
	if options.AbsoluteTimeout <= 0 {
		options.AbsoluteTimeout = defaultWebSSHAbsoluteTimeout
	}
	if options.AbsoluteTimeout > 8*time.Hour {
		return nil, errors.New("web SSH absolute timeout must not exceed eight hours")
	}
	if options.MaxConcurrent <= 0 {
		options.MaxConcurrent = defaultWebSSHConcurrent
	}
	if options.MaxConcurrent > 64 {
		return nil, errors.New("web SSH concurrency limit must not exceed 64")
	}
	if options.MaxOutstandingTickets <= 0 {
		options.MaxOutstandingTickets = defaultWebSSHOutstandingTickets
	}
	if options.MaxOutstandingTickets > 4096 {
		return nil, errors.New("web SSH outstanding ticket limit must not exceed 4096")
	}
	if options.MaxInputMessageBytes <= 0 {
		options.MaxInputMessageBytes = defaultWebSSHInputMessageBytes
	}
	if options.MaxInputMessageBytes > 64<<10 {
		return nil, errors.New("web SSH input message limit must not exceed 64 KiB")
	}
	if options.MaxOutputMessageBytes <= 0 {
		options.MaxOutputMessageBytes = defaultWebSSHOutputMessageBytes
	}
	if options.MaxOutputMessageBytes > 64<<10 {
		return nil, errors.New("web SSH output message limit must not exceed 64 KiB")
	}
	if options.InputBytesPerSecond <= 0 {
		options.InputBytesPerSecond = defaultWebSSHInputBytesPerSecond
	}
	if options.InputBytesPerSecond > 4<<20 {
		return nil, errors.New("web SSH input rate must not exceed 4 MiB/s")
	}
	if options.OutputBytesPerSecond <= 0 {
		options.OutputBytesPerSecond = defaultWebSSHOutputBytesPerSecond
	}
	if options.OutputBytesPerSecond > 8<<20 {
		return nil, errors.New("web SSH output rate must not exceed 8 MiB/s")
	}
	if options.ConnectTimeout <= 0 {
		options.ConnectTimeout = 10 * time.Second
	}
	if options.ConnectTimeout > 30*time.Second {
		return nil, errors.New("web SSH connect timeout must not exceed 30 seconds")
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Runner == nil {
		options.Runner = websshtransport.New()
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager = &webSSHManager{
		enabled: true, origins: origins, ticketTTL: options.TicketTTL,
		handshakeTimeout: options.HandshakeTimeout, idleTimeout: options.IdleTimeout,
		absoluteTimeout: options.AbsoluteTimeout, maxTickets: options.MaxOutstandingTickets,
		maxConsumed:           options.MaxOutstandingTickets * 4,
		maxInputMessageBytes:  options.MaxInputMessageBytes,
		maxOutputMessageBytes: options.MaxOutputMessageBytes,
		inputBytesPerSecond:   options.InputBytesPerSecond,
		outputBytesPerSecond:  options.OutputBytesPerSecond,
		allowPrivateTargets:   options.AllowPrivateTargets, connectTimeout: options.ConnectTimeout,
		now: options.Now, runner: options.Runner, concurrency: make(chan struct{}, options.MaxConcurrent),
		connections: make(chan struct{}, options.MaxConcurrent*2),
		ctx:         ctx, cancel: cancel, tickets: make(map[[sha256.Size]byte]*webSSHTicket),
		consumed: make(map[[sha256.Size]byte]time.Time),
	}
	manager.wait.Add(1)
	go manager.pruneLoop()
	return manager, nil
}

func (m *webSSHManager) Close() {
	if m == nil || !m.enabled {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	for key, ticket := range m.tickets {
		wipeCredential(&ticket.credential)
		delete(m.tickets, key)
	}
	m.mu.Unlock()
	m.cancel()
	m.wait.Wait()
}

func (m *webSSHManager) pruneLoop() {
	defer m.wait.Done()
	interval := m.ticketTTL / 2
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			m.pruneLocked(m.now())
			m.mu.Unlock()
		}
	}
}

func (m *webSSHManager) pruneLocked(now time.Time) {
	for key, ticket := range m.tickets {
		if !ticket.expiresAt.After(now) {
			wipeCredential(&ticket.credential)
			delete(m.tickets, key)
		}
	}
	for key, expiresAt := range m.consumed {
		if !expiresAt.After(now) {
			delete(m.consumed, key)
		}
	}
}

func (s *Server) handleWebSSHTicket(writer http.ResponseWriter, request *http.Request, requestID string) {
	if s.webSSH == nil || !s.webSSH.enabled {
		writeError(writer, http.StatusServiceUnavailable, requestID, "webssh_disabled", "web SSH is not enabled on this Connector", false)
		return
	}
	body, ok := s.authenticateJSON(writer, request, requestID)
	if !ok {
		return
	}
	defer wipe(body)
	var payload connectorprotocol.WebSSHTicketRequest
	if err := decodeStrictJSON(body, &payload); err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_json", "request must be one valid JSON object with only supported fields", false)
		return
	}
	defer wipeCredential(&payload.Credential)
	if err := validateWebSSHTicketRequest(payload, s.webSSH.allowPrivateTargets); err != nil {
		writeError(writer, http.StatusBadRequest, requestID, "invalid_webssh_ticket", "web SSH ticket request is invalid", false)
		return
	}
	response, err := s.webSSH.createTicket(payload, requestID)
	if err != nil {
		writeError(writer, http.StatusTooManyRequests, requestID, "ticket_capacity", "web SSH ticket capacity reached", true)
		return
	}
	writeJSON(writer, http.StatusCreated, response)
}

func (m *webSSHManager) createTicket(payload connectorprotocol.WebSSHTicketRequest, requestID string) (connectorprotocol.WebSSHTicketResponse, error) {
	ticketBytes := make([]byte, 32)
	sessionBytes := make([]byte, 16)
	if _, err := rand.Read(ticketBytes); err != nil {
		return connectorprotocol.WebSSHTicketResponse{}, err
	}
	if _, err := rand.Read(sessionBytes); err != nil {
		wipe(ticketBytes)
		return connectorprotocol.WebSSHTicketResponse{}, err
	}
	ticketValue := base64.RawURLEncoding.EncodeToString(ticketBytes)
	ticketHash := sha256.Sum256(ticketBytes)
	wipe(ticketBytes)
	now := m.now()
	entry := &webSSHTicket{
		sessionID: base64.RawURLEncoding.EncodeToString(sessionBytes), binding: payload.Binding,
		target: payload.Target, pinnedHostKey: payload.PinnedHostKey,
		credential: cloneCredential(payload.Credential), initialSize: payload.InitialSize,
		expiresAt: now.Add(m.ticketTTL),
	}
	wipe(sessionBytes)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	if m.closed || len(m.tickets) >= m.maxTickets || len(m.consumed) >= m.maxConsumed {
		wipeCredential(&entry.credential)
		return connectorprotocol.WebSSHTicketResponse{}, errors.New("web SSH ticket capacity reached")
	}
	if _, exists := m.tickets[ticketHash]; exists {
		wipeCredential(&entry.credential)
		return connectorprotocol.WebSSHTicketResponse{}, errors.New("web SSH ticket collision")
	}
	m.tickets[ticketHash] = entry
	return connectorprotocol.WebSSHTicketResponse{
		ProtocolVersion: connectorprotocol.ProtocolVersion, RequestID: requestID,
		Ticket: ticketValue, SessionID: entry.sessionID, ExpiresAt: entry.expiresAt.UTC(),
	}, nil
}

func (s *Server) handleWebSSHConnect(writer http.ResponseWriter, request *http.Request, requestID string) {
	manager := s.webSSH
	if manager == nil || !manager.enabled {
		writeError(writer, http.StatusServiceUnavailable, requestID, "webssh_disabled", "web SSH is not enabled on this Connector", false)
		return
	}
	if !manager.originAllowed(request) {
		writeError(writer, http.StatusForbidden, requestID, "origin_denied", "WebSocket origin is not allowed", false)
		return
	}
	select {
	case manager.connections <- struct{}{}:
		defer func() { <-manager.connections }()
	default:
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusTooManyRequests, requestID, "websocket_capacity", "web SSH connection capacity reached", true)
		return
	}
	connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols:       []string{connectorprotocol.WebSSHSubprotocol},
		InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	if err := clearUpgradedConnectionDeadlines(request.Context()); err != nil {
		_ = writeWebSSHError(context.Background(), connection, nil, "transport_deadline_error", "could not initialize WebSocket transport", true)
		_ = connection.Close(websocket.StatusInternalError, "transport initialization failed")
		return
	}
	connection.SetReadLimit(int64(manager.maxInputMessageBytes*2 + 4096))
	if connection.Subprotocol() != connectorprotocol.WebSSHSubprotocol {
		_ = writeWebSSHError(context.Background(), connection, nil, "subprotocol_required", "required WebSocket subprotocol was not negotiated", false)
		_ = connection.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}
	if !manager.beginSession() {
		_ = writeWebSSHError(context.Background(), connection, nil, "connector_shutdown", "Connector is shutting down", true)
		_ = connection.Close(websocket.StatusGoingAway, "Connector shutdown")
		return
	}
	defer manager.wait.Done()
	manager.serveConnection(connection)
}

func (m *webSSHManager) serveConnection(connection *websocket.Conn) {
	defer connection.CloseNow()
	handshakeContext, cancelHandshake := context.WithTimeout(m.ctx, m.handshakeTimeout)
	messageType, body, err := connection.Read(handshakeContext)
	cancelHandshake()
	if err != nil {
		return
	}
	if messageType != websocket.MessageText {
		_ = writeWebSSHError(m.ctx, connection, nil, "invalid_hello", "first WebSocket message must be a JSON hello", false)
		_ = connection.Close(websocket.StatusPolicyViolation, "invalid hello")
		return
	}
	var hello connectorprotocol.WebSSHHelloMessage
	if err := decodeStrictJSON(body, &hello); err != nil || hello.Type != connectorprotocol.WebSSHMessageHello {
		_ = writeWebSSHError(m.ctx, connection, nil, "invalid_hello", "first WebSocket message must be a valid hello", false)
		_ = connection.Close(websocket.StatusPolicyViolation, "invalid hello")
		return
	}
	ticket, consumeCode := m.consumeTicket(hello)
	if ticket == nil {
		_ = writeWebSSHError(m.ctx, connection, nil, consumeCode, "web SSH ticket is invalid or unavailable", false)
		_ = connection.Close(websocket.StatusPolicyViolation, "invalid ticket")
		return
	}
	defer wipeCredential(&ticket.credential)
	select {
	case m.concurrency <- struct{}{}:
		defer func() { <-m.concurrency }()
	default:
		_ = writeWebSSHError(m.ctx, connection, nil, "session_capacity", "web SSH session capacity reached", true)
		_ = connection.Close(websocket.StatusTryAgainLater, "session capacity")
		return
	}

	pinnedHostKey, err := sshconnector.ParsePinnedHostKey(ticket.pinnedHostKey)
	if err != nil {
		_ = writeWebSSHError(m.ctx, connection, nil, "invalid_host_key", "pinned host key is invalid", false)
		return
	}
	var signer ssh.Signer
	if len(ticket.credential.Passphrase) == 0 {
		signer, err = ssh.ParsePrivateKey(ticket.credential.PrivateKeyPEM)
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(ticket.credential.PrivateKeyPEM, ticket.credential.Passphrase)
	}
	if err != nil {
		_ = writeWebSSHError(m.ctx, connection, nil, "invalid_credential", "SSH private key could not be parsed", false)
		return
	}
	sessionContext, cancelSession := context.WithTimeout(m.ctx, m.absoluteTimeout)
	defer cancelSession()
	pty, err := m.runner.OpenPTY(sessionContext, websshtransport.Config{
		Address: ticket.target.Address, Port: ticket.target.Port, User: ticket.target.User,
		Auth: ssh.PublicKeys(signer), PinnedHostKey: pinnedHostKey, InitialSize: ticket.initialSize,
		ConnectTimeout: m.connectTimeout, AllowPrivateTargets: m.allowPrivateTargets,
	})
	wipeCredential(&ticket.credential)
	if err != nil {
		_ = writeWebSSHError(m.ctx, connection, nil, "ssh_connect_failed", "web SSH connection failed", true)
		_ = connection.Close(websocket.StatusInternalError, "SSH connection failed")
		return
	}
	defer pty.Close()
	writer := &webSocketWriter{connection: connection}
	if err := writer.write(sessionContext, connectorprotocol.WebSSHReadyMessage{
		Type: connectorprotocol.WebSSHMessageReady, SessionID: ticket.sessionID, Size: ticket.initialSize,
	}); err != nil {
		return
	}
	lastActivity := &atomic.Int64{}
	lastActivity.Store(time.Now().UnixNano())
	ioContext, cancelIO := context.WithCancel(m.ctx)
	defer cancelIO()
	inputErrors := make(chan sessionEvent, 1)
	outputErrors := make(chan sessionEvent, 1)
	waitErrors := make(chan error, 1)
	go m.readClient(ioContext, connection, pty, lastActivity, inputErrors)
	go m.writeOutput(ioContext, writer, pty, lastActivity, outputErrors)
	go func() { waitErrors <- pty.Wait() }()

	idleInterval := m.idleTimeout / 4
	if idleInterval > time.Second {
		idleInterval = time.Second
	}
	if idleInterval < 5*time.Millisecond {
		idleInterval = 5 * time.Millisecond
	}
	idleTicker := time.NewTicker(idleInterval)
	defer idleTicker.Stop()
	for {
		select {
		case event := <-inputErrors:
			if event.code != "client_closed" {
				_ = writer.writeError(context.Background(), event.code, event.message, event.retryable)
			}
			return
		case event := <-outputErrors:
			if event.code != "output_closed" {
				_ = writer.writeError(context.Background(), event.code, event.message, event.retryable)
			}
			return
		case waitErr := <-waitErrors:
			exitCode := 0
			reason := "remote shell exited"
			var exitError *ssh.ExitError
			if errors.As(waitErr, &exitError) {
				exitCode = exitError.ExitStatus()
			} else if waitErr != nil {
				exitCode = -1
				reason = "remote shell disconnected"
			}
			_ = writer.write(context.Background(), connectorprotocol.WebSSHExitMessage{
				Type: connectorprotocol.WebSSHMessageExit, ExitCode: exitCode, Reason: reason,
			})
			_ = connection.Close(websocket.StatusNormalClosure, "remote shell exited")
			return
		case <-sessionContext.Done():
			code, message := "absolute_timeout", "web SSH absolute timeout reached"
			if errors.Is(m.ctx.Err(), context.Canceled) {
				code, message = "connector_shutdown", "Connector is shutting down"
			}
			_ = writer.writeError(context.Background(), code, message, false)
			return
		case <-idleTicker.C:
			last := time.Unix(0, lastActivity.Load())
			if time.Since(last) >= m.idleTimeout {
				_ = writer.writeError(context.Background(), "idle_timeout", "web SSH session was idle too long", false)
				_ = connection.Close(websocket.StatusNormalClosure, "idle timeout")
				return
			}
		}
	}
}

type sessionEvent struct {
	code      string
	message   string
	retryable bool
}

func (m *webSSHManager) readClient(ctx context.Context, connection *websocket.Conn, pty websshtransport.Session, lastActivity *atomic.Int64, result chan<- sessionEvent) {
	limiter := newByteRateLimiter(m.inputBytesPerSecond, m.inputBytesPerSecond*2)
	for {
		messageType, body, err := connection.Read(ctx)
		if err != nil {
			result <- sessionEvent{code: "client_closed"}
			return
		}
		if messageType != websocket.MessageText {
			result <- sessionEvent{code: "invalid_message", message: "web SSH messages must be JSON text"}
			return
		}
		charge := int64(len(body))
		if charge < 512 {
			charge = 512
		}
		if !limiter.Allow(charge) {
			result <- sessionEvent{code: "input_rate_limit", message: "web SSH input rate limit exceeded"}
			return
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(body, &header); err != nil {
			result <- sessionEvent{code: "invalid_message", message: "web SSH message is invalid"}
			return
		}
		switch header.Type {
		case connectorprotocol.WebSSHMessageInput:
			var message connectorprotocol.WebSSHInputMessage
			if err := decodeStrictJSON(body, &message); err != nil || len(message.Data) > m.maxInputMessageBytes {
				result <- sessionEvent{code: "input_too_large", message: "web SSH input message is invalid or too large"}
				return
			}
			if err := writeAll(pty, message.Data); err != nil {
				result <- sessionEvent{code: "ssh_input_failed", message: "could not write SSH input", retryable: true}
				return
			}
			lastActivity.Store(time.Now().UnixNano())
		case connectorprotocol.WebSSHMessageResize:
			var message connectorprotocol.WebSSHResizeMessage
			if err := decodeStrictJSON(body, &message); err != nil || !validTerminalSize(message.Size) {
				result <- sessionEvent{code: "invalid_resize", message: "PTY size is outside the allowed range"}
				return
			}
			if err := pty.Resize(message.Size); err != nil {
				result <- sessionEvent{code: "resize_failed", message: "could not resize SSH PTY", retryable: true}
				return
			}
			lastActivity.Store(time.Now().UnixNano())
		default:
			result <- sessionEvent{code: "unsupported_message", message: "web SSH message type is not supported"}
			return
		}
	}
}

func (m *webSSHManager) writeOutput(ctx context.Context, writer *webSocketWriter, pty websshtransport.Session, lastActivity *atomic.Int64, result chan<- sessionEvent) {
	limiter := newByteRateLimiter(m.outputBytesPerSecond, m.outputBytesPerSecond*2)
	buffer := make([]byte, m.maxOutputMessageBytes)
	for {
		count, err := pty.ReadOutput(buffer)
		if count > 0 {
			if !limiter.Allow(int64(count)) {
				result <- sessionEvent{code: "output_rate_limit", message: "web SSH output rate limit exceeded"}
				return
			}
			output := append([]byte(nil), buffer[:count]...)
			if writeErr := writer.write(ctx, connectorprotocol.WebSSHOutputMessage{Type: connectorprotocol.WebSSHMessageOutput, Data: output}); writeErr != nil {
				wipe(output)
				result <- sessionEvent{code: "client_closed"}
				return
			}
			wipe(output)
			lastActivity.Store(time.Now().UnixNano())
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				result <- sessionEvent{code: "output_closed"}
			} else {
				result <- sessionEvent{code: "ssh_output_failed", message: "could not read SSH output", retryable: true}
			}
			return
		}
	}
}

func (m *webSSHManager) consumeTicket(hello connectorprotocol.WebSSHHelloMessage) (*webSSHTicket, string) {
	decoded, err := base64.RawURLEncoding.DecodeString(hello.Ticket)
	if err != nil || len(decoded) != 32 {
		wipe(decoded)
		return nil, "invalid_ticket"
	}
	hash := sha256.Sum256(decoded)
	wipe(decoded)
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked(now)
	entry, found := m.tickets[hash]
	if !found {
		if _, replayed := m.consumed[hash]; replayed {
			return nil, "ticket_replayed"
		}
		return nil, "invalid_ticket"
	}
	delete(m.tickets, hash)
	m.consumed[hash] = now.Add(m.ticketTTL)
	if !entry.expiresAt.After(now) {
		wipeCredential(&entry.credential)
		return nil, "ticket_expired"
	}
	if !sameString(entry.sessionID, hello.SessionID) || !sameBinding(entry.binding, hello.Binding) || hello.Type != connectorprotocol.WebSSHMessageHello {
		wipeCredential(&entry.credential)
		return nil, "ticket_binding_mismatch"
	}
	return entry, ""
}

func (m *webSSHManager) beginSession() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	m.wait.Add(1)
	return true
}

func (m *webSSHManager) originAllowed(request *http.Request) bool {
	values := request.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	normalized, err := normalizeOrigin(values[0])
	if err != nil {
		return false
	}
	_, allowed := m.origins[normalized]
	return allowed
}

type webSocketWriter struct {
	connection *websocket.Conn
	mu         sync.Mutex
}

func (w *webSocketWriter) write(ctx context.Context, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	writeContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.connection.Write(writeContext, websocket.MessageText, body)
}

func (w *webSocketWriter) writeError(ctx context.Context, code, message string, retryable bool) error {
	return w.write(ctx, connectorprotocol.WebSSHErrorMessage{
		Type: connectorprotocol.WebSSHMessageError, Code: code, Message: message, Retryable: retryable,
	})
}

func writeWebSSHError(ctx context.Context, connection *websocket.Conn, writer *webSocketWriter, code, message string, retryable bool) error {
	if writer == nil {
		writer = &webSocketWriter{connection: connection}
	}
	return writer.writeError(ctx, code, message, retryable)
}

type byteRateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newByteRateLimiter(rate, burst int64) *byteRateLimiter {
	return &byteRateLimiter{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (l *byteRateLimiter) Allow(amount int64) bool {
	if amount < 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.tokens += now.Sub(l.last).Seconds() * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now
	if float64(amount) > l.tokens {
		return false
	}
	l.tokens -= float64(amount)
	return true
}

func validateWebSSHTicketRequest(payload connectorprotocol.WebSSHTicketRequest, allowPrivate bool) error {
	if payload.ProtocolVersion != connectorprotocol.ProtocolVersion || payload.Binding.Action != connectorprotocol.ActionWebSSH ||
		!validBoundID(payload.Binding.PrincipalID) || !validBoundID(payload.Binding.HostID) || !validBoundID(payload.Binding.CredentialID) ||
		strings.TrimSpace(payload.Target.Address) == "" || payload.Target.Address != strings.TrimSpace(payload.Target.Address) || len(payload.Target.Address) > 253 ||
		payload.Target.Port < 1 || payload.Target.Port > 65535 || !validSSHUser(payload.Target.User) ||
		len(payload.PinnedHostKey) == 0 || len(payload.PinnedHostKey) > 16<<10 ||
		len(payload.Credential.PrivateKeyPEM) == 0 || len(payload.Credential.PrivateKeyPEM) > 48<<10 ||
		len(payload.Credential.Passphrase) > 4<<10 || !validTerminalSize(payload.InitialSize) {
		return errors.New("invalid web SSH ticket")
	}
	if err := sshconnector.ValidateTargetLiteral(payload.Target.Address, allowPrivate); err != nil {
		return err
	}
	if _, err := sshconnector.ParsePinnedHostKey(payload.PinnedHostKey); err != nil {
		return err
	}
	if len(payload.Credential.Passphrase) == 0 {
		_, err := ssh.ParsePrivateKey(payload.Credential.PrivateKeyPEM)
		return err
	}
	_, err := ssh.ParsePrivateKeyWithPassphrase(payload.Credential.PrivateKeyPEM, payload.Credential.Passphrase)
	return err
}

func validBoundID(value string) bool {
	if len(value) < 1 || len(value) > 128 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validSSHUser(value string) bool {
	if len(value) < 1 || len(value) > 64 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.IsSpace(character) {
			return false
		}
	}
	return true
}

func validTerminalSize(size connectorprotocol.TerminalSize) bool {
	return size.Columns >= 20 && size.Columns <= 500 && size.Rows >= 5 && size.Rows <= 300 &&
		size.WidthPixels <= 10_000 && size.HeightPixels <= 10_000
}

func sameBinding(left, right connectorprotocol.WebSSHBinding) bool {
	return sameString(left.PrincipalID, right.PrincipalID) && sameString(left.HostID, right.HostID) &&
		sameString(left.CredentialID, right.CredentialID) && sameString(left.Action, right.Action)
}

func sameString(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func normalizeOrigins(values []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized, err := normalizeOrigin(value)
		if err != nil {
			return nil, err
		}
		result[normalized] = struct{}{}
	}
	if len(result) == 0 {
		return nil, errors.New("at least one exact web SSH origin is required")
	}
	return result, nil
}

func normalizeOrigin(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "*?,") {
		return "", errors.New("web SSH origins must be exact HTTP(S) origins without wildcards")
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" ||
		parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("web SSH origins must be exact HTTP(S) origins")
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host), nil
}

func cloneCredential(value connectorprotocol.Credential) connectorprotocol.Credential {
	return connectorprotocol.Credential{
		PrivateKeyPEM: append([]byte(nil), value.PrivateKeyPEM...),
		Passphrase:    append([]byte(nil), value.Passphrase...),
	}
}

func wipeCredential(value *connectorprotocol.Credential) {
	if value == nil {
		return
	}
	wipe(value.PrivateKeyPEM)
	wipe(value.Passphrase)
	value.PrivateKeyPEM = nil
	value.Passphrase = nil
}

type inputWriter interface {
	WriteInput([]byte) (int, error)
}

func writeAll(writer inputWriter, value []byte) error {
	for len(value) > 0 {
		written, err := writer.WriteInput(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
