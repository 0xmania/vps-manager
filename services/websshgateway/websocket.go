package websshgateway

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	connectorprotocol "vpsmanager/services/connector-protocol"
)

type activeSession struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	browser  *websocket.Conn
	upstream *websocket.Conn
}

func (s *activeSession) closeNow() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	if s.browser != nil {
		s.browser.CloseNow()
	}
	if s.upstream != nil {
		s.upstream.CloseNow()
	}
	s.mu.Unlock()
}

func (s *activeSession) setUpstream(connection *websocket.Conn) {
	s.mu.Lock()
	s.upstream = connection
	s.mu.Unlock()
}

type socketWriter struct {
	connection *websocket.Conn
	timeout    time.Duration
	mu         sync.Mutex
}

func (w *socketWriter) raw(ctx context.Context, body []byte) error {
	writeContext, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.connection.Write(writeContext, websocket.MessageText, body)
}

func (w *socketWriter) json(ctx context.Context, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer wipe(body)
	return w.raw(ctx, body)
}

func (w *socketWriter) safeError(ctx context.Context, code, message string, retryable bool) {
	_ = w.json(ctx, connectorprotocol.WebSSHErrorMessage{
		Type: connectorprotocol.WebSSHMessageError, Code: code, Message: message, Retryable: retryable,
	})
}

type proxyResult struct {
	disconnectType string
	code           string
	message        string
	retryable      bool
	sendError      bool
}

// Handler returns the fixed-path browser WebSocket handler.
func (b *Broker) Handler() http.Handler { return b }

func (b *Broker) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path != ConnectPath {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		writer.Header().Set("Allow", http.MethodGet)
		writeHTTPError(writer, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if request.URL.RawQuery != "" || request.URL.Fragment != "" {
		writeHTTPError(writer, http.StatusBadRequest, "query_not_allowed")
		return
	}
	if !b.originAllowed(request) {
		writeHTTPError(writer, http.StatusForbidden, "origin_denied")
		return
	}
	if !hasSubprotocol(request.Header.Values("Sec-WebSocket-Protocol"), connectorprotocol.WebSSHSubprotocol) {
		writeHTTPError(writer, http.StatusBadRequest, "subprotocol_required")
		return
	}
	if !b.beginHandler() {
		writeHTTPError(writer, http.StatusServiceUnavailable, "gateway_shutdown")
		return
	}
	defer b.wait.Done()
	select {
	case b.connSlots <- struct{}{}:
		defer func() { <-b.connSlots }()
	default:
		writer.Header().Set("Retry-After", "1")
		writeHTTPError(writer, http.StatusTooManyRequests, "session_capacity")
		return
	}

	browser, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{connectorprotocol.WebSSHSubprotocol}, InsecureSkipVerify: true,
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	browser.SetReadLimit(int64(b.config.MaxInputMessageBytes*2 + 8192))
	if browser.Subprotocol() != connectorprotocol.WebSSHSubprotocol {
		_ = browser.Close(websocket.StatusPolicyViolation, "subprotocol required")
		return
	}
	sessionContext, cancel := context.WithTimeout(b.ctx, b.config.AbsoluteTimeout)
	session := &activeSession{cancel: cancel, browser: browser}
	if !b.registerSession(session) {
		cancel()
		_ = browser.Close(websocket.StatusGoingAway, "gateway shutdown")
		return
	}
	defer func() {
		b.unregisterSession(session)
		session.closeNow()
	}()
	b.serveSession(sessionContext, session)
}

func (b *Broker) serveSession(ctx context.Context, session *activeSession) {
	browserWriter := &socketWriter{connection: session.browser, timeout: b.config.WriteTimeout}
	handshakeContext, cancelHandshake := context.WithTimeout(ctx, b.config.HandshakeTimeout)
	messageType, body, err := session.browser.Read(handshakeContext)
	cancelHandshake()
	if err != nil {
		return
	}
	if messageType != websocket.MessageText {
		wipe(body)
		browserWriter.safeError(ctx, "invalid_hello", "first WebSocket message must be a JSON hello", false)
		return
	}
	var hello HelloMessage
	if err := decodeStrictJSON(body, &hello); err != nil || hello.Type != MessageHello {
		wipe(body)
		hello.Ticket = ""
		browserWriter.safeError(ctx, "invalid_hello", "first WebSocket message must be a valid hello", false)
		return
	}
	ticket, consumeCode := b.consumeTicket(hello)
	hello.Ticket = ""
	wipe(body)
	if ticket == nil {
		browserWriter.safeError(ctx, consumeCode, "WebSSH ticket is invalid or unavailable", false)
		return
	}
	defer wipeTicket(ticket)
	authorization := Authorization{Binding: cloneBinding(ticket.binding), Reason: ticket.reason}
	if !b.authorize(ctx, authorization) {
		b.audit(authorization, "disconnected", "authorization_denied", ticket.connectionID)
		browserWriter.safeError(ctx, "authorization_denied", "WebSSH authorization is no longer valid", false)
		return
	}

	upstream, response, err := b.dialConnector(ctx)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		b.audit(authorization, "disconnected", "connector_unavailable", ticket.connectionID)
		browserWriter.safeError(ctx, "connector_unavailable", "WebSSH Connector is unavailable", true)
		return
	}
	session.setUpstream(upstream)
	upstream.SetReadLimit(int64(b.config.MaxOutputMessageBytes*2 + 8192))
	if upstream.Subprotocol() != connectorprotocol.WebSSHSubprotocol {
		_ = upstream.Close(websocket.StatusPolicyViolation, "subprotocol required")
		b.audit(authorization, "disconnected", "connector_protocol_error", ticket.connectionID)
		browserWriter.safeError(ctx, "connector_protocol_error", "WebSSH Connector protocol negotiation failed", false)
		return
	}
	upstreamWriter := &socketWriter{connection: upstream, timeout: b.config.WriteTimeout}
	connectorHello := connectorprotocol.WebSSHHelloMessage{
		Type: connectorprotocol.WebSSHMessageHello, Ticket: string(ticket.upstreamTicket),
		SessionID: string(ticket.upstreamSession), Binding: ticket.connectorBinding,
	}
	if err := upstreamWriter.json(ctx, connectorHello); err != nil {
		connectorHello.Ticket = ""
		connectorHello.SessionID = ""
		b.audit(authorization, "disconnected", "connector_handshake_failed", ticket.connectionID)
		browserWriter.safeError(ctx, "connector_unavailable", "WebSSH Connector handshake failed", true)
		return
	}
	connectorHello.Ticket = ""
	connectorHello.SessionID = ""
	b.audit(authorization, "connected", "", ticket.connectionID)

	proxyContext, cancelProxy := context.WithCancel(ctx)
	defer cancelProxy()
	lastActivity := &atomic.Int64{}
	lastActivity.Store(time.Now().UnixNano())
	results := make(chan proxyResult, 2)
	var proxyWait sync.WaitGroup
	proxyWait.Add(2)
	go func() {
		defer proxyWait.Done()
		results <- b.proxyBrowserToConnector(proxyContext, session.browser, upstreamWriter, lastActivity)
	}()
	go func() {
		defer proxyWait.Done()
		results <- b.proxyConnectorToBrowser(proxyContext, upstream, browserWriter, ticket, lastActivity)
	}()

	authorizationTicker := time.NewTicker(b.config.AuthorizationInterval)
	idleInterval := b.config.IdleTimeout / 4
	if idleInterval > time.Second {
		idleInterval = time.Second
	}
	if idleInterval < 10*time.Millisecond {
		idleInterval = 10 * time.Millisecond
	}
	idleTicker := time.NewTicker(idleInterval)
	disconnectType := "client_closed"
	for {
		select {
		case result := <-results:
			disconnectType = result.disconnectType
			if result.sendError {
				browserWriter.safeError(context.Background(), result.code, result.message, result.retryable)
			}
			goto finished
		case <-authorizationTicker.C:
			if !b.authorize(ctx, authorization) {
				disconnectType = "authorization_revoked"
				browserWriter.safeError(context.Background(), "authorization_revoked", "WebSSH authorization was revoked", false)
				goto finished
			}
		case <-idleTicker.C:
			if time.Since(time.Unix(0, lastActivity.Load())) >= b.config.IdleTimeout {
				disconnectType = "idle_timeout"
				browserWriter.safeError(context.Background(), "idle_timeout", "WebSSH session was idle too long", false)
				goto finished
			}
		case <-ctx.Done():
			disconnectType = "absolute_timeout"
			if errors.Is(b.ctx.Err(), context.Canceled) {
				disconnectType = "gateway_shutdown"
			}
			goto finished
		}
	}

finished:
	authorizationTicker.Stop()
	idleTicker.Stop()
	cancelProxy()
	session.closeNow()
	proxyWait.Wait()
	b.audit(authorization, "disconnected", disconnectType, ticket.connectionID)
}

func (b *Broker) proxyBrowserToConnector(ctx context.Context, browser *websocket.Conn, upstream *socketWriter, lastActivity *atomic.Int64) proxyResult {
	limiter := newRateLimiter(b.config.InputBytesPerSecond, b.config.InputBytesPerSecond*2)
	for {
		messageType, body, err := browser.Read(ctx)
		if err != nil {
			return proxyResult{disconnectType: "client_closed"}
		}
		if messageType != websocket.MessageText {
			wipe(body)
			return proxyResult{disconnectType: "invalid_client_message", code: "invalid_message", message: "WebSSH messages must be JSON text", sendError: true}
		}
		if !limiter.allow(int64(len(body))) {
			wipe(body)
			return proxyResult{disconnectType: "input_rate_limit", code: "input_rate_limit", message: "WebSSH input rate limit exceeded", sendError: true}
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(body, &header); err != nil {
			wipe(body)
			return proxyResult{disconnectType: "invalid_client_message", code: "invalid_message", message: "WebSSH message is invalid", sendError: true}
		}
		valid := false
		switch header.Type {
		case connectorprotocol.WebSSHMessageInput:
			var message connectorprotocol.WebSSHInputMessage
			valid = decodeStrictJSON(body, &message) == nil && len(message.Data) <= b.config.MaxInputMessageBytes
			wipe(message.Data)
		case connectorprotocol.WebSSHMessageResize:
			var message connectorprotocol.WebSSHResizeMessage
			valid = decodeStrictJSON(body, &message) == nil && validTerminalSize(message.Size)
		}
		if !valid {
			wipe(body)
			return proxyResult{disconnectType: "invalid_client_message", code: "invalid_message", message: "WebSSH message is invalid or too large", sendError: true}
		}
		if err := upstream.raw(ctx, body); err != nil {
			wipe(body)
			return proxyResult{disconnectType: "connector_closed", code: "connector_closed", message: "WebSSH Connector disconnected", retryable: true, sendError: true}
		}
		wipe(body)
		lastActivity.Store(time.Now().UnixNano())
	}
}

func (b *Broker) proxyConnectorToBrowser(ctx context.Context, upstream *websocket.Conn, browser *socketWriter, ticket *browserTicket, lastActivity *atomic.Int64) proxyResult {
	limiter := newRateLimiter(b.config.OutputBytesPerSecond, b.config.OutputBytesPerSecond*2)
	ready := false
	for {
		messageType, body, err := upstream.Read(ctx)
		if err != nil {
			return proxyResult{disconnectType: "connector_closed", code: "connector_closed", message: "WebSSH Connector disconnected", retryable: true, sendError: true}
		}
		if messageType != websocket.MessageText || !limiter.allow(int64(len(body))) {
			wipe(body)
			return proxyResult{disconnectType: "connector_protocol_error", code: "connector_protocol_error", message: "WebSSH Connector sent an invalid message", sendError: true}
		}
		var header struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(body, &header); err != nil {
			wipe(body)
			return proxyResult{disconnectType: "connector_protocol_error", code: "connector_protocol_error", message: "WebSSH Connector sent an invalid message", sendError: true}
		}
		terminal := false
		valid := false
		switch header.Type {
		case connectorprotocol.WebSSHMessageReady:
			var message connectorprotocol.WebSSHReadyMessage
			valid = !ready && decodeStrictJSON(body, &message) == nil && message.SessionID == string(ticket.upstreamSession) && validTerminalSize(message.Size)
			if valid {
				ready = true
				message.SessionID = ticket.connectionID
				wipe(body)
				if err := browser.json(ctx, message); err != nil {
					return proxyResult{disconnectType: "client_closed"}
				}
				lastActivity.Store(time.Now().UnixNano())
				continue
			}
		case connectorprotocol.WebSSHMessageOutput:
			var message connectorprotocol.WebSSHOutputMessage
			valid = ready && decodeStrictJSON(body, &message) == nil && len(message.Data) <= b.config.MaxOutputMessageBytes
			wipe(message.Data)
		case connectorprotocol.WebSSHMessageExit:
			var message connectorprotocol.WebSSHExitMessage
			valid = ready && decodeStrictJSON(body, &message) == nil
			terminal = valid
		case connectorprotocol.WebSSHMessageError:
			var message connectorprotocol.WebSSHErrorMessage
			valid = decodeStrictJSON(body, &message) == nil && len(message.Code) <= 128 && len(message.Message) <= 512
			terminal = valid
		}
		if !valid {
			wipe(body)
			return proxyResult{disconnectType: "connector_protocol_error", code: "connector_protocol_error", message: "WebSSH Connector sent an invalid message", sendError: true}
		}
		if err := browser.raw(ctx, body); err != nil {
			wipe(body)
			return proxyResult{disconnectType: "client_closed"}
		}
		wipe(body)
		lastActivity.Store(time.Now().UnixNano())
		if terminal {
			return proxyResult{disconnectType: "remote_exit"}
		}
	}
}

func (b *Broker) consumeTicket(hello HelloMessage) (*browserTicket, string) {
	decoded, err := base64.RawURLEncoding.DecodeString(hello.Ticket)
	if err != nil || len(decoded) != 32 {
		wipe(decoded)
		return nil, "invalid_ticket"
	}
	hash := sha256.Sum256(decoded)
	wipe(decoded)
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(now)
	entry, found := b.tickets[hash]
	if !found {
		if _, replayed := b.consumed[hash]; replayed {
			return nil, "ticket_replayed"
		}
		return nil, "invalid_ticket"
	}
	delete(b.tickets, hash)
	b.consumed[hash] = now.Add(b.config.TicketTTL)
	if !entry.expiresAt.After(now) {
		wipeTicket(entry)
		return nil, "ticket_expired"
	}
	binding, err := normalizeBinding(hello.Binding)
	if err != nil || hello.ConnectionID != entry.connectionID || hello.Type != MessageHello || !sameBinding(entry.binding, binding) {
		wipeTicket(entry)
		return nil, "ticket_binding_mismatch"
	}
	return entry, ""
}

func (b *Broker) originAllowed(request *http.Request) bool {
	values := request.Header.Values("Origin")
	if len(values) != 1 {
		return false
	}
	normalized, err := normalizeHTTPOrigin(values[0], b.config.Development)
	if err != nil {
		return false
	}
	_, allowed := b.origins[normalized]
	return allowed
}

func hasSubprotocol(values []string, required string) bool {
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			if strings.TrimSpace(candidate) == required {
				return true
			}
		}
	}
	return false
}

func (b *Broker) beginHandler() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.wait.Add(1)
	return true
}

func (b *Broker) registerSession(session *activeSession) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	b.active[session] = struct{}{}
	return true
}

func (b *Broker) unregisterSession(session *activeSession) {
	b.mu.Lock()
	delete(b.active, session)
	b.mu.Unlock()
}

func (b *Broker) dialConnector(ctx context.Context) (*websocket.Conn, *http.Response, error) {
	header := make(http.Header)
	header.Set("Origin", b.config.ConnectorOrigin)
	dialContext, cancel := context.WithTimeout(ctx, b.config.ConnectorDialTimeout)
	defer cancel()
	return websocket.Dial(dialContext, b.upstreamURL, &websocket.DialOptions{
		HTTPClient: b.upstreamHTTP, HTTPHeader: header,
		Subprotocols: []string{connectorprotocol.WebSSHSubprotocol}, CompressionMode: websocket.CompressionDisabled,
	})
}

func newUpstreamTransport(config Config) (string, *http.Client, error) {
	if _, err := normalizeHTTPOrigin(config.ConnectorOrigin, config.Development); err != nil {
		return "", nil, fmt.Errorf("invalid Connector WebSSH origin: %w", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	baseURL := strings.TrimRight(config.ConnectorBaseURL, "/")
	if config.ConnectorUnixSocket != "" {
		if config.ConnectorBaseURL != "" || !filepath.IsAbs(config.ConnectorUnixSocket) {
			return "", nil, errors.New("Connector Unix socket must be absolute and mutually exclusive with base URL")
		}
		socketPath := filepath.Clean(config.ConnectorUnixSocket)
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}
		baseURL = "http://connector.local"
	} else {
		parsed, err := url.Parse(baseURL)
		if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" ||
			parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() == "" {
			return "", nil, errors.New("Connector base URL must be a loopback HTTP URL with an explicit port")
		}
		address, err := netip.ParseAddr(parsed.Hostname())
		if err != nil || !address.IsLoopback() {
			return "", nil, errors.New("Connector base URL must use a loopback IP literal")
		}
	}
	client := &http.Client{
		Transport: transport, Timeout: config.ConnectorDialTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return "ws" + strings.TrimPrefix(baseURL, "http") + connectorprotocol.WebSSHConnectPath, client, nil
}

func writeHTTPError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]string{"code": code}})
}

type rateLimiter struct {
	mu     sync.Mutex
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func newRateLimiter(rate, burst int64) *rateLimiter {
	return &rateLimiter{rate: float64(rate), burst: float64(burst), tokens: float64(burst), last: time.Now()}
}

func (l *rateLimiter) allow(amount int64) bool {
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
