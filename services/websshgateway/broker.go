package websshgateway

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	connectorprotocol "vpsmanager/services/connector-protocol"
)

var (
	ErrClosed         = errors.New("WebSSH gateway is closed")
	ErrUnauthorized   = errors.New("WebSSH authorization denied")
	ErrCapacity       = errors.New("WebSSH gateway capacity reached")
	ErrInvalidRequest = errors.New("invalid WebSSH issue request")
	ErrConnector      = errors.New("Connector WebSSH ticket request failed")
)

const (
	defaultTicketTTL             = 20 * time.Second
	defaultHandshakeTimeout      = 5 * time.Second
	defaultConnectorDialTimeout  = 5 * time.Second
	defaultAuthorizationTimeout  = 2 * time.Second
	defaultAuthorizationInterval = 5 * time.Second
	defaultIdleTimeout           = 10 * time.Minute
	defaultAbsoluteTimeout       = time.Hour
	defaultWriteTimeout          = 5 * time.Second
	defaultMaxConcurrent         = 4
	defaultMaxTickets            = 128
	defaultInputMessageBytes     = 16 << 10
	defaultOutputMessageBytes    = 16 << 10
	defaultInputBytesPerSecond   = 64 << 10
	defaultOutputBytesPerSecond  = 256 << 10
)

type browserTicket struct {
	connectionID     string
	binding          Binding
	reason           string
	upstreamTicket   []byte
	upstreamSession  []byte
	connectorBinding connectorprotocol.WebSSHBinding
	expiresAt        time.Time
}

// Broker owns browser tickets and the fixed-path WebSocket gateway handler.
type Broker struct {
	config       Config
	connector    *connectorprotocol.Client
	authorizer   Authorizer
	auditor      Auditor
	origins      map[string]struct{}
	publicURL    string
	upstreamURL  string
	upstreamHTTP *http.Client
	now          func() time.Time
	random       io.Reader

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	closed    bool
	issuing   int
	tickets   map[[sha256.Size]byte]*browserTicket
	consumed  map[[sha256.Size]byte]time.Time
	active    map[*activeSession]struct{}
	connSlots chan struct{}
	wait      sync.WaitGroup
}

// New constructs a broker backed by connectorprotocol.Client, which provides
// the protocol HMAC signer, replay nonce, no-proxy transport, and no-redirect
// policy for ticket issuance.
func New(config Config, connector *connectorprotocol.Client, authorizer Authorizer, auditor Auditor) (*Broker, error) {
	if connector == nil {
		return nil, errors.New("Connector client is required")
	}
	if authorizer == nil {
		return nil, errors.New("WebSSH authorizer is required")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Random == nil {
		config.Random = rand.Reader
	}
	if err := applyConfigDefaults(&config); err != nil {
		return nil, err
	}
	origins, err := normalizeOrigins(config.AllowedOrigins, config.Development)
	if err != nil {
		return nil, err
	}
	publicURL, err := validatePublicWebSocketURL(config.PublicWebSocketURL, config.Development)
	if err != nil {
		return nil, err
	}
	upstreamURL, upstreamHTTP, err := newUpstreamTransport(config)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	broker := &Broker{
		config: config, connector: connector, authorizer: authorizer, auditor: auditor,
		origins: origins, publicURL: publicURL, upstreamURL: upstreamURL, upstreamHTTP: upstreamHTTP,
		now: config.Now, random: config.Random, ctx: ctx, cancel: cancel,
		tickets: make(map[[sha256.Size]byte]*browserTicket), consumed: make(map[[sha256.Size]byte]time.Time),
		active: make(map[*activeSession]struct{}), connSlots: make(chan struct{}, config.MaxConcurrent),
	}
	broker.wait.Add(1)
	go broker.pruneLoop()
	return broker, nil
}

func applyConfigDefaults(config *Config) error {
	setDurationDefault(&config.TicketTTL, defaultTicketTTL)
	setDurationDefault(&config.HandshakeTimeout, defaultHandshakeTimeout)
	setDurationDefault(&config.ConnectorDialTimeout, defaultConnectorDialTimeout)
	setDurationDefault(&config.AuthorizationTimeout, defaultAuthorizationTimeout)
	setDurationDefault(&config.AuthorizationInterval, defaultAuthorizationInterval)
	setDurationDefault(&config.IdleTimeout, defaultIdleTimeout)
	setDurationDefault(&config.AbsoluteTimeout, defaultAbsoluteTimeout)
	setDurationDefault(&config.WriteTimeout, defaultWriteTimeout)
	setIntDefault(&config.MaxConcurrent, defaultMaxConcurrent)
	setIntDefault(&config.MaxOutstandingTickets, defaultMaxTickets)
	setIntDefault(&config.MaxInputMessageBytes, defaultInputMessageBytes)
	setIntDefault(&config.MaxOutputMessageBytes, defaultOutputMessageBytes)
	setInt64Default(&config.InputBytesPerSecond, defaultInputBytesPerSecond)
	setInt64Default(&config.OutputBytesPerSecond, defaultOutputBytesPerSecond)

	if config.TicketTTL > 30*time.Second || config.HandshakeTimeout > 15*time.Second ||
		config.ConnectorDialTimeout > 30*time.Second || config.AuthorizationTimeout > 5*time.Second ||
		config.AuthorizationInterval > 5*time.Second || config.IdleTimeout > time.Hour ||
		config.AbsoluteTimeout > 8*time.Hour || config.AbsoluteTimeout < config.IdleTimeout ||
		config.WriteTimeout > 10*time.Second {
		return errors.New("WebSSH timeout configuration is outside the allowed bounds")
	}
	if config.MaxConcurrent > 64 || config.MaxOutstandingTickets > 4096 ||
		config.MaxInputMessageBytes > 64<<10 || config.MaxOutputMessageBytes > 64<<10 ||
		config.InputBytesPerSecond > 4<<20 || config.OutputBytesPerSecond > 8<<20 {
		return errors.New("WebSSH capacity or byte limit is outside the allowed bounds")
	}
	return nil
}

func setDurationDefault(value *time.Duration, fallback time.Duration) {
	if *value <= 0 {
		*value = fallback
	}
}

func setIntDefault(value *int, fallback int) {
	if *value <= 0 {
		*value = fallback
	}
}

func setInt64Default(value *int64, fallback int64) {
	if *value <= 0 {
		*value = fallback
	}
}

// Issue exchanges a consumed credential buffer for an independent browser
// ticket. The browser response omits the Connector ticket and session ID.
func (b *Broker) Issue(ctx context.Context, request *IssueRequest) (IssueResponse, error) {
	if request == nil {
		return IssueResponse{}, fmt.Errorf("%w: body is required", ErrInvalidRequest)
	}
	defer wipeCredential(&request.Credential)
	if err := validateIssueRequest(*request); err != nil {
		return IssueResponse{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	binding, _ := normalizeBinding(request.Binding)
	request.Binding = binding
	authorization := Authorization{Binding: cloneBinding(binding), Reason: request.Reason}
	if !b.authorize(ctx, authorization) {
		b.audit(authorization, "issue_denied", "authorization_denied", "")
		return IssueResponse{}, ErrUnauthorized
	}
	if !b.reserveTicket() {
		return IssueResponse{}, ErrCapacity
	}
	defer b.releaseTicketReservation()

	credential := cloneCredential(request.Credential)
	connectorRequest := connectorprotocol.WebSSHTicketRequest{
		Binding: connectorprotocol.WebSSHBinding{
			PrincipalID: binding.PrincipalID, HostID: binding.HostID,
			CredentialID: binding.CredentialID, Action: connectorprotocol.ActionWebSSH,
		},
		Target: request.Target, PinnedHostKey: request.PinnedHostKey,
		Credential: credential, InitialSize: request.InitialSize,
	}
	defer wipeCredential(&connectorRequest.Credential)
	connectorResponse, err := b.connector.WebSSHTicket(ctx, connectorRequest)
	if err != nil {
		b.audit(authorization, "issue_failed", "connector_ticket_failed", "")
		return IssueResponse{}, fmt.Errorf("%w: %v", ErrConnector, err)
	}
	upstreamTicket, upstreamSession, err := validateConnectorResponse(connectorResponse, b.now())
	connectorResponse.Ticket = ""
	connectorResponse.SessionID = ""
	if err != nil {
		wipe(upstreamTicket)
		wipe(upstreamSession)
		return IssueResponse{}, fmt.Errorf("%w: invalid response", ErrConnector)
	}
	stored := false
	defer func() {
		if !stored {
			wipe(upstreamTicket)
			wipe(upstreamSession)
		}
	}()

	browserRaw := make([]byte, 32)
	connectionRaw := make([]byte, 16)
	if _, err := io.ReadFull(b.random, browserRaw); err != nil {
		wipe(browserRaw)
		wipe(connectionRaw)
		return IssueResponse{}, errors.New("generate WebSSH browser ticket")
	}
	if _, err := io.ReadFull(b.random, connectionRaw); err != nil {
		wipe(browserRaw)
		wipe(connectionRaw)
		return IssueResponse{}, errors.New("generate WebSSH connection ID")
	}
	browserValue := base64.RawURLEncoding.EncodeToString(browserRaw)
	connectionID := base64.RawURLEncoding.EncodeToString(connectionRaw)
	hash := sha256.Sum256(browserRaw)
	wipe(browserRaw)
	wipe(connectionRaw)
	now := b.now()
	expiresAt := now.Add(b.config.TicketTTL)
	if connectorResponse.ExpiresAt.Before(expiresAt) {
		expiresAt = connectorResponse.ExpiresAt
	}
	if !expiresAt.After(now) {
		return IssueResponse{}, fmt.Errorf("%w: expired response", ErrConnector)
	}
	entry := &browserTicket{
		connectionID: connectionID, binding: cloneBinding(binding), reason: request.Reason,
		upstreamTicket: upstreamTicket, upstreamSession: upstreamSession,
		connectorBinding: connectorRequest.Binding, expiresAt: expiresAt,
	}
	if !b.storeTicket(hash, entry) {
		wipeTicket(entry)
		return IssueResponse{}, ErrCapacity
	}
	stored = true
	b.audit(authorization, "issued", "", connectionID)
	return IssueResponse{
		ProtocolVersion: ProtocolVersion, Ticket: browserValue, ConnectionID: connectionID,
		ExpiresAt: expiresAt.UTC(), WebSocketURL: b.publicURL,
	}, nil
}

func validateConnectorResponse(response connectorprotocol.WebSSHTicketResponse, now time.Time) ([]byte, []byte, error) {
	if response.ProtocolVersion != connectorprotocol.ProtocolVersion || !response.ExpiresAt.After(now) ||
		response.ExpiresAt.After(now.Add(time.Minute)) {
		return nil, nil, errors.New("invalid Connector WebSSH response")
	}
	ticketDecoded, err := base64.RawURLEncoding.DecodeString(response.Ticket)
	if err != nil || len(ticketDecoded) != 32 {
		wipe(ticketDecoded)
		return nil, nil, errors.New("invalid Connector ticket")
	}
	wipe(ticketDecoded)
	sessionDecoded, err := base64.RawURLEncoding.DecodeString(response.SessionID)
	if err != nil || len(sessionDecoded) != 16 {
		wipe(sessionDecoded)
		return nil, nil, errors.New("invalid Connector session")
	}
	wipe(sessionDecoded)
	return []byte(response.Ticket), []byte(response.SessionID), nil
}

func (b *Broker) authorize(parent context.Context, authorization Authorization) bool {
	ctx, cancel := context.WithTimeout(parent, b.config.AuthorizationTimeout)
	defer cancel()
	return b.authorizer.AuthorizeWebSSH(ctx, cloneAuthorization(authorization)) == nil
}

func (b *Broker) reserveTicket() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(b.now())
	if b.closed || len(b.tickets)+b.issuing >= b.config.MaxOutstandingTickets {
		return false
	}
	b.issuing++
	return true
}

func (b *Broker) releaseTicketReservation() {
	b.mu.Lock()
	if b.issuing > 0 {
		b.issuing--
	}
	b.mu.Unlock()
}

func (b *Broker) storeTicket(hash [sha256.Size]byte, ticket *browserTicket) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pruneLocked(b.now())
	if b.closed || len(b.tickets) >= b.config.MaxOutstandingTickets || len(b.consumed) >= b.config.MaxOutstandingTickets*4 {
		return false
	}
	if _, exists := b.tickets[hash]; exists {
		return false
	}
	b.tickets[hash] = ticket
	return true
}

func (b *Broker) pruneLoop() {
	defer b.wait.Done()
	interval := b.config.TicketTTL / 2
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.mu.Lock()
			b.pruneLocked(b.now())
			b.mu.Unlock()
		}
	}
}

func (b *Broker) pruneLocked(now time.Time) {
	for hash, ticket := range b.tickets {
		if !ticket.expiresAt.After(now) {
			wipeTicket(ticket)
			delete(b.tickets, hash)
		}
	}
	for hash, expiresAt := range b.consumed {
		if !expiresAt.After(now) {
			delete(b.consumed, hash)
		}
	}
}

func cloneBinding(value Binding) Binding {
	value.Roles = append([]string(nil), value.Roles...)
	return value
}

func cloneAuthorization(value Authorization) Authorization {
	value.Binding = cloneBinding(value.Binding)
	return value
}

func wipeTicket(ticket *browserTicket) {
	if ticket == nil {
		return
	}
	wipe(ticket.upstreamTicket)
	wipe(ticket.upstreamSession)
	ticket.upstreamTicket = nil
	ticket.upstreamSession = nil
	ticket.binding.Roles = nil
}

func (b *Broker) audit(authorization Authorization, event, disconnectType, connectionID string) {
	if b.auditor == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.config.AuthorizationTimeout)
	defer cancel()
	_ = b.auditor.AuditWebSSH(ctx, AuditEvent{
		At: b.now().UTC(), Event: event, PrincipalID: authorization.Binding.PrincipalID,
		SessionID: authorization.Binding.SessionID, Roles: append([]string(nil), authorization.Binding.Roles...),
		HostID: authorization.Binding.HostID, CredentialID: authorization.Binding.CredentialID,
		Action: authorization.Binding.Action, ConnectionID: connectionID,
		Reason: authorization.Reason, DisconnectType: disconnectType,
	})
}

// Close cancels active sessions, clears all ticket material, and waits for
// handlers and background cleanup to stop.
func (b *Broker) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	for hash, ticket := range b.tickets {
		wipeTicket(ticket)
		delete(b.tickets, hash)
	}
	active := make([]*activeSession, 0, len(b.active))
	for session := range b.active {
		active = append(active, session)
	}
	b.mu.Unlock()
	b.cancel()
	for _, session := range active {
		session.closeNow()
	}
	b.wait.Wait()
	b.connector.CloseIdleConnections()
	b.upstreamHTTP.CloseIdleConnections()
	return nil
}
