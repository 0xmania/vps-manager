package connectorprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultClientTimeout          = 100 * time.Second
	defaultMaxResponseBytes int64 = 3 << 20
)

type ClientConfig struct {
	BaseURL          string
	UnixSocket       string
	KeyID            string
	Key              []byte
	Timeout          time.Duration
	MaxResponseBytes int64
	Now              func() time.Time
}

type Client struct {
	baseURL          string
	http             *http.Client
	signer           *Signer
	maxResponseBytes int64
}

// NewClient creates a client that can send credentials only to an IP-literal
// loopback HTTP endpoint or an absolute Unix-domain socket path.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultClientTimeout
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = defaultMaxResponseBytes
	}
	if cfg.MaxResponseBytes > 16<<20 {
		return nil, errors.New("connector response limit must not exceed 16 MiB")
	}
	signer, err := NewSigner(SignerConfig{KeyID: cfg.KeyID, Key: cfg.Key, Now: cfg.Now})
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	if cfg.UnixSocket != "" {
		if cfg.BaseURL != "" {
			return nil, errors.New("base URL and Unix socket are mutually exclusive")
		}
		if !filepath.IsAbs(cfg.UnixSocket) {
			return nil, errors.New("Unix socket path must be absolute")
		}
		socketPath := filepath.Clean(cfg.UnixSocket)
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		}
		baseURL = "http://connector.local"
	} else if err := validateLoopbackBaseURL(baseURL); err != nil {
		return nil, err
	}
	return &Client{
		baseURL: baseURL, http: &http.Client{
			Transport: transport, Timeout: cfg.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		signer: signer, maxResponseBytes: cfg.MaxResponseBytes,
	}, nil
}

func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

func (c *Client) RuntimeSnapshot(ctx context.Context, request RuntimeSnapshotRequest) (RuntimeSnapshotResponse, error) {
	var response RuntimeSnapshotResponse
	request.ProtocolVersion = ProtocolVersion
	err := c.post(ctx, RuntimeSnapshotPath, request, &response)
	return response, err
}

func (c *Client) ProbeHostKey(ctx context.Context, request HostKeyProbeRequest) (HostKeyProbeResponse, error) {
	var response HostKeyProbeResponse
	request.ProtocolVersion = ProtocolVersion
	err := c.post(ctx, HostKeyProbePath, request, &response)
	return response, err
}

// WebSSHTicket sends the credential only over the authenticated local
// Connector channel. Callers remain responsible for wiping their request-owned
// credential slices after this method returns.
func (c *Client) WebSSHTicket(ctx context.Context, request WebSSHTicketRequest) (WebSSHTicketResponse, error) {
	var response WebSSHTicketResponse
	request.ProtocolVersion = ProtocolVersion
	err := c.post(ctx, WebSSHTicketPath, request, &response)
	return response, err
}

func (c *Client) Health(ctx context.Context) (HealthResponse, error) {
	var response HealthResponse
	err := c.get(ctx, HealthPath, &response)
	return response, err
}

func (c *Client) Version(ctx context.Context) (VersionResponse, error) {
	var response VersionResponse
	err := c.get(ctx, VersionPath, &response)
	return response, err
}

func (c *Client) post(ctx context.Context, path string, payload, destination any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encode connector request: %w", err)
	}
	defer wipeBytes(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create connector request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	if err := c.signer.Sign(request, body); err != nil {
		return err
	}
	return c.do(request, destination)
}

func (c *Client) get(ctx context.Context, path string, destination any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("create connector request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	return c.do(request, destination)
}

func (c *Client) do(request *http.Request, destination any) error {
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("call connector: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, c.maxResponseBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read connector response: %w", err)
	}
	if int64(len(body)) > c.maxResponseBytes {
		return errors.New("connector response exceeded configured limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var envelope ErrorEnvelope
		if err := decodeOneJSON(body, &envelope); err != nil {
			return &RemoteError{StatusCode: response.StatusCode, Detail: ErrorDetail{Code: "invalid_error_response"}}
		}
		return &RemoteError{StatusCode: response.StatusCode, Detail: envelope.Error}
	}
	if err := decodeOneJSON(body, destination); err != nil {
		return fmt.Errorf("decode connector response: %w", err)
	}
	return nil
}

func validateLoopbackBaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
		return errors.New("connector base URL must be a loopback HTTP URL")
	}
	if parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("connector base URL must not contain credentials, path, query, or fragment")
	}
	host := parsed.Hostname()
	address, err := netip.ParseAddr(host)
	if err != nil || !address.IsLoopback() {
		return errors.New("connector base URL host must be a loopback IP literal")
	}
	if parsed.Port() == "" {
		return errors.New("connector base URL must include a port")
	}
	return nil
}

func decodeOneJSON(body []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
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

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
