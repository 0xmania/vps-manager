package ai

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultTimeout          = 10 * time.Second
	defaultMaxRequestBytes  = 64 << 10
	defaultMaxResponseBytes = 64 << 10
	hardMaxPayloadBytes     = 256 << 10
)

var (
	errRedirectBlocked  = errors.New("redirect blocked")
	errResponseTooLarge = errors.New("response too large")
)

type Config struct {
	Endpoint            string
	TokenFile           string
	AllowedGatewayHosts []string
	Timeout             time.Duration
	MaxRequestBytes     int64
	MaxResponseBytes    int64
	RootCAs             *x509.CertPool
}

type Analyzer struct {
	endpoint         *url.URL
	tokenFile        string
	timeout          time.Duration
	maxRequestBytes  int64
	maxResponseBytes int64
	client           *http.Client
	readToken        func(string) ([]byte, error)
}

// New creates an analyzer. An empty endpoint uses local rule ordering.
func New(config Config) (*Analyzer, error) {
	config.Timeout = defaultDuration(config.Timeout, defaultTimeout)
	config.MaxRequestBytes = defaultSize(config.MaxRequestBytes, defaultMaxRequestBytes)
	config.MaxResponseBytes = defaultSize(config.MaxResponseBytes, defaultMaxResponseBytes)
	if config.Timeout <= 0 || config.Timeout > 30*time.Second {
		return nil, errors.New("AI gateway timeout must be between zero and 30 seconds")
	}
	if config.MaxRequestBytes <= 0 || config.MaxRequestBytes > hardMaxPayloadBytes || config.MaxResponseBytes <= 0 || config.MaxResponseBytes > hardMaxPayloadBytes {
		return nil, errors.New("AI gateway payload limit is invalid")
	}
	analyzer := &Analyzer{
		timeout:          config.Timeout,
		maxRequestBytes:  config.MaxRequestBytes,
		maxResponseBytes: config.MaxResponseBytes,
		readToken:        readTokenFile,
	}
	if strings.TrimSpace(config.Endpoint) == "" {
		if config.TokenFile != "" || len(config.AllowedGatewayHosts) != 0 {
			return nil, errors.New("offline AI mode cannot configure gateway credentials or hosts")
		}
		return analyzer, nil
	}
	endpoint, err := validateEndpoint(config.Endpoint, config.AllowedGatewayHosts)
	if err != nil {
		return nil, err
	}
	if config.TokenFile == "" || !filepath.IsAbs(config.TokenFile) {
		return nil, errors.New("AI gateway token file must be an absolute path")
	}
	analyzer.endpoint = endpoint
	analyzer.tokenFile = filepath.Clean(config.TokenFile)
	analyzer.client = secureHTTPClient(config.Timeout, config.RootCAs)
	return analyzer, nil
}

// Analyze returns gateway output or the local rule ordering.
func (analyzer *Analyzer) Analyze(ctx context.Context, findings []Finding) (Outcome, error) {
	if err := validateFindings(findings); err != nil {
		return Outcome{}, errInvalidFindings
	}
	fallback := func(reason FallbackReason) Outcome {
		return Outcome{Analysis: deterministicAnalysis(findings), Mode: ModeRulesFallback, FallbackReason: reason}
	}
	if len(findings) == 0 {
		return fallback(FallbackNone), nil
	}
	if analyzer.endpoint == nil {
		return fallback(FallbackGatewayDisabled), nil
	}

	token, err := analyzer.readToken(analyzer.tokenFile)
	if err != nil {
		return fallback(FallbackCredentialUnavailable), nil
	}
	defer wipe(token)

	payload, err := buildGatewayRequest(findings)
	if err != nil || int64(len(payload)) > analyzer.maxRequestBytes {
		return fallback(FallbackTransportError), nil
	}
	requestContext, cancel := context.WithTimeout(ctx, analyzer.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, analyzer.endpoint.String(), bytes.NewReader(payload))
	if err != nil {
		return fallback(FallbackTransportError), nil
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "vpsmanager-ai-gateway/1")
	authorization := make([]byte, len("Bearer ")+len(token))
	copy(authorization, "Bearer ")
	copy(authorization[len("Bearer "):], token)
	request.Header.Set("Authorization", string(authorization))
	wipe(authorization)

	response, err := analyzer.client.Do(request)
	request.Header.Del("Authorization")
	if err != nil {
		switch {
		case errors.Is(err, errRedirectBlocked):
			return fallback(FallbackRedirectBlocked), nil
		case errors.Is(err, context.DeadlineExceeded), errors.Is(requestContext.Err(), context.DeadlineExceeded), isTimeout(err):
			return fallback(FallbackTimeout), nil
		default:
			return fallback(FallbackTransportError), nil
		}
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fallback(FallbackHTTPError), nil
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return fallback(FallbackInvalidResponse), nil
	}
	body, err := readLimited(response.Body, analyzer.maxResponseBytes)
	if err != nil {
		if errors.Is(err, errResponseTooLarge) {
			return fallback(FallbackResponseTooLarge), nil
		}
		return fallback(FallbackTransportError), nil
	}
	defer wipe(body)
	analysis, err := decodeAnalysis(body)
	if err != nil || validateAnalysis(analysis, findings) != nil {
		return fallback(FallbackInvalidResponse), nil
	}
	return Outcome{Analysis: analysis, Mode: ModeGateway, FallbackReason: FallbackNone}, nil
}

func validateEndpoint(raw string, allowedHosts []string) (*url.URL, error) {
	endpoint, err := url.Parse(raw)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return nil, errors.New("AI gateway endpoint must be an HTTPS URL without credentials, query, or fragment")
	}
	host := canonicalHost(endpoint.Hostname())
	if host == "" || len(allowedHosts) == 0 {
		return nil, errors.New("AI gateway requires an exact hostname allowlist")
	}
	allowed := false
	for _, configuredHost := range allowedHosts {
		if canonicalHost(configuredHost) == "" || strings.Contains(configuredHost, ":") && net.ParseIP(configuredHost) == nil {
			return nil, errors.New("AI gateway allowlist entries must be hostnames without ports")
		}
		if canonicalHost(configuredHost) == host {
			allowed = true
		}
	}
	if !allowed {
		return nil, errors.New("AI gateway endpoint host is not allowlisted")
	}
	return endpoint, nil
}

func canonicalHost(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" || strings.ContainsAny(value, "/*?@#[]\\") {
		return ""
	}
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-' && r != ':' {
			return ""
		}
	}
	return value
}

func secureHTTPClient(timeout time.Duration, rootCAs *x509.CertPool) *http.Client {
	var roots *x509.CertPool
	if rootCAs != nil {
		roots = rootCAs.Clone()
	}
	dialTimeout := min(timeout, 5*time.Second)
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: -1}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:   dialTimeout,
		ResponseHeaderTimeout: timeout,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		DisableKeepAlives:     true,
		MaxIdleConns:          0,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errRedirectBlocked
		},
	}
}

func decodeAnalysis(body []byte) (Analysis, error) {
	var analysis Analysis
	if err := json.Unmarshal(body, &analysis); err != nil {
		return Analysis{}, errors.New("invalid gateway response")
	}
	return analysis, nil
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, errors.New("gateway response read failed")
	}
	if int64(len(body)) > limit {
		return nil, errResponseTooLarge
	}
	return body, nil
}

func isTimeout(err error) bool {
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func defaultSize(value, fallback int64) int64 {
	if value == 0 {
		return fallback
	}
	return value
}

func wipe(value []byte) {
	clear(value)
}
