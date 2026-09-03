package cloudflareprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	defaultRequestTimeout              = 15 * time.Second
	defaultPollInterval                = 250 * time.Millisecond
	defaultPollTimeout                 = 20 * time.Second
	defaultMaxModuleBytes        int64 = 1 << 20
	defaultMaxResponseBytes      int64 = 1 << 20
	defaultMaxIdempotencyEntries       = 1024
	maximumModuleBytes           int64 = 10 << 20
	maximumResponseBytes         int64 = 4 << 20
)

var errRedirectBlocked = errors.New("Cloudflare API redirect blocked")

type Client struct {
	accountID        string
	tokenOwner       TokenOwner
	tokenSource      TokenSource
	baseURL          string
	httpClient       *http.Client
	pollInterval     time.Duration
	pollTimeout      time.Duration
	maxModuleBytes   int64
	maxResponseBytes int64

	idemMu         sync.Mutex
	idem           map[string]*idempotencyEntry
	maxIdemEntries int
}

func (*Client) String() string   { return "cloudflareprovider.Client{credentials:[redacted]}" }
func (*Client) GoString() string { return "cloudflareprovider.Client{credentials:[redacted]}" }

func (c *Client) CloseIdleConnections() {
	c.httpClient.CloseIdleConnections()
}

func New(config Config, tokenSource TokenSource) (*Client, error) {
	if !accountIDPattern.MatchString(config.AccountID) || tokenSource == nil {
		return nil, validationError("configure")
	}
	if config.TokenOwner == "" {
		config.TokenOwner = TokenOwnerUser
	}
	if config.TokenOwner != TokenOwnerUser && config.TokenOwner != TokenOwnerAccount {
		return nil, validationError("configure")
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}
	if config.PollInterval == 0 {
		config.PollInterval = defaultPollInterval
	}
	if config.PollTimeout == 0 {
		config.PollTimeout = defaultPollTimeout
	}
	if config.MaxModuleBytes == 0 {
		config.MaxModuleBytes = defaultMaxModuleBytes
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = defaultMaxResponseBytes
	}
	if config.MaxIdempotencyEntries == 0 {
		config.MaxIdempotencyEntries = defaultMaxIdempotencyEntries
	}
	if config.RequestTimeout < time.Millisecond || config.RequestTimeout > time.Minute ||
		config.PollInterval < time.Millisecond || config.PollInterval > time.Minute ||
		config.PollTimeout < config.PollInterval || config.PollTimeout > 5*time.Minute ||
		config.MaxModuleBytes < 1 || config.MaxModuleBytes > maximumModuleBytes ||
		config.MaxResponseBytes < 1024 || config.MaxResponseBytes > maximumResponseBytes ||
		config.MaxIdempotencyEntries < 1 || config.MaxIdempotencyEntries > 100_000 {
		return nil, validationError("configure")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxIdleConnsPerHost = 8
	transport.ResponseHeaderTimeout = config.RequestTimeout
	client := &http.Client{Transport: transport}
	client.Timeout = config.RequestTimeout
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return errRedirectBlocked }

	return &Client{
		accountID:        config.AccountID,
		tokenOwner:       config.TokenOwner,
		tokenSource:      tokenSource,
		baseURL:          OfficialAPIBaseURL,
		httpClient:       client,
		pollInterval:     config.PollInterval,
		pollTimeout:      config.PollTimeout,
		maxModuleBytes:   config.MaxModuleBytes,
		maxResponseBytes: config.MaxResponseBytes,
		idem:             make(map[string]*idempotencyEntry),
		maxIdemEntries:   config.MaxIdempotencyEntries,
	}, nil
}

var _ Provider = (*Client)(nil)

type apiError struct {
	Code int `json:"code"`
}

type apiEnvelope[T any] struct {
	Success bool       `json:"success"`
	Errors  []apiError `json:"errors"`
	Result  T          `json:"result"`
}

type requestSpec struct {
	operation      string
	method         string
	path           string
	query          url.Values
	body           []byte
	contentType    string
	idempotencyKey string
}

func requestAPI[T any](ctx context.Context, client *Client, spec requestSpec) (T, error) {
	var zero T
	if ctx == nil {
		return zero, validationError(spec.operation)
	}
	endpoint := client.baseURL + spec.path
	if len(spec.query) > 0 {
		endpoint += "?" + spec.query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, spec.method, endpoint, bytes.NewReader(spec.body))
	if err != nil {
		return zero, validationError(spec.operation)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vpsmanager-cloudflare-provider/1")
	if spec.contentType != "" {
		req.Header.Set("Content-Type", spec.contentType)
	}
	if spec.idempotencyKey != "" {
		req.Header.Set("Idempotency-Key", spec.idempotencyKey)
	}
	token, err := client.tokenSource.Token(ctx)
	if err != nil || validateToken(token) != nil {
		wipe(token)
		return zero, &Error{Kind: ErrorAuthentication, Operation: spec.operation}
	}
	req.Header.Set("Authorization", "Bearer "+string(token))
	wipe(token)

	resp, err := client.httpClient.Do(req)
	req.Header.Del("Authorization")
	if err != nil {
		if errors.Is(err, errRedirectBlocked) {
			return zero, &Error{Kind: ErrorRedirect, Operation: spec.operation}
		}
		if errors.Is(err, context.Canceled) {
			return zero, &Error{Kind: ErrorCancelled, Operation: spec.operation}
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return zero, &Error{Kind: ErrorTimeout, Operation: spec.operation, Retryable: true}
		}
		return zero, &Error{Kind: ErrorTransport, Operation: spec.operation, Retryable: true}
	}
	defer resp.Body.Close()

	if resp.ContentLength > client.maxResponseBytes {
		return zero, &Error{Kind: ErrorResponseTooLarge, Operation: spec.operation, StatusCode: resp.StatusCode}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, client.maxResponseBytes+1))
	if err != nil {
		return zero, &Error{Kind: ErrorTransport, Operation: spec.operation, StatusCode: resp.StatusCode, Retryable: true}
	}
	if int64(len(body)) > client.maxResponseBytes {
		return zero, &Error{Kind: ErrorResponseTooLarge, Operation: spec.operation, StatusCode: resp.StatusCode}
	}
	mediaType, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return zero, statusError(spec.operation, resp.StatusCode, 0, resp.Header.Get("Retry-After"))
	}
	var envelope apiEnvelope[T]
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&envelope); err != nil {
		return zero, statusError(spec.operation, resp.StatusCode, 0, resp.Header.Get("Retry-After"))
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return zero, statusError(spec.operation, resp.StatusCode, 0, resp.Header.Get("Retry-After"))
	}
	providerCode := 0
	if len(envelope.Errors) > 0 {
		providerCode = envelope.Errors[0].Code
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices || !envelope.Success {
		return zero, statusError(spec.operation, resp.StatusCode, providerCode, resp.Header.Get("Retry-After"))
	}
	return envelope.Result, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func statusError(operation string, statusCode, providerCode int, retryAfterHeader string) error {
	providerErr := &Error{Operation: operation, StatusCode: statusCode, ProviderCode: providerCode}
	switch statusCode {
	case http.StatusUnauthorized:
		providerErr.Kind = ErrorAuthentication
	case http.StatusForbidden:
		providerErr.Kind = ErrorPermission
	case http.StatusNotFound:
		providerErr.Kind = ErrorNotFound
	case http.StatusConflict, http.StatusPreconditionFailed:
		providerErr.Kind = ErrorConflict
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		providerErr.Kind = ErrorTimeout
		providerErr.Retryable = true
	case http.StatusTooManyRequests:
		providerErr.Kind = ErrorRateLimited
		providerErr.Retryable = true
		if seconds, err := strconv.Atoi(retryAfterHeader); err == nil && seconds >= 0 && seconds <= 3600 {
			providerErr.RetryAfter = time.Duration(seconds) * time.Second
		}
	default:
		providerErr.Kind = ErrorProvider
		providerErr.Retryable = statusCode >= 500 || statusCode == 0
	}
	return providerErr
}
