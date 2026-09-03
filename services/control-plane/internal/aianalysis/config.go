package aianalysis

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"vpsmanager/services/ai"
)

const (
	EnvGatewayEndpoint         = "VPSMGR_AI_GATEWAY_ENDPOINT"
	EnvGatewayTokenFile        = "VPSMGR_AI_GATEWAY_TOKEN_FILE"
	EnvGatewayAllowedHosts     = "VPSMGR_AI_GATEWAY_ALLOWED_HOSTS"
	EnvGatewayTimeout          = "VPSMGR_AI_GATEWAY_TIMEOUT"
	EnvGatewayMaxRequestBytes  = "VPSMGR_AI_GATEWAY_MAX_REQUEST_BYTES"
	EnvGatewayMaxResponseBytes = "VPSMGR_AI_GATEWAY_MAX_RESPONSE_BYTES"
)

// LookupEnv matches os.LookupEnv.
type LookupEnv func(string) (string, bool)

// NewFromEnv constructs an adapter from deployment-owned environment values.
// With no gateway endpoint it selects offline mode; request data can never
// choose or override the destination.
func NewFromEnv() (*Adapter, error) {
	return NewFromLookup(os.LookupEnv)
}

func NewFromLookup(lookup LookupEnv) (*Adapter, error) {
	config, err := ConfigFromLookup(lookup)
	if err != nil {
		return nil, err
	}
	return New(config)
}

// ConfigFromLookup parses the optional gateway settings.
func ConfigFromLookup(lookup LookupEnv) (ai.Config, error) {
	if lookup == nil {
		return ai.Config{}, errors.New("AI gateway environment lookup is nil")
	}
	config := ai.Config{
		Endpoint:  envValue(lookup, EnvGatewayEndpoint),
		TokenFile: envValue(lookup, EnvGatewayTokenFile),
	}

	allowedHosts := envValue(lookup, EnvGatewayAllowedHosts)
	if allowedHosts != "" {
		parts := strings.Split(allowedHosts, ",")
		config.AllowedGatewayHosts = make([]string, 0, len(parts))
		seen := make(map[string]struct{}, len(parts))
		for _, part := range parts {
			host := strings.TrimSpace(part)
			if host == "" {
				return ai.Config{}, fmt.Errorf("%s contains an empty hostname", EnvGatewayAllowedHosts)
			}
			key := strings.ToLower(strings.TrimSuffix(host, "."))
			if _, duplicate := seen[key]; duplicate {
				return ai.Config{}, fmt.Errorf("%s contains a duplicate hostname", EnvGatewayAllowedHosts)
			}
			seen[key] = struct{}{}
			config.AllowedGatewayHosts = append(config.AllowedGatewayHosts, host)
		}
	}

	var err error
	if raw := envValue(lookup, EnvGatewayTimeout); raw != "" {
		config.Timeout, err = time.ParseDuration(raw)
		if err != nil {
			return ai.Config{}, fmt.Errorf("parse %s: %w", EnvGatewayTimeout, err)
		}
	}
	if raw := envValue(lookup, EnvGatewayMaxRequestBytes); raw != "" {
		config.MaxRequestBytes, err = parsePositiveInt64(EnvGatewayMaxRequestBytes, raw)
		if err != nil {
			return ai.Config{}, err
		}
	}
	if raw := envValue(lookup, EnvGatewayMaxResponseBytes); raw != "" {
		config.MaxResponseBytes, err = parsePositiveInt64(EnvGatewayMaxResponseBytes, raw)
		if err != nil {
			return ai.Config{}, err
		}
	}

	return config, nil
}

func envValue(lookup LookupEnv, name string) string {
	value, ok := lookup(name)
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func parsePositiveInt64(name, raw string) (int64, error) {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive base-10 integer", name)
	}
	return value, nil
}
