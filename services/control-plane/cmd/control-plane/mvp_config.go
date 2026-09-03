package main

import (
	"errors"
	"os"
	"strings"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/websshgateway"
)

func connectorRuntimeConfigured() bool {
	return strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_HMAC_KEY")) != "" ||
		strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_HMAC_KEY_ID")) != "" ||
		strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_URL")) != "" ||
		strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_UNIX_SOCKET")) != ""
}

func loadWebSSHConfig(devMode bool, connector *connectorprotocol.Client) (*websshgateway.Config, error) {
	publicURL := strings.TrimSpace(os.Getenv("VPSMGR_WEBSSH_PUBLIC_URL"))
	if publicURL == "" {
		return nil, nil
	}
	if !devMode || connector == nil {
		return nil, errors.New("VPSMGR_WEBSSH_PUBLIC_URL requires development mode and an external Connector")
	}
	originsRaw := strings.TrimSpace(os.Getenv("VPSMGR_WEBSSH_ALLOWED_ORIGINS"))
	if originsRaw == "" {
		return nil, errors.New("VPSMGR_WEBSSH_ALLOWED_ORIGINS is required when WebSSH is enabled")
	}
	origins := strings.Split(originsRaw, ",")
	for index := range origins {
		origins[index] = strings.TrimSpace(origins[index])
		if origins[index] == "" {
			return nil, errors.New("VPSMGR_WEBSSH_ALLOWED_ORIGINS contains an empty origin")
		}
	}
	return &websshgateway.Config{
		PublicWebSocketURL:  publicURL,
		Development:         true,
		AllowedOrigins:      origins,
		ConnectorBaseURL:    strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_URL")),
		ConnectorUnixSocket: strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_UNIX_SOCKET")),
		ConnectorOrigin:     envOr("VPSMGR_WEBSSH_CONNECTOR_ORIGIN", "http://127.0.0.1:8080"),
	}, nil
}
