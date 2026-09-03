package websshgateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"unicode"

	connectorprotocol "vpsmanager/services/connector-protocol"
)

func normalizeBinding(value Binding) (Binding, error) {
	if !validID(value.PrincipalID) || !validID(value.SessionID) || !validID(value.HostID) ||
		!validID(value.CredentialID) || value.Action != connectorprotocol.ActionWebSSH {
		return Binding{}, errors.New("invalid WebSSH binding")
	}
	if len(value.Roles) == 0 || len(value.Roles) > 32 {
		return Binding{}, errors.New("WebSSH binding must contain between one and 32 roles")
	}
	roles := append([]string(nil), value.Roles...)
	for _, role := range roles {
		if !validID(role) {
			return Binding{}, errors.New("invalid WebSSH role")
		}
	}
	sort.Strings(roles)
	for index := 1; index < len(roles); index++ {
		if roles[index] == roles[index-1] {
			return Binding{}, errors.New("duplicate WebSSH role")
		}
	}
	value.Roles = roles
	return value, nil
}

func validID(value string) bool {
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

func validateReason(value string) error {
	if value == "" || len(value) > 500 || value != strings.TrimSpace(value) {
		return errors.New("WebSSH reason must contain between one and 500 trimmed characters")
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\t' {
			return errors.New("WebSSH reason contains control characters")
		}
	}
	return nil
}

func validateIssueRequest(request IssueRequest) error {
	if _, err := normalizeBinding(request.Binding); err != nil {
		return err
	}
	if err := validateReason(request.Reason); err != nil {
		return err
	}
	if strings.TrimSpace(request.Target.Address) == "" || request.Target.Address != strings.TrimSpace(request.Target.Address) ||
		len(request.Target.Address) > 253 || request.Target.Port < 1 || request.Target.Port > 65535 ||
		!validID(request.Target.User) || len(request.PinnedHostKey) == 0 || len(request.PinnedHostKey) > 16<<10 ||
		len(request.Credential.PrivateKeyPEM) == 0 || len(request.Credential.PrivateKeyPEM) > 48<<10 ||
		len(request.Credential.Passphrase) > 4<<10 || !validTerminalSize(request.InitialSize) {
		return errors.New("invalid WebSSH target, credential, host key, or terminal size")
	}
	return nil
}

func validTerminalSize(size connectorprotocol.TerminalSize) bool {
	return size.Columns >= 20 && size.Columns <= 500 && size.Rows >= 5 && size.Rows <= 300 &&
		size.WidthPixels <= 10_000 && size.HeightPixels <= 10_000
}

func sameBinding(left, right Binding) bool {
	if left.PrincipalID != right.PrincipalID || left.SessionID != right.SessionID || left.HostID != right.HostID ||
		left.CredentialID != right.CredentialID || left.Action != right.Action || len(left.Roles) != len(right.Roles) {
		return false
	}
	for index := range left.Roles {
		if left.Roles[index] != right.Roles[index] {
			return false
		}
	}
	return true
}

func normalizeOrigins(values []string, development bool) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalized, err := normalizeHTTPOrigin(value, development)
		if err != nil {
			return nil, err
		}
		result[normalized] = struct{}{}
	}
	if len(result) == 0 {
		return nil, errors.New("at least one exact WebSSH origin is required")
	}
	return result, nil
}

func normalizeHTTPOrigin(value string, development bool) (string, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "*?,") {
		return "", errors.New("WebSSH origins must be exact origins without wildcards")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("WebSSH origin must not contain credentials, path, query, or fragment")
	}
	if parsed.Scheme == "https" {
		return "https://" + strings.ToLower(parsed.Host), nil
	}
	if parsed.Scheme != "http" || !development || !isLoopbackHost(parsed.Hostname()) {
		return "", errors.New("non-HTTPS WebSSH origins are allowed only on loopback in development")
	}
	return "http://" + strings.ToLower(parsed.Host), nil
}

func validatePublicWebSocketURL(value string, development bool) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != ConnectPath {
		return "", errors.New("public WebSocket URL must use the fixed WebSSH path without credentials, query, or fragment")
	}
	if parsed.Scheme == "wss" {
		return parsed.String(), nil
	}
	if parsed.Scheme != "ws" || !development || !isLoopbackHost(parsed.Hostname()) {
		return "", errors.New("public WebSocket URL must use wss; ws is allowed only on loopback in development")
	}
	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	address, err := netip.ParseAddr(host)
	return err == nil && address.IsLoopback()
}

func decodeStrictJSON(body []byte, destination any) error {
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

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
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

func cloneCredential(value connectorprotocol.Credential) connectorprotocol.Credential {
	return connectorprotocol.Credential{
		PrivateKeyPEM: append([]byte(nil), value.PrivateKeyPEM...),
		Passphrase:    append([]byte(nil), value.Passphrase...),
	}
}
