package keymanager

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

// EncryptionContext is the canonical object binding for wrapped data keys.
// Version is the immutable credential version, not a schema version.
type EncryptionContext struct {
	InstallationID string `json:"installation_id"`
	CredentialID   string `json:"credential_id"`
	Version        uint64 `json:"version"`
	CredentialType string `json:"credential_type"`
}

var (
	contextIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	credentialPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

func (c EncryptionContext) AAD() ([]byte, error) {
	if !contextIDPattern.MatchString(c.InstallationID) || !contextIDPattern.MatchString(c.CredentialID) || c.Version == 0 || !credentialPattern.MatchString(c.CredentialType) {
		return nil, errors.New("encryption context is invalid")
	}
	return json.Marshal(c)
}

func ValidateEncryptionContext(aad []byte) error {
	if len(aad) == 0 || len(aad) > 1024 {
		return errors.New("encryption context is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(aad))
	decoder.DisallowUnknownFields()
	var contextValue EncryptionContext
	if err := decoder.Decode(&contextValue); err != nil {
		return errors.New("encryption context is invalid")
	}
	canonical, err := contextValue.AAD()
	if err != nil || !bytes.Equal(canonical, aad) {
		return errors.New("encryption context is not canonical")
	}
	return nil
}
