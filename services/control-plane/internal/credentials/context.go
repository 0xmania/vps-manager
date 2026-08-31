package credentials

import (
	"errors"
	"strings"

	"vpsmanager/services/keymanager"
)

// ContextAAD binds an envelope to this installation, object, immutable secret
// id, version and secret type. It emits the canonical Vault Transit context.
func ContextAAD(installationID, objectID, secretID, secretType string) ([]byte, error) {
	if strings.Contains(objectID, ":") || strings.Contains(secretID, ":") {
		return nil, errors.New("encryption context object ids are invalid")
	}
	return (keymanager.EncryptionContext{
		InstallationID: installationID,
		CredentialID:   objectID + ":" + secretID,
		Version:        1,
		CredentialType: secretType,
	}).AAD()
}
