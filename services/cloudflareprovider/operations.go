package cloudflareprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	accountIDPattern   = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)
	scriptNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	moduleNamePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	uuidPattern        = regexp.MustCompile(`^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[1-8][A-Fa-f0-9]{3}-[89AaBb][A-Fa-f0-9]{3}-[A-Fa-f0-9]{12}$`)
	idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$`)
)

type tokenVerifyResult struct {
	ID        string     `json:"id"`
	Status    string     `json:"status"`
	ExpiresOn *time.Time `json:"expires_on"`
	NotBefore *time.Time `json:"not_before"`
}

type accountResult struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ValidateAccess verifies that the bearer token is active and can access the
// configured account. Cloudflare exposes no safe read-only endpoint that proves
// Workers Scripts Write; a 403 from upload/deploy is therefore classified as a
// permission error and must fail the provider job closed.
func (c *Client) ValidateAccess(ctx context.Context) (AccountAccess, error) {
	verifyPath := "/user/tokens/verify"
	if c.tokenOwner == TokenOwnerAccount {
		verifyPath = "/accounts/" + c.accountID + "/tokens/verify"
	}
	token, err := requestAPI[tokenVerifyResult](ctx, c, requestSpec{
		operation: "verify_token",
		method:    http.MethodGet,
		path:      verifyPath,
	})
	if err != nil {
		return AccountAccess{}, err
	}
	now := time.Now().UTC()
	if token.ID == "" || token.Status != "active" || (token.NotBefore != nil && token.NotBefore.After(now)) || (token.ExpiresOn != nil && !token.ExpiresOn.After(now)) {
		return AccountAccess{}, &Error{Kind: ErrorAuthentication, Operation: "verify_token"}
	}
	account, err := requestAPI[accountResult](ctx, c, requestSpec{
		operation: "verify_account_scope",
		method:    http.MethodGet,
		path:      "/accounts/" + c.accountID,
	})
	if err != nil {
		return AccountAccess{}, err
	}
	if account.ID != c.accountID {
		return AccountAccess{}, &Error{Kind: ErrorAccountScope, Operation: "verify_account_scope"}
	}
	return AccountAccess{
		AccountID:   account.ID,
		AccountName: account.Name,
		TokenID:     token.ID,
		TokenStatus: token.Status,
		NotBefore:   token.NotBefore,
		ExpiresAt:   token.ExpiresOn,
	}, nil
}

type versionResult struct {
	ID       string `json:"id"`
	Number   int64  `json:"number"`
	Metadata struct {
		CreatedOn *time.Time `json:"created_on"`
	} `json:"metadata"`
}

func (c *Client) UploadVersion(ctx context.Context, module PrebuiltModule) (Version, error) {
	if err := c.validateModule(module); err != nil {
		return Version{}, err
	}
	module.Source = append([]byte(nil), module.Source...)
	sourceDigest := sha256.Sum256(module.Source)
	fingerprint := fingerprint(
		module.ScriptName,
		module.MainModule,
		hex.EncodeToString(sourceDigest[:]),
		module.Message,
		module.Tag,
	)
	value, err := c.runIdempotent(ctx, "upload_version", module.ScriptName, module.IdempotencyKey, fingerprint, func() (any, error) {
		body, contentType, buildErr := buildVersionMultipart(module)
		if buildErr != nil {
			return nil, &Error{Kind: ErrorValidation, Operation: "upload_version"}
		}
		result, requestErr := requestAPI[versionResult](ctx, c, requestSpec{
			operation:      "upload_version",
			method:         http.MethodPost,
			path:           "/accounts/" + c.accountID + "/workers/scripts/" + module.ScriptName + "/versions",
			query:          url.Values{"bindings_inherit": []string{"strict"}},
			body:           body,
			contentType:    contentType,
			idempotencyKey: module.IdempotencyKey,
		})
		if requestErr != nil {
			return nil, requestErr
		}
		if !uuidPattern.MatchString(result.ID) || result.Number < 0 {
			return nil, &Error{Kind: ErrorProvider, Operation: "upload_version"}
		}
		return Version{
			ID:         result.ID,
			Number:     result.Number,
			CreatedAt:  result.Metadata.CreatedOn,
			ScriptName: module.ScriptName,
			SHA256:     hex.EncodeToString(sourceDigest[:]),
			SizeBytes:  int64(len(module.Source)),
		}, nil
	})
	if err != nil {
		return Version{}, err
	}
	version, ok := value.(Version)
	if !ok {
		return Version{}, &Error{Kind: ErrorProvider, Operation: "upload_version"}
	}
	return version, nil
}

func (c *Client) validateModule(module PrebuiltModule) error {
	if !scriptNamePattern.MatchString(module.ScriptName) || !moduleNamePattern.MatchString(module.MainModule) ||
		(!strings.HasSuffix(module.MainModule, ".js") && !strings.HasSuffix(module.MainModule, ".mjs")) ||
		len(module.Source) == 0 || int64(len(module.Source)) > c.maxModuleBytes || !utf8.Valid(module.Source) || bytes.IndexByte(module.Source, 0) >= 0 ||
		!validMessage(module.Message, 1000) || !validMessage(module.Tag, 100) || !idempotencyPattern.MatchString(module.IdempotencyKey) {
		return validationError("upload_version")
	}
	return nil
}

func buildVersionMultipart(module PrebuiltModule) ([]byte, string, error) {
	metadata := struct {
		MainModule  string            `json:"main_module"`
		Annotations map[string]string `json:"annotations,omitempty"`
	}{MainModule: module.MainModule}
	metadata.Annotations = make(map[string]string)
	if module.Message != "" {
		metadata.Annotations["workers/message"] = module.Message
	}
	if module.Tag != "" {
		metadata.Annotations["workers/tag"] = module.Tag
	}
	encodedMetadata, err := json.Marshal(metadata)
	if err != nil {
		return nil, "", err
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	metadataHeader := make(textproto.MIMEHeader)
	metadataHeader.Set("Content-Disposition", `form-data; name="metadata"`)
	metadataHeader.Set("Content-Type", "application/json")
	metadataPart, err := writer.CreatePart(metadataHeader)
	if err != nil {
		return nil, "", err
	}
	if _, err := metadataPart.Write(encodedMetadata); err != nil {
		return nil, "", err
	}
	moduleHeader := make(textproto.MIMEHeader)
	moduleHeader.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, module.MainModule, module.MainModule))
	moduleHeader.Set("Content-Type", "application/javascript+module")
	modulePart, err := writer.CreatePart(moduleHeader)
	if err != nil {
		return nil, "", err
	}
	if _, err := modulePart.Write(module.Source); err != nil {
		return nil, "", err
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return body.Bytes(), writer.FormDataContentType(), nil
}

type deploymentPayload struct {
	Strategy    string                    `json:"strategy"`
	Versions    []deploymentVersionResult `json:"versions"`
	Annotations map[string]string         `json:"annotations,omitempty"`
}

type deploymentVersionResult struct {
	Percentage float64 `json:"percentage"`
	VersionID  string  `json:"version_id"`
}

type deploymentResult struct {
	ID        string                    `json:"id"`
	CreatedOn *time.Time                `json:"created_on"`
	Source    string                    `json:"source"`
	Strategy  string                    `json:"strategy"`
	Versions  []deploymentVersionResult `json:"versions"`
}

func (c *Client) DeployVersion(ctx context.Context, request DeployRequest) (Deployment, error) {
	if !validDeploymentInput(request.ScriptName, request.VersionID, request.Message, request.IdempotencyKey) {
		return Deployment{}, validationError("deploy_version")
	}
	fingerprint := fingerprint(request.ScriptName, request.VersionID, request.Message)
	value, err := c.runIdempotent(ctx, "deploy_version", request.ScriptName, request.IdempotencyKey, fingerprint, func() (any, error) {
		created, createErr := c.createDeployment(ctx, "deploy_version", request.ScriptName, request.VersionID, request.Message, "deployment", request.IdempotencyKey)
		if createErr != nil {
			return nil, createErr
		}
		return c.WaitForDeployment(ctx, WaitDeploymentRequest{
			ScriptName: request.ScriptName, DeploymentID: created.ID, VersionID: request.VersionID,
		})
	})
	if err != nil {
		return Deployment{}, err
	}
	deployment, ok := value.(Deployment)
	if !ok {
		return Deployment{}, &Error{Kind: ErrorProvider, Operation: "deploy_version"}
	}
	return deployment, nil
}

func (c *Client) Rollback(ctx context.Context, request RollbackRequest) (Deployment, error) {
	if !validDeploymentInput(request.ScriptName, request.TargetVersionID, request.Message, request.IdempotencyKey) {
		return Deployment{}, validationError("rollback")
	}
	fingerprint := fingerprint(request.ScriptName, request.TargetVersionID, request.Message)
	value, err := c.runIdempotent(ctx, "rollback", request.ScriptName, request.IdempotencyKey, fingerprint, func() (any, error) {
		history, historyErr := c.ListDeployments(ctx, request.ScriptName)
		if historyErr != nil {
			return nil, historyErr
		}
		found := false
		for _, deployment := range history {
			for _, version := range deployment.Versions {
				if version.VersionID == request.TargetVersionID {
					found = true
				}
			}
		}
		if !found {
			return nil, &Error{Kind: ErrorNotFound, Operation: "rollback"}
		}
		if len(history) > 0 && deploymentHasVersionAt100(history[0], request.TargetVersionID) {
			return nil, &Error{Kind: ErrorConflict, Operation: "rollback"}
		}
		created, createErr := c.createDeployment(ctx, "rollback", request.ScriptName, request.TargetVersionID, request.Message, "rollback", request.IdempotencyKey)
		if createErr != nil {
			return nil, createErr
		}
		return c.WaitForDeployment(ctx, WaitDeploymentRequest{
			ScriptName: request.ScriptName, DeploymentID: created.ID, VersionID: request.TargetVersionID,
		})
	})
	if err != nil {
		return Deployment{}, err
	}
	deployment, ok := value.(Deployment)
	if !ok {
		return Deployment{}, &Error{Kind: ErrorProvider, Operation: "rollback"}
	}
	return deployment, nil
}

func (c *Client) createDeployment(ctx context.Context, operation, scriptName, versionID, message, triggeredBy, idempotencyKey string) (Deployment, error) {
	payload := deploymentPayload{
		Strategy:    "percentage",
		Versions:    []deploymentVersionResult{{Percentage: 100, VersionID: versionID}},
		Annotations: map[string]string{"workers/triggered_by": triggeredBy},
	}
	if message != "" {
		payload.Annotations["workers/message"] = message
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Deployment{}, &Error{Kind: ErrorValidation, Operation: operation}
	}
	result, err := requestAPI[deploymentResult](ctx, c, requestSpec{
		operation:      operation,
		method:         http.MethodPost,
		path:           "/accounts/" + c.accountID + "/workers/scripts/" + scriptName + "/deployments",
		body:           body,
		contentType:    "application/json",
		idempotencyKey: idempotencyKey,
	})
	if err != nil {
		return Deployment{}, err
	}
	return convertDeployment(operation, scriptName, result)
}

func (c *Client) GetDeployment(ctx context.Context, scriptName, deploymentID string) (Deployment, error) {
	if !scriptNamePattern.MatchString(scriptName) || !uuidPattern.MatchString(deploymentID) {
		return Deployment{}, validationError("get_deployment")
	}
	result, err := requestAPI[deploymentResult](ctx, c, requestSpec{
		operation: "get_deployment",
		method:    http.MethodGet,
		path:      "/accounts/" + c.accountID + "/workers/scripts/" + scriptName + "/deployments/" + deploymentID,
	})
	if err != nil {
		return Deployment{}, err
	}
	return convertDeployment("get_deployment", scriptName, result)
}

type deploymentListResult struct {
	Deployments []deploymentResult `json:"deployments"`
}

func (c *Client) ListDeployments(ctx context.Context, scriptName string) ([]Deployment, error) {
	if !scriptNamePattern.MatchString(scriptName) {
		return nil, validationError("list_deployments")
	}
	result, err := requestAPI[deploymentListResult](ctx, c, requestSpec{
		operation: "list_deployments",
		method:    http.MethodGet,
		path:      "/accounts/" + c.accountID + "/workers/scripts/" + scriptName + "/deployments",
	})
	if err != nil {
		return nil, err
	}
	deployments := make([]Deployment, 0, len(result.Deployments))
	for _, item := range result.Deployments {
		deployment, convertErr := convertDeployment("list_deployments", scriptName, item)
		if convertErr != nil {
			return nil, convertErr
		}
		deployments = append(deployments, deployment)
	}
	return deployments, nil
}

func (c *Client) WaitForDeployment(ctx context.Context, request WaitDeploymentRequest) (Deployment, error) {
	if !scriptNamePattern.MatchString(request.ScriptName) || !uuidPattern.MatchString(request.DeploymentID) || !uuidPattern.MatchString(request.VersionID) {
		return Deployment{}, validationError("wait_deployment")
	}
	pollContext, cancel := context.WithTimeout(ctx, c.pollTimeout)
	defer cancel()
	for {
		deployment, err := c.GetDeployment(pollContext, request.ScriptName, request.DeploymentID)
		if err == nil && deploymentHasVersionAt100(deployment, request.VersionID) {
			deployment.State = DeploymentStateActive
			return deployment, nil
		}
		if err != nil && !IsKind(err, ErrorNotFound) {
			if IsKind(err, ErrorCancelled) && ctx.Err() == nil {
				return Deployment{}, &Error{Kind: ErrorTimeout, Operation: "wait_deployment", Retryable: true}
			}
			return Deployment{}, err
		}
		timer := time.NewTimer(c.pollInterval)
		select {
		case <-pollContext.Done():
			timer.Stop()
			if ctx.Err() == context.Canceled {
				return Deployment{}, &Error{Kind: ErrorCancelled, Operation: "wait_deployment"}
			}
			return Deployment{}, &Error{Kind: ErrorTimeout, Operation: "wait_deployment", Retryable: true}
		case <-timer.C:
		}
	}
}

func convertDeployment(operation, scriptName string, result deploymentResult) (Deployment, error) {
	if !uuidPattern.MatchString(result.ID) || result.Strategy != "percentage" || len(result.Versions) < 1 || len(result.Versions) > 2 {
		return Deployment{}, &Error{Kind: ErrorProvider, Operation: operation}
	}
	versions := make([]DeploymentVersion, 0, len(result.Versions))
	total := 0.0
	for _, item := range result.Versions {
		if !uuidPattern.MatchString(item.VersionID) || item.Percentage < 0.01 || item.Percentage > 100 {
			return Deployment{}, &Error{Kind: ErrorProvider, Operation: operation}
		}
		total += item.Percentage
		versions = append(versions, DeploymentVersion{VersionID: item.VersionID, Percentage: item.Percentage})
	}
	if total > 100.000001 {
		return Deployment{}, &Error{Kind: ErrorProvider, Operation: operation}
	}
	return Deployment{
		ID: result.ID, ScriptName: scriptName, State: DeploymentStatePending,
		CreatedAt: result.CreatedOn, Source: result.Source, Versions: versions,
	}, nil
}

func deploymentHasVersionAt100(deployment Deployment, versionID string) bool {
	return len(deployment.Versions) == 1 && deployment.Versions[0].VersionID == versionID && deployment.Versions[0].Percentage == 100
}

func validDeploymentInput(scriptName, versionID, message, idempotencyKey string) bool {
	return scriptNamePattern.MatchString(scriptName) && uuidPattern.MatchString(versionID) && validMessage(message, 1000) && idempotencyPattern.MatchString(idempotencyKey)
}

func validMessage(value string, maxBytes int) bool {
	return len(value) <= maxBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func fingerprint(parts ...string) string {
	digest := sha256.New()
	for _, part := range parts {
		_, _ = digest.Write([]byte(part))
		_, _ = digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}
