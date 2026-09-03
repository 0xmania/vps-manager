package main

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"time"

	connectorprotocol "vpsmanager/services/connector-protocol"
	"vpsmanager/services/connector/sshconnector"
	"vpsmanager/services/control-plane/internal/api"
	"vpsmanager/services/control-plane/internal/credentials"
	"vpsmanager/services/control-plane/internal/snapshot"
	"vpsmanager/services/control-plane/internal/store"
	"vpsmanager/services/keymanager"
	"vpsmanager/services/persistence"
)

const defaultConnectorClientTimeout = 100 * time.Second

type runtimeDependencies struct {
	repository      store.Repository
	credentialStore *credentials.Service
	collector       *snapshot.Collector
	prober          api.HostKeyProber
	readiness       []api.DependencyProbe
	connector       *connectorprotocol.Client
	installationID  string
	secretExecution bool
	close           func()
}

func loadRuntimeDependencies(ctx context.Context, devMode, allowPrivate bool) (runtimeDependencies, error) {
	if devMode {
		kms, err := credentials.NewRandomDevKMS()
		if err != nil {
			return runtimeDependencies{}, err
		}
		credentialStore, err := credentials.NewService(kms)
		if err != nil {
			return runtimeDependencies{}, err
		}
		connector := sshconnector.New()
		repository := store.NewMemory()
		var protocolClient *connectorprotocol.Client
		var readiness []api.DependencyProbe
		if connectorRuntimeConfigured() {
			protocolClient, err = loadConnectorClient()
			if err != nil {
				repository.Close()
				return runtimeDependencies{}, err
			}
			readiness = append(readiness, &protocolProber{client: protocolClient})
		}
		closeDependencies := func() {
			if protocolClient != nil {
				protocolClient.CloseIdleConnections()
			}
			repository.Close()
		}
		return runtimeDependencies{
			repository: repository, credentialStore: credentialStore,
			collector: snapshot.NewCollector(connector, snapshot.WithPrivateTargets(allowPrivate)), prober: connector,
			readiness: readiness, connector: protocolClient,
			installationID: "development", secretExecution: true, close: closeDependencies,
		}, nil
	}

	installationID := strings.TrimSpace(os.Getenv("VPSMGR_INSTALLATION_ID"))
	if installationID == "" {
		return runtimeDependencies{}, errors.New("VPSMGR_INSTALLATION_ID is required in production")
	}
	postgres, err := persistence.OpenPostgres(ctx, persistence.PostgresConfig{
		URL: os.Getenv("VPSMGR_POSTGRES_URL"), Environment: "production",
		ExpectedRole:    strings.TrimSpace(os.Getenv("VPSMGR_POSTGRES_EXPECTED_ROLE")),
		ApplicationName: "vps-manager-control-plane", ConnectTimeout: 5 * time.Second,
	})
	if err != nil {
		return runtimeDependencies{}, err
	}
	repository, err := store.NewPostgres(postgres, installationID, 5*time.Second)
	if err != nil {
		postgres.Close()
		return runtimeDependencies{}, err
	}
	redis, err := persistence.OpenRedis(ctx, persistence.RedisConfig{
		URL: os.Getenv("VPSMGR_REDIS_URL"), InstallationID: installationID, Environment: "production",
		ExpectedUsername: strings.TrimSpace(os.Getenv("VPSMGR_REDIS_EXPECTED_USERNAME")),
		TLSCAFile:        os.Getenv("VPSMGR_REDIS_TLS_CA_FILE"), TLSServerName: os.Getenv("VPSMGR_REDIS_TLS_SERVER_NAME"),
	})
	if err != nil {
		repository.Close()
		return runtimeDependencies{}, err
	}

	vault, err := keymanager.NewVaultTransit(keymanager.VaultConfig{
		Address: os.Getenv("VPSMGR_VAULT_ADDR"), TransitMount: envOr("VPSMGR_VAULT_TRANSIT_MOUNT", "transit"),
		KeyName: os.Getenv("VPSMGR_VAULT_KEY_NAME"), Namespace: os.Getenv("VPSMGR_VAULT_NAMESPACE"),
		Environment: "production", Capability: keymanager.WrapOnly,
		TLSCAFile: os.Getenv("VPSMGR_VAULT_TLS_CA_FILE"), TLSServerName: os.Getenv("VPSMGR_VAULT_TLS_SERVER_NAME"), RequestTimeout: 10 * time.Second,
	}, keymanager.FileTokenSource{Path: os.Getenv("VPSMGR_VAULT_TOKEN_FILE")})
	if err != nil {
		_ = redis.Close()
		repository.Close()
		return runtimeDependencies{}, err
	}
	credentialStore, err := credentials.NewSealingService(vault)
	if err != nil {
		_ = redis.Close()
		repository.Close()
		return runtimeDependencies{}, err
	}

	connector, err := loadConnectorClient()
	if err != nil {
		_ = redis.Close()
		repository.Close()
		return runtimeDependencies{}, err
	}
	probe := &protocolProber{client: connector}
	return runtimeDependencies{
		repository: repository, credentialStore: credentialStore,
		collector: snapshot.NewCollector(disabledRunner{}), prober: probe,
		readiness: []api.DependencyProbe{redis, probe}, connector: connector, installationID: installationID, secretExecution: false,
		close: func() { connector.CloseIdleConnections(); _ = redis.Close(); repository.Close() },
	}, nil
}

func loadConnectorClient() (*connectorprotocol.Client, error) {
	config, err := loadConnectorClientConfig()
	if err != nil {
		return nil, err
	}
	defer wipeRuntimeSecret(config.Key)
	return connectorprotocol.NewClient(config)
}

func loadConnectorClientConfig() (connectorprotocol.ClientConfig, error) {
	unixSocket := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_UNIX_SOCKET"))
	baseURL := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_URL"))
	if unixSocket == "" && baseURL == "" {
		baseURL = "http://127.0.0.1:9081"
	}
	encoded := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_HMAC_KEY"))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		key, err = base64.RawStdEncoding.Strict().DecodeString(encoded)
	}
	if err != nil || len(key) < 32 {
		wipeRuntimeSecret(key)
		return connectorprotocol.ClientConfig{}, errors.New("VPSMGR_CONNECTOR_HMAC_KEY must be base64 encoded and contain at least 32 bytes")
	}
	return connectorprotocol.ClientConfig{
		BaseURL: baseURL, UnixSocket: unixSocket,
		KeyID: strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_HMAC_KEY_ID")), Key: key, Timeout: defaultConnectorClientTimeout,
	}, nil
}

type protocolProber struct{ client *connectorprotocol.Client }

func (p *protocolProber) ProbeHostKey(ctx context.Context, address string, port int, _ bool) (sshconnector.HostKeyObservation, error) {
	response, err := p.client.ProbeHostKey(ctx, connectorprotocol.HostKeyProbeRequest{Target: connectorprotocol.ProbeTarget{Address: address, Port: port}})
	if err != nil {
		return sshconnector.HostKeyObservation{}, err
	}
	return sshconnector.HostKeyObservation{Algorithm: response.Algorithm, FingerprintSHA256: response.FingerprintSHA256, PublicKey: response.PublicKey, ResolvedAddress: response.ResolvedAddress}, nil
}

func (p *protocolProber) VerifyRuntime(ctx context.Context) error {
	health, err := p.client.Health(ctx)
	if err != nil || health.Status != "ok" || health.ProtocolVersion != connectorprotocol.ProtocolVersion {
		return errors.New("connector health or protocol version check failed")
	}
	return nil
}

type disabledRunner struct{}

func (disabledRunner) Run(context.Context, sshconnector.Config, sshconnector.Command) (sshconnector.Result, error) {
	return sshconnector.Result{}, credentials.ErrUnwrapUnavailable
}

func wipeRuntimeSecret(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
