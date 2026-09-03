package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vpsmanager/services/control-plane/internal/aianalysis"
	"vpsmanager/services/control-plane/internal/api"
	"vpsmanager/services/control-plane/internal/auth"
	"vpsmanager/services/control-plane/internal/identity"
)

const (
	defaultJobTimeout       = 100 * time.Second
	defaultHTTPWriteTimeout = 110 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("control plane stopped", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	listenAddress := envOr("VPSMGR_LISTEN_ADDR", "127.0.0.1:8080")
	devMode, err := boolEnv("VPSMGR_DEV_MODE", false)
	if err != nil {
		return err
	}
	allowPrivate, err := boolEnv("VPSMGR_ALLOW_PRIVATE_TARGETS", false)
	if err != nil {
		return err
	}
	allowDevNonLoopback, err := boolEnv("VPSMGR_DEV_ALLOW_NON_LOOPBACK", false)
	if err != nil {
		return err
	}
	if err := validateDevelopmentNetworkPolicy(listenAddress, devMode, allowDevNonLoopback, allowPrivate); err != nil {
		return err
	}
	sessionTTL, err := durationEnv("VPSMGR_SESSION_TTL", time.Hour)
	if err != nil {
		return err
	}
	jobTimeout, err := loadJobTimeout()
	if err != nil {
		return err
	}
	mutationsEnabled, err := boolEnv("VPSMGR_ENABLE_MUTATIONS", false)
	if err != nil {
		return err
	}
	cloudflareExecutionEnabled, err := boolEnv("VPSMGR_ENABLE_CLOUDFLARE_EXECUTION", false)
	if err != nil {
		return err
	}
	aiAnalyzer, err := aianalysis.NewFromEnv()
	if err != nil {
		return err
	}
	identityVerifier, err := loadIdentityVerifier(devMode)
	if err != nil {
		return err
	}

	startupContext, cancelStartup := context.WithTimeout(context.Background(), 20*time.Second)
	dependencies, err := loadRuntimeDependencies(startupContext, devMode, allowPrivate)
	cancelStartup()
	if err != nil {
		return err
	}
	defer dependencies.close()
	webSSHConfig, err := loadWebSSHConfig(devMode, dependencies.connector)
	if err != nil {
		return err
	}
	var cloudflareFactory api.CloudflareProviderFactory
	if cloudflareExecutionEnabled {
		cloudflareFactory = api.NewCloudflareProviderFactory()
	}
	server, err := api.NewServer(api.Config{
		DevMode: devMode, DevBootstrapToken: os.Getenv("VPSMGR_DEV_BOOTSTRAP_TOKEN"),
		SessionTTL: sessionTTL, JobTimeout: jobTimeout, AllowPrivateTargets: allowPrivate,
		IdentityVerifier: identityVerifier, InstallationID: dependencies.installationID,
		SecretExecutionEnabled: dependencies.secretExecution, ReadinessChecks: dependencies.readiness,
		AIAnalyzer: aiAnalyzer, ConnectorClient: dependencies.connector, WebSSHConfig: webSSHConfig,
		RunbookConnector: dependencies.connector, MutationsEnabled: mutationsEnabled,
		CloudflareExecutionEnabled: cloudflareExecutionEnabled,
		CloudflareProviderFactory:  cloudflareFactory,
	}, dependencies.repository, auth.NewSessions(), dependencies.credentialStore, dependencies.collector, dependencies.prober)
	if err != nil {
		return err
	}
	defer server.Close()

	httpServer := newControlPlaneHTTPServer(listenAddress, accessLog(logger, server.Handler()))
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-shutdownContext.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	logger.Info("control plane listening", "address", listenAddress, "dev_mode", devMode, "storage", dependencies.repository.StorageMode(), "private_targets", allowPrivate, "secret_execution", dependencies.secretExecution)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func loadJobTimeout() (time.Duration, error) {
	return durationEnv("VPSMGR_JOB_TIMEOUT", defaultJobTimeout)
}

func newControlPlaneHTTPServer(listenAddress string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: listenAddress, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: defaultHTTPWriteTimeout, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
}

func validateDevelopmentNetworkPolicy(listenAddress string, devMode, allowDevNonLoopback, allowPrivate bool) error {
	if allowDevNonLoopback && !devMode {
		return errors.New("VPSMGR_DEV_ALLOW_NON_LOOPBACK requires VPSMGR_DEV_MODE=true")
	}
	if devMode && !loopbackListenAddress(listenAddress) && !allowDevNonLoopback {
		return errors.New("development authentication on a non-loopback listener requires VPSMGR_DEV_ALLOW_NON_LOOPBACK=true")
	}
	if allowPrivate && !devMode {
		return errors.New("the coarse private-target escape hatch is allowed only in development mode")
	}
	return nil
}

func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		response := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("http handler panic", "method", r.Method, "path", r.URL.Path)
				if !response.wroteHeader {
					http.Error(response, "internal server error", http.StatusInternalServerError)
				}
			}
			logger.Info("http request", "method", r.Method, "path", r.URL.Path, "status", response.status, "duration_ms", time.Since(started).Milliseconds())
		}()
		next.ServeHTTP(response, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status, w.wroteHeader = status, true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(value []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(value)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func boolEnv(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, errors.New(name + " must be true or false")
	}
	return parsed, nil
}

func durationEnv(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed <= 0 {
		return 0, errors.New(name + " must be a positive Go duration")
	}
	return parsed, nil
}

func loadIdentityVerifier(devMode bool) (*identity.Verifier, error) {
	issuer := strings.TrimSpace(os.Getenv("VPSMGR_IDENTITY_ISSUER"))
	audience := strings.TrimSpace(os.Getenv("VPSMGR_IDENTITY_AUDIENCE"))
	keyID := strings.TrimSpace(os.Getenv("VPSMGR_IDENTITY_KEY_ID"))
	encodedKey := strings.TrimSpace(os.Getenv("VPSMGR_IDENTITY_PUBLIC_KEY"))
	configured := issuer != "" || audience != "" || keyID != "" || encodedKey != ""
	if !configured {
		if devMode {
			return nil, nil
		}
		return nil, errors.New("production mode requires the signed identity bridge configuration")
	}
	if issuer == "" || audience == "" || keyID == "" || encodedKey == "" {
		return nil, errors.New("VPSMGR_IDENTITY_ISSUER, VPSMGR_IDENTITY_AUDIENCE, VPSMGR_IDENTITY_KEY_ID and VPSMGR_IDENTITY_PUBLIC_KEY must be configured together")
	}
	key, err := decodePublicKey(encodedKey)
	if err != nil {
		return nil, err
	}
	return identity.NewVerifier(identity.Config{
		Issuer: issuer, Audience: audience, KeyID: keyID, PublicKey: key,
	})
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawStdEncoding.Strict().DecodeString(value)
	if err != nil {
		decoded, err = base64.StdEncoding.Strict().DecodeString(value)
	}
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("VPSMGR_IDENTITY_PUBLIC_KEY must be a base64-encoded Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func loopbackListenAddress(value string) bool {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
