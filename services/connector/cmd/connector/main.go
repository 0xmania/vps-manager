package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"vpsmanager/services/connector/service"
)

var version = "dev"

type config struct {
	listen                listenSpec
	keyID                 string
	hmacKey               []byte
	allowPrivateTargets   bool
	maxConcurrent         int
	webSSHOrigins         []string
	webSSHIdleTimeout     time.Duration
	webSSHAbsoluteTimeout time.Duration
	webSSHMaxConcurrent   int
}

type listenSpec struct {
	network string
	address string
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	runbookCfg, err := loadRunbookConfig()
	if err != nil {
		wipe(cfg.hmacKey)
		return err
	}
	handler, err := service.New(service.Options{
		KeyID: cfg.keyID, HMACKey: cfg.hmacKey, ServiceVersion: version,
		AllowPrivateTargets: cfg.allowPrivateTargets, MaxConcurrent: cfg.maxConcurrent,
		WebSSH: service.WebSSHOptions{
			AllowedOrigins: cfg.webSSHOrigins, AllowPrivateTargets: cfg.allowPrivateTargets,
			IdleTimeout: cfg.webSSHIdleTimeout, AbsoluteTimeout: cfg.webSSHAbsoluteTimeout,
			MaxConcurrent: cfg.webSSHMaxConcurrent,
		},
	})
	if err != nil {
		wipe(cfg.hmacKey)
		return fmt.Errorf("configure connector service: %w", err)
	}
	defer handler.Close()
	runbookHandler, err := service.NewRunbookHandler(service.RunbookOptions{
		KeyID: cfg.keyID, HMACKey: cfg.hmacKey, MutationsEnabled: runbookCfg.mutationsEnabled,
		AllowPrivateTargets: cfg.allowPrivateTargets, MaxConcurrent: runbookCfg.maxConcurrent,
		MaxIdempotencyJobs: runbookCfg.maxIdempotency,
	})
	wipe(cfg.hmacKey)
	if err != nil {
		return fmt.Errorf("configure connector runbooks: %w", err)
	}
	listener, cleanup, err := listen(cfg.listen)
	if err != nil {
		return err
	}
	defer cleanup()

	server := &http.Server{
		Handler: runbookHandler.Wrap(handler), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 3 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
		ConnContext: service.WithConnection,
	}
	shutdownContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errChannel := make(chan error, 1)
	go func() { errChannel <- server.Serve(listener) }()
	log.Printf("SSH Connector %s listening on %s://%s", version, cfg.listen.network, cfg.listen.address)
	if cfg.allowPrivateTargets {
		log.Print("SSH Connector private-target policy is explicitly enabled")
	}
	if runbookCfg.mutationsEnabled {
		log.Print("SSH Connector mutating runbook policy is explicitly enabled")
	}

	select {
	case <-shutdownContext.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shut down connector: %w", err)
		}
		serveErr := <-errChannel
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve connector: %w", serveErr)
		}
		return nil
	case serveErr := <-errChannel:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return fmt.Errorf("serve connector: %w", serveErr)
		}
		return nil
	}
}

func loadConfig() (config, error) {
	listenValue := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_LISTEN"))
	if listenValue == "" {
		listenValue = "tcp://127.0.0.1:9081"
	}
	parsedListen, err := parseListenSpec(listenValue)
	if err != nil {
		return config{}, err
	}
	keyID := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_HMAC_KEY_ID"))
	if keyID == "" {
		return config{}, errors.New("VPSMGR_CONNECTOR_HMAC_KEY_ID is required")
	}
	encodedKey := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_HMAC_KEY"))
	if encodedKey == "" {
		return config{}, errors.New("VPSMGR_CONNECTOR_HMAC_KEY is required and must be base64 encoded")
	}
	key, err := decodeBase64Key(encodedKey)
	if err != nil {
		return config{}, errors.New("VPSMGR_CONNECTOR_HMAC_KEY must be valid base64")
	}
	if len(key) < 32 {
		wipe(key)
		return config{}, errors.New("VPSMGR_CONNECTOR_HMAC_KEY must decode to at least 32 bytes")
	}
	allowPrivate := false
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_ALLOW_PRIVATE_TARGETS")); value != "" {
		allowPrivate, err = strconv.ParseBool(value)
		if err != nil {
			wipe(key)
			return config{}, errors.New("VPSMGR_CONNECTOR_ALLOW_PRIVATE_TARGETS must be true or false")
		}
	}
	maxConcurrent := 8
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_MAX_CONCURRENT")); value != "" {
		maxConcurrent, err = strconv.Atoi(value)
		if err != nil || maxConcurrent < 1 || maxConcurrent > 256 {
			wipe(key)
			return config{}, errors.New("VPSMGR_CONNECTOR_MAX_CONCURRENT must be between 1 and 256")
		}
	}
	webSSH, err := loadWebSSHConfig()
	if err != nil {
		wipe(key)
		return config{}, err
	}
	return config{
		listen: parsedListen, keyID: keyID, hmacKey: key,
		allowPrivateTargets: allowPrivate, maxConcurrent: maxConcurrent,
		webSSHOrigins: webSSH.origins, webSSHIdleTimeout: webSSH.idleTimeout,
		webSSHAbsoluteTimeout: webSSH.absoluteTimeout, webSSHMaxConcurrent: webSSH.maxConcurrent,
	}, nil
}

func parseListenSpec(value string) (listenSpec, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
		return listenSpec{}, errors.New("connector listen address is invalid")
	}
	switch parsed.Scheme {
	case "tcp":
		if parsed.Path != "" || parsed.Host == "" {
			return listenSpec{}, errors.New("TCP connector listen address must be tcp://LOOPBACK_IP:PORT")
		}
		host, portText, err := net.SplitHostPort(parsed.Host)
		if err != nil {
			return listenSpec{}, errors.New("TCP connector listen address must include a port")
		}
		address, err := netip.ParseAddr(host)
		if err != nil || !address.IsLoopback() {
			return listenSpec{}, errors.New("TCP connector listener must use a loopback IP literal")
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return listenSpec{}, errors.New("TCP connector listener port is invalid")
		}
		return listenSpec{network: "tcp", address: net.JoinHostPort(address.String(), strconv.Itoa(port))}, nil
	case "unix":
		if parsed.Host != "" || parsed.Path == "" || !filepath.IsAbs(parsed.Path) {
			return listenSpec{}, errors.New("Unix connector listen address must contain an absolute path")
		}
		cleaned := filepath.Clean(parsed.Path)
		if len(cleaned) > 100 {
			return listenSpec{}, errors.New("Unix connector socket path is too long")
		}
		return listenSpec{network: "unix", address: cleaned}, nil
	default:
		return listenSpec{}, errors.New("connector listener must use tcp:// or unix://")
	}
}

func listen(spec listenSpec) (net.Listener, func(), error) {
	if spec.network == "unix" {
		if _, err := os.Lstat(spec.address); err == nil {
			return nil, func() {}, errors.New("connector Unix socket path already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, func() {}, fmt.Errorf("inspect connector Unix socket path: %w", err)
		}
	}
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), spec.network, spec.address)
	if err != nil {
		return nil, func() {}, fmt.Errorf("listen for connector requests: %w", err)
	}
	cleanup := func() { _ = listener.Close() }
	if spec.network == "unix" {
		if err := os.Chmod(spec.address, 0o600); err != nil {
			_ = listener.Close()
			return nil, func() {}, fmt.Errorf("restrict connector Unix socket permissions: %w", err)
		}
		cleanup = func() {
			_ = listener.Close()
			if info, err := os.Lstat(spec.address); err == nil && info.Mode()&os.ModeSocket != 0 {
				_ = os.Remove(spec.address)
			}
		}
	}
	return listener, cleanup, nil
}

func decodeBase64Key(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err == nil {
		return decoded, nil
	}
	return base64.RawStdEncoding.Strict().DecodeString(value)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
