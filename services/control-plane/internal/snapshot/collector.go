package snapshot

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"vpsmanager/services/connector/sshconnector"
	"vpsmanager/services/control-plane/internal/model"
)

type Runner interface {
	Run(context.Context, sshconnector.Config, sshconnector.Command) (sshconnector.Result, error)
}

type Collector struct {
	runner              Runner
	now                 func() time.Time
	allowPrivateTargets bool
}

type Option func(*Collector)

func WithPrivateTargets(allowed bool) Option {
	return func(collector *Collector) { collector.allowPrivateTargets = allowed }
}

func NewCollector(runner Runner, options ...Option) *Collector {
	collector := &Collector{runner: runner, now: time.Now}
	for _, option := range options {
		option(collector)
	}
	return collector
}

func (c *Collector) Collect(ctx context.Context, host model.Host, authMethod ssh.AuthMethod) (model.RuntimeSnapshot, error) {
	if host.HostKey == nil {
		return model.RuntimeSnapshot{}, errors.New("host key is not pinned")
	}
	pinned, err := sshconnector.ParsePinnedHostKey(host.HostKey.PublicKey)
	if err != nil {
		return model.RuntimeSnapshot{}, errors.New("stored host key is invalid")
	}
	result, err := c.runner.Run(ctx, sshconnector.Config{
		Address:             host.Address,
		Port:                host.Port,
		User:                host.Username,
		Auth:                authMethod,
		PinnedHostKey:       pinned,
		ConnectTimeout:      10 * time.Second,
		CommandTimeout:      20 * time.Second,
		MaxOutputBytes:      64 << 10,
		AllowPrivateTargets: c.allowPrivateTargets,
	}, sshconnector.RuntimeSnapshotCommand())
	if err != nil {
		return model.RuntimeSnapshot{}, err
	}
	return parseLinuxSnapshot(result.Stdout, c.now().UTC()), nil
}

func parseLinuxSnapshot(output []byte, observedAt time.Time) model.RuntimeSnapshot {
	snapshot := model.RuntimeSnapshot{
		ObservedAt:  observedAt,
		FieldErrors: make(map[string]string),
	}
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 1024), 64<<10)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 2 || seen[parts[0]] {
			continue
		}
		seen[parts[0]] = true
		switch parts[0] {
		case "hostname":
			snapshot.Hostname = boundedText(parts[1], 255)
		case "kernel":
			snapshot.Kernel = boundedText(parts[1], 512)
		case "uptime":
			if value, err := strconv.ParseUint(parts[1], 10, 64); err == nil {
				snapshot.UptimeSeconds = value
			} else {
				snapshot.FieldErrors["uptimeSeconds"] = "unavailable"
			}
		case "load":
			if len(parts) != 4 {
				snapshot.FieldErrors["load"] = "unavailable"
				continue
			}
			valid := true
			for i := range snapshot.Load {
				value, err := strconv.ParseFloat(parts[i+1], 64)
				if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
					valid = false
					break
				}
				snapshot.Load[i] = value
			}
			if !valid {
				snapshot.Load = [3]float64{}
				snapshot.FieldErrors["load"] = "unavailable"
			}
		case "memory_kib":
			if len(parts) != 3 {
				snapshot.FieldErrors["memory"] = "unavailable"
				continue
			}
			total, errTotal := strconv.ParseUint(parts[1], 10, 64)
			available, errAvailable := strconv.ParseUint(parts[2], 10, 64)
			if errTotal != nil || errAvailable != nil || available > total || total > ^uint64(0)/1024 {
				snapshot.FieldErrors["memory"] = "unavailable"
				continue
			}
			snapshot.MemoryTotalBytes = total * 1024
			snapshot.MemoryAvailableBytes = available * 1024
		case "cpu_model":
			snapshot.CPUModel = boundedText(parts[1], 512)
		case "cpu_logical":
			value, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil || value == 0 || value > 65536 {
				snapshot.FieldErrors["cpuLogicalCores"] = "unavailable"
			} else {
				snapshot.CPULogicalCores = uint32(value)
			}
		case "filesystem":
			if len(parts) != 5 || len(snapshot.Filesystems) >= 256 {
				snapshot.FieldErrors["filesystems"] = "partial or unavailable"
				continue
			}
			total, errTotal := strconv.ParseUint(parts[2], 10, 64)
			used, errUsed := strconv.ParseUint(parts[3], 10, 64)
			free, errFree := strconv.ParseUint(parts[4], 10, 64)
			if errTotal != nil || errUsed != nil || errFree != nil || used > total || free > total {
				snapshot.FieldErrors["filesystems"] = "partial or unavailable"
				continue
			}
			snapshot.Filesystems = append(snapshot.Filesystems, model.FilesystemUsage{Mount: boundedText(parts[1], 1024), TotalBytes: total, UsedBytes: used, FreeBytes: free})
		}
	}
	if scanner.Err() != nil {
		snapshot.FieldErrors["collectorOutput"] = "truncated or invalid"
	}
	for _, field := range []string{"hostname", "kernel", "uptime", "load", "memory_kib", "cpu_model", "cpu_logical", "filesystem"} {
		if !seen[field] {
			snapshot.FieldErrors[displayField(field)] = "unavailable"
		}
	}
	if len(snapshot.FieldErrors) == 0 {
		snapshot.FieldErrors = nil
	}
	return snapshot
}

func displayField(field string) string {
	switch field {
	case "uptime":
		return "uptimeSeconds"
	case "memory_kib":
		return "memory"
	case "cpu_model":
		return "cpuModel"
	case "cpu_logical":
		return "cpuLogicalCores"
	case "filesystem":
		return "filesystems"
	default:
		return field
	}
}

func boundedText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) > max {
		return value[:max]
	}
	return value
}

func ParseCredentialSigner(plaintext []byte) (ssh.Signer, error) {
	var payload struct {
		PrivateKey string `json:"privateKey"`
		Passphrase string `json:"passphrase,omitempty"`
	}
	// Credential JSON is created by our own handler before encryption.
	if err := jsonUnmarshalStrict(plaintext, &payload); err != nil {
		return nil, errors.New("stored credential payload is invalid")
	}
	var signer ssh.Signer
	var err error
	if payload.Passphrase == "" {
		signer, err = ssh.ParsePrivateKey([]byte(payload.PrivateKey))
	} else {
		signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(payload.PrivateKey), []byte(payload.Passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("stored ssh credential cannot be used: %w", err)
	}
	return signer, nil
}

func jsonUnmarshalStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("credential payload has trailing JSON")
	}
	return nil
}
