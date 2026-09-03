package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type webSSHRuntimeConfig struct {
	origins         []string
	idleTimeout     time.Duration
	absoluteTimeout time.Duration
	maxConcurrent   int
}

func loadWebSSHConfig() (webSSHRuntimeConfig, error) {
	var origins []string
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_WEBSSH_ALLOWED_ORIGINS")); value != "" {
		for _, origin := range strings.Split(value, ",") {
			origin = strings.TrimSpace(origin)
			if origin == "" {
				return webSSHRuntimeConfig{}, errors.New("VPSMGR_CONNECTOR_WEBSSH_ALLOWED_ORIGINS contains an empty origin")
			}
			origins = append(origins, origin)
		}
	}
	idleTimeout := 10 * time.Minute
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_WEBSSH_IDLE_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed < 30*time.Second || parsed > time.Hour {
			return webSSHRuntimeConfig{}, errors.New("VPSMGR_CONNECTOR_WEBSSH_IDLE_TIMEOUT must be between 30s and 1h")
		}
		idleTimeout = parsed
	}
	absoluteTimeout := time.Hour
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_WEBSSH_ABSOLUTE_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil || parsed < time.Minute || parsed > 8*time.Hour {
			return webSSHRuntimeConfig{}, errors.New("VPSMGR_CONNECTOR_WEBSSH_ABSOLUTE_TIMEOUT must be between 1m and 8h")
		}
		absoluteTimeout = parsed
	}
	if absoluteTimeout < idleTimeout {
		return webSSHRuntimeConfig{}, errors.New("web SSH absolute timeout must not be shorter than idle timeout")
	}
	maxConcurrent := 4
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_WEBSSH_MAX_CONCURRENT")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 64 {
			return webSSHRuntimeConfig{}, errors.New("VPSMGR_CONNECTOR_WEBSSH_MAX_CONCURRENT must be between 1 and 64")
		}
		maxConcurrent = parsed
	}
	return webSSHRuntimeConfig{
		origins: origins, idleTimeout: idleTimeout,
		absoluteTimeout: absoluteTimeout, maxConcurrent: maxConcurrent,
	}, nil
}
