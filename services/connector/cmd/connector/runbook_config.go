package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

type runbookConfig struct {
	mutationsEnabled bool
	maxConcurrent    int
	maxIdempotency   int
}

func loadRunbookConfig() (runbookConfig, error) {
	config := runbookConfig{maxConcurrent: 4, maxIdempotency: 10_000}
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_ENABLE_MUTATIONS")); value != "" {
		if value != "true" && value != "false" {
			return runbookConfig{}, errors.New("VPSMGR_CONNECTOR_ENABLE_MUTATIONS must be true or false")
		}
		config.mutationsEnabled = value == "true"
	}
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_RUNBOOK_MAX_CONCURRENT")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 32 {
			return runbookConfig{}, errors.New("VPSMGR_CONNECTOR_RUNBOOK_MAX_CONCURRENT must be between 1 and 32")
		}
		config.maxConcurrent = parsed
	}
	if value := strings.TrimSpace(os.Getenv("VPSMGR_CONNECTOR_RUNBOOK_IDEMPOTENCY_JOBS")); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 100 || parsed > 1_000_000 {
			return runbookConfig{}, errors.New("VPSMGR_CONNECTOR_RUNBOOK_IDEMPOTENCY_JOBS must be between 100 and 1000000")
		}
		config.maxIdempotency = parsed
	}
	return config, nil
}
