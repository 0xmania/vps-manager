package sshconnector

import (
	"context"
	"errors"

	"vpsmanager/services/runbook"
)

// RunRunbookStep accepts only sealed steps produced by the server-owned
// runbook catalog. It does not expose a constructor for arbitrary SSH text.
func (c *Client) RunRunbookStep(ctx context.Context, cfg Config, step runbook.Step) (runbook.CommandResult, error) {
	if !step.IsReviewedCatalogStep() || step.CommandText() == "" {
		return runbook.CommandResult{}, runbook.ErrInvalidPlan
	}
	if step.Timeout() > 0 && (cfg.CommandTimeout <= 0 || step.Timeout() < cfg.CommandTimeout) {
		cfg.CommandTimeout = step.Timeout()
	}
	result, err := c.Run(ctx, cfg, Command{
		id: CommandID("runbook:" + step.ID()), script: step.CommandText(),
	})
	return runbook.CommandResult{
		Stdout: result.Stdout, Stderr: result.Stderr, ExitCode: result.ExitCode, Duration: result.Duration,
	}, translateRunbookError(err)
}

func translateRunbookError(err error) error {
	if errors.Is(err, ErrOutputLimit) {
		return runbook.ErrOutputLimit
	}
	return err
}
