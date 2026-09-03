package runbook

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Execute runs catalog steps in order and stops at the first failure.
func Execute(ctx context.Context, plan Plan, runner Runner) (Execution, error) {
	if runner == nil || len(plan.steps) == 0 {
		return Execution{}, ErrInvalidPlan
	}
	for _, step := range plan.steps {
		if !step.IsReviewedCatalogStep() {
			return Execution{}, ErrInvalidPlan
		}
	}
	execution := Execution{Status: "succeeded", Steps: make([]StepResult, 0, len(plan.steps))}
	for _, step := range plan.steps {
		stepContext, cancel := context.WithTimeout(ctx, step.timeout)
		started := time.Now()
		result, runErr := runner.RunRunbookStep(stepContext, step)
		cancel()
		if result.Duration <= 0 {
			result.Duration = time.Since(started)
		}
		stepResult := StepResult{
			ID: step.id, Phase: step.phase, State: StepSucceeded,
			Stdout: append([]byte(nil), result.Stdout...), Stderr: append([]byte(nil), result.Stderr...),
			ExitCode: result.ExitCode, Duration: result.Duration,
		}
		if runErr != nil || result.ExitCode != 0 {
			stepResult.State = StepFailed
			stepResult.ErrorCode = classifyError(runErr, result.ExitCode)
			if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.Canceled) {
				stepResult.State = StepCanceled
			}
			execution.Status = "failed"
			execution.Stopped = true
		}
		execution.Steps = append(execution.Steps, stepResult)
		if execution.Stopped {
			break
		}
	}
	return execution, nil
}

func classifyError(err error, exitCode int) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "step_timeout"
	case errors.Is(err, context.Canceled):
		return "step_canceled"
	case errors.Is(err, ErrOutputLimit):
		return "output_limit"
	case exitCode != 0:
		return "nonzero_exit"
	case err != nil:
		return "execution_error"
	default:
		return fmt.Sprintf("exit_%d", exitCode)
	}
}
