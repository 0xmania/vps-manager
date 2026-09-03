// Package runbook owns the versioned operation catalog.
package runbook

import (
	"context"
	"errors"
	"time"
)

const CatalogVersion = "2026-08-29.1"

type ActionID string

const (
	ActionCapabilities   ActionID = "system_capabilities_v1"
	ActionUpdateCheck    ActionID = "package_update_check_v1"
	ActionServiceStatus  ActionID = "service_status_v1"
	ActionServiceRestart ActionID = "service_restart_v1"
	ActionTimezoneSet    ActionID = "timezone_set_v1"
	ActionProcessSIGTERM ActionID = "process_sigterm_v1"
	ActionHostRebootPlan ActionID = "host_reboot_plan_v1"
)

type Service string

const (
	ServiceNginx  Service = "nginx"
	ServiceSSH    Service = "ssh"
	ServiceDocker Service = "docker"
	ServiceCron   Service = "cron"
)

type Timezone string

const (
	TimezoneUTC      Timezone = "UTC"
	TimezoneShanghai Timezone = "Asia/Shanghai"
	TimezoneNewYork  Timezone = "America/New_York"
	TimezoneLondon   Timezone = "Europe/London"
)

// ProcessStartTicks is Linux /proc PID field 22 and binds SIGTERM to a process instance.
type Parameters struct {
	Service           Service  `json:"service,omitempty"`
	Timezone          Timezone `json:"timezone,omitempty"`
	PID               int      `json:"pid,omitempty"`
	ProcessStartTicks uint64   `json:"processStartTicks,omitempty"`
}

type Phase string

const (
	PhasePreflight Phase = "preflight"
	PhaseEvidence  Phase = "evidence"
	PhaseApply     Phase = "apply"
	PhaseVerify    Phase = "verify"
)

type Definition struct {
	ID          ActionID
	Version     int
	Title       string
	Mutating    bool
	Emergency   bool
	RetryPolicy string
}

type Step struct {
	id          string
	phase       Phase
	description string
	command     string
	timeout     time.Duration
	seal        [32]byte
}

func (s Step) ID() string                  { return s.id }
func (s Step) Phase() Phase                { return s.phase }
func (s Step) Description() string         { return s.description }
func (s Step) CommandText() string         { return s.command }
func (s Step) Timeout() time.Duration      { return s.timeout }
func (s Step) IsReviewedCatalogStep() bool { return s.seal == sealStep(s) }

type Plan struct {
	definition Definition
	parameters Parameters
	steps      []Step
}

func (p Plan) Definition() Definition { return p.definition }
func (p Plan) Parameters() Parameters { return p.parameters }
func (p Plan) Steps() []Step          { return append([]Step(nil), p.steps...) }

type CommandResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

type Runner interface {
	RunRunbookStep(context.Context, Step) (CommandResult, error)
}

type StepState string

const (
	StepSucceeded StepState = "succeeded"
	StepFailed    StepState = "failed"
	StepCanceled  StepState = "canceled"
)

type StepResult struct {
	ID        string
	Phase     Phase
	State     StepState
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	Duration  time.Duration
	ErrorCode string
}

type Execution struct {
	Status  string
	Steps   []StepResult
	Stopped bool
}

var (
	ErrInvalidPlan = errors.New("runbook plan is not from the reviewed catalog")
	ErrOutputLimit = errors.New("runbook step exceeded its output limit")
)
