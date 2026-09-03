package aianalysis

import (
	"context"
	"errors"

	"vpsmanager/services/ai"
	"vpsmanager/services/control-plane/internal/model"
)

type Result struct {
	Analysis       ai.Analysis       `json:"analysis"`
	Mode           ai.Mode           `json:"mode"`
	FallbackReason ai.FallbackReason `json:"fallbackReason,omitempty"`
}

type Adapter struct {
	analyzer *ai.Analyzer
}

func New(config ai.Config) (*Adapter, error) {
	analyzer, err := ai.New(config)
	if err != nil {
		return nil, err
	}
	return &Adapter{analyzer: analyzer}, nil
}

func NewOffline() (*Adapter, error) {
	return New(ai.Config{})
}

func MapFindings(findings []model.ProcessFinding) []ai.Finding {
	mapped := make([]ai.Finding, len(findings))
	for index, finding := range findings {
		mapped[index] = ai.Finding{
			ID:                finding.ID,
			RuleID:            finding.RuleID,
			Title:             finding.Title,
			Severity:          finding.Severity,
			Confidence:        finding.Confidence,
			FalsePositiveNote: finding.FalsePositiveNote,
			Evidence: ai.Evidence{
				PID:            finding.Evidence.PID,
				ParentPID:      finding.Evidence.ParentPID,
				User:           finding.Evidence.User,
				ProcessName:    finding.Evidence.ProcessName,
				CPUPercent:     finding.Evidence.CPUPercent,
				ElapsedSeconds: finding.Evidence.ElapsedSeconds,
			},
		}
	}
	return mapped
}

func (adapter *Adapter) Analyze(ctx context.Context, findings []model.ProcessFinding) (Result, error) {
	if adapter == nil || adapter.analyzer == nil {
		return Result{}, errors.New("AI analysis adapter is not initialized")
	}
	outcome, err := adapter.analyzer.Analyze(ctx, MapFindings(findings))
	if err != nil {
		return Result{}, err
	}
	return Result{
		Analysis:       outcome.Analysis,
		Mode:           outcome.Mode,
		FallbackReason: outcome.FallbackReason,
	}, nil
}
