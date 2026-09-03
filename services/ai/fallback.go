package ai

import (
	"fmt"
	"slices"
)

func deterministicAnalysis(findings []Finding) Analysis {
	ordered := slices.Clone(findings)
	slices.SortStableFunc(ordered, func(left, right Finding) int {
		if difference := severityWeight(right.Severity) - severityWeight(left.Severity); difference != 0 {
			return difference
		}
		if left.Confidence > right.Confidence {
			return -1
		}
		if left.Confidence < right.Confidence {
			return 1
		}
		if left.RuleID < right.RuleID {
			return -1
		}
		if left.RuleID > right.RuleID {
			return 1
		}
		return 0
	})

	analysis := Analysis{
		SchemaVersion:          SchemaVersion,
		RankedFindings:         make([]RankedFinding, 0, len(ordered)),
		HumanVerificationSteps: make([]HumanVerificationStep, 0, len(ordered)),
		Recommendations:        make([]Recommendation, 0, len(ordered)),
	}
	if len(ordered) == 0 {
		analysis.Summary = "规则扫描未发现异常项。"
		return analysis
	}

	analysis.Summary = fmt.Sprintf("按严重度和置信度整理了 %d 个异常项。", len(ordered))
	for index, finding := range ordered {
		analysis.RankedFindings = append(analysis.RankedFindings, RankedFinding{
			FindingID: finding.ID,
			Rank:      index + 1,
			Rationale: fmt.Sprintf("严重度 %s，置信度 %.2f。", finding.Severity, finding.Confidence),
		})
		analysis.HumanVerificationSteps = append(analysis.HumanVerificationSteps, HumanVerificationStep{
			FindingID:   finding.ID,
			Description: "核对进程所属服务、启动时间和近期变更。",
		})
		analysis.Recommendations = append(analysis.Recommendations, Recommendation{
			FindingID: finding.ID,
			Priority:  priorityForSeverity(finding.Severity),
			Advice:    "查看关联日志，确认进程是否符合预期。",
		})
	}
	return analysis
}

func severityWeight(value string) int {
	switch value {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func priorityForSeverity(value string) string {
	switch value {
	case "critical":
		return "urgent"
	case "high":
		return "high"
	case "medium":
		return "normal"
	default:
		return "low"
	}
}
