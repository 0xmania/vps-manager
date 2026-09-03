package ai

import (
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	errInvalidFindings = errors.New("invalid redacted findings")
	identifierPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	secretPattern      = regexp.MustCompile(`(?i)(-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|(?:password|passwd|api[_-]?key|secret|token|authorization)\s*[:=]\s*\S+)`)
	commandPattern     = regexp.MustCompile(`(?i)(?:^|\s)(?:sudo|bash|sh|zsh|powershell|cmd\.exe|rm|kill|pkill|systemctl|curl|wget|chmod|chown)\s+`)
)

func validateFindings(findings []Finding) error {
	if len(findings) > MaxFindings {
		return errInvalidFindings
	}
	seen := make(map[string]struct{}, len(findings))
	for i := range findings {
		finding := &findings[i]
		if !identifierPattern.MatchString(finding.ID) ||
			!identifierPattern.MatchString(finding.RuleID) ||
			validateText(finding.Title, 1, 256, true) != nil ||
			validateText(finding.FalsePositiveNote, 1, 1024, true) != nil {
			return errInvalidFindings
		}
		if _, exists := seen[finding.ID]; exists {
			return errInvalidFindings
		}
		seen[finding.ID] = struct{}{}
		if !validSeverity(finding.Severity) || math.IsNaN(finding.Confidence) || math.IsInf(finding.Confidence, 0) || finding.Confidence < 0 || finding.Confidence > 1 {
			return errInvalidFindings
		}
		if finding.Evidence.PID < 0 || finding.Evidence.ParentPID < 0 ||
			math.IsNaN(finding.Evidence.CPUPercent) || math.IsInf(finding.Evidence.CPUPercent, 0) ||
			finding.Evidence.CPUPercent < 0 || finding.Evidence.CPUPercent > 10000 {
			return errInvalidFindings
		}
		if validateOptionalText(finding.Evidence.User, 64) != nil || validateOptionalText(finding.Evidence.ProcessName, 128) != nil {
			return errInvalidFindings
		}
	}
	return nil
}

func validateAnalysis(value Analysis, findings []Finding) error {
	if value.SchemaVersion != SchemaVersion || value.ExecutionAllowed {
		return errors.New("invalid analysis contract")
	}
	if validateOutputText(value.Summary, 1, 2000) != nil {
		return errors.New("invalid analysis summary")
	}
	if len(value.RankedFindings) != len(findings) || len(value.HumanVerificationSteps) > max(1, len(findings)*3) || len(value.Recommendations) > max(1, len(findings)*2) {
		return errors.New("invalid analysis collection size")
	}
	known := make(map[string]struct{}, len(findings))
	for _, finding := range findings {
		known[finding.ID] = struct{}{}
	}
	ranks := make(map[int]struct{}, len(findings))
	rankedIDs := make(map[string]struct{}, len(findings))
	verificationCoverage := make(map[string]struct{}, len(findings))
	recommendationCoverage := make(map[string]struct{}, len(findings))
	for _, item := range value.RankedFindings {
		if _, ok := known[item.FindingID]; !ok || item.Rank < 1 || item.Rank > len(findings) || validateOutputText(item.Rationale, 1, 600) != nil {
			return errors.New("invalid ranked finding")
		}
		if _, duplicate := ranks[item.Rank]; duplicate {
			return errors.New("duplicate rank")
		}
		if _, duplicate := rankedIDs[item.FindingID]; duplicate {
			return errors.New("duplicate ranked finding")
		}
		ranks[item.Rank] = struct{}{}
		rankedIDs[item.FindingID] = struct{}{}
	}
	if len(findings) > 0 && (len(value.HumanVerificationSteps) == 0 || len(value.Recommendations) == 0) {
		return errors.New("missing human guidance")
	}
	for _, step := range value.HumanVerificationSteps {
		if _, ok := known[step.FindingID]; !ok || validateOutputText(step.Description, 1, 600) != nil {
			return errors.New("invalid verification step")
		}
		verificationCoverage[step.FindingID] = struct{}{}
	}
	for _, recommendation := range value.Recommendations {
		if _, ok := known[recommendation.FindingID]; !ok || !validPriority(recommendation.Priority) || validateOutputText(recommendation.Advice, 1, 600) != nil {
			return errors.New("invalid recommendation")
		}
		recommendationCoverage[recommendation.FindingID] = struct{}{}
	}
	if len(verificationCoverage) != len(findings) || len(recommendationCoverage) != len(findings) {
		return errors.New("human guidance does not cover every finding")
	}
	return nil
}

func validateOptionalText(value string, limit int) error {
	if value == "" {
		return nil
	}
	return validateText(value, 1, limit, true)
}

func validateOutputText(value string, minimum, maximum int) error {
	if err := validateText(value, minimum, maximum, true); err != nil {
		return err
	}
	if strings.ContainsAny(value, "`|;<>") || strings.Contains(value, "&&") || strings.Contains(value, "||") || strings.Contains(value, "$(") || commandPattern.MatchString(value) {
		return errors.New("execution syntax is forbidden")
	}
	return nil
}

func validateText(value string, minimum, maximum int, rejectSecrets bool) error {
	if !utf8.ValidString(value) {
		return errors.New("invalid utf-8")
	}
	length := utf8.RuneCountInString(value)
	if length < minimum || length > maximum || len(value) > maximum*4 {
		return fmt.Errorf("text length outside bounds")
	}
	for _, r := range value {
		if unicode.Is(unicode.C, r) {
			return errors.New("control or format character is forbidden")
		}
	}
	if rejectSecrets && secretPattern.MatchString(value) {
		return errors.New("probable secret is forbidden")
	}
	return nil
}

func validSeverity(value string) bool {
	switch value {
	case "critical", "high", "medium", "low":
		return true
	default:
		return false
	}
}

func validPriority(value string) bool {
	switch value {
	case "urgent", "high", "normal", "low":
		return true
	default:
		return false
	}
}
