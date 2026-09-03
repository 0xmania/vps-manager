// Package anomaly implements deterministic, read-only process heuristics
// without remediation, AI, or network integration.
package anomaly

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"vpsmanager/services/control-plane/internal/model"
)

const maxProcesses = 4096

type Process struct {
	PID            int
	ParentPID      int
	User           string
	CPUPercent     float64
	ElapsedSeconds uint64
	Name           string
}

// ParseProcessInventory parses the fixed ps output produced by the connector.
// Process records omit command-line and environment fields because those
// frequently contain credentials.
func ParseProcessInventory(output []byte) ([]Process, error) {
	if len(output) > 256<<10 {
		return nil, fmt.Errorf("process inventory exceeds size limit")
	}
	processes := make([]Process, 0, 128)
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 1024), 4096)
	for scanner.Scan() {
		if len(processes) >= maxProcesses {
			return nil, fmt.Errorf("process inventory exceeds entry limit")
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		pid, pidErr := strconv.Atoi(fields[0])
		parentPID, parentErr := strconv.Atoi(fields[1])
		cpu, cpuErr := strconv.ParseFloat(fields[3], 64)
		elapsed, elapsedErr := strconv.ParseUint(fields[4], 10, 64)
		if pidErr != nil || parentErr != nil || cpuErr != nil || elapsedErr != nil || pid < 1 || parentPID < 0 || cpu < 0 || cpu > 10000 || math.IsNaN(cpu) || math.IsInf(cpu, 0) {
			continue
		}
		processes = append(processes, Process{
			PID: pid, ParentPID: parentPID, User: safeToken(fields[2], 64), CPUPercent: cpu,
			ElapsedSeconds: elapsed, Name: safeToken(strings.Join(fields[5:], " "), 128),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("process inventory is invalid or truncated")
	}
	return processes, nil
}

func Scan(processes []Process, observedAt time.Time) model.AnomalyScanResult {
	result := model.AnomalyScanResult{
		ObservedAt: observedAt.UTC(), Engine: "rules_v1", AIExecutionAllowed: false,
		ProcessesEvaluated: len(processes), Findings: make([]model.ProcessFinding, 0),
	}
	for _, process := range processes {
		name := strings.ToLower(strings.TrimSpace(process.Name))
		evidence := model.FindingEvidence{
			PID: process.PID, ParentPID: process.ParentPID, User: process.User,
			ProcessName: process.Name, CPUPercent: process.CPUPercent, ElapsedSeconds: process.ElapsedSeconds,
		}
		if knownMiner(name) {
			result.Findings = append(result.Findings, finding(process, "known_miner_name", "进程名命中已知挖矿程序特征", "critical", 0.97, evidence,
				"管理员可能为压测、研究或合规计算主动运行同名程序；处置前应核对软件来源、父进程和变更记录。"))
		}
		if process.CPUPercent >= 90 && process.ElapsedSeconds >= 120 {
			result.Findings = append(result.Findings, finding(process, "sustained_high_cpu", "进程持续占用高 CPU", "high", 0.82, evidence,
				"编译、压缩、数据库维护和业务峰值可能产生相同行为；建议结合历史基线与业务窗口复核。"))
		}
		if strings.HasPrefix(name, ".") && name != "." && name != ".." {
			result.Findings = append(result.Findings, finding(process, "hidden_process_name", "进程名称采用隐藏文件样式", "medium", 0.68, evidence,
				"某些合法守护程序或运维脚本也会使用点号开头的名称；需检查软件包归属和启动方式。"))
		}
		if strings.HasPrefix(name, "kworker") && process.User != "root" {
			result.Findings = append(result.Findings, finding(process, "kernel_worker_impersonation", "非 root 进程疑似伪装为内核工作线程", "high", 0.9, evidence,
				"容器用户映射或测试夹具可能造成非典型属主；应从宿主机命名空间复核。"))
		}
	}
	return result
}

func finding(process Process, ruleID, title, severity string, confidence float64, evidence model.FindingEvidence, falsePositive string) model.ProcessFinding {
	return model.ProcessFinding{
		ID: fmt.Sprintf("%s:%d", ruleID, process.PID), RuleID: ruleID, Title: title,
		Severity: severity, Confidence: confidence, Evidence: evidence, FalsePositiveNote: falsePositive,
	}
}

func knownMiner(name string) bool {
	switch name {
	case "xmrig", "minerd", "kinsing", "watchbog", "cryptonight":
		return true
	default:
		return false
	}
}

func safeToken(value string, limit int) string {
	value = strings.ToValidUTF8(value, "�")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	for len(value) > limit {
		_, size := utf8.DecodeLastRuneInString(value)
		value = value[:len(value)-size]
	}
	return value
}
