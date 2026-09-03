package runbook

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

var definitions = map[ActionID]Definition{
	ActionCapabilities:   {ID: ActionCapabilities, Version: 1, Title: "Inspect host capabilities", RetryPolicy: "never"},
	ActionUpdateCheck:    {ID: ActionUpdateCheck, Version: 1, Title: "Inspect cached package updates", RetryPolicy: "never"},
	ActionServiceStatus:  {ID: ActionServiceStatus, Version: 1, Title: "Inspect service status", RetryPolicy: "never"},
	ActionServiceRestart: {ID: ActionServiceRestart, Version: 1, Title: "Restart an approved service", Mutating: true, Emergency: true, RetryPolicy: "never"},
	ActionTimezoneSet:    {ID: ActionTimezoneSet, Version: 1, Title: "Set an approved timezone", Mutating: true, Emergency: true, RetryPolicy: "never"},
	ActionProcessSIGTERM: {ID: ActionProcessSIGTERM, Version: 1, Title: "Send SIGTERM to a bound process", Mutating: true, Emergency: true, RetryPolicy: "never"},
	ActionHostRebootPlan: {ID: ActionHostRebootPlan, Version: 1, Title: "Schedule a host reboot in one minute", Mutating: true, Emergency: true, RetryPolicy: "never"},
}

func Definitions() []Definition {
	order := []ActionID{ActionCapabilities, ActionUpdateCheck, ActionServiceStatus, ActionServiceRestart, ActionTimezoneSet, ActionProcessSIGTERM, ActionHostRebootPlan}
	result := make([]Definition, 0, len(order))
	for _, id := range order {
		result = append(result, definitions[id])
	}
	return result
}

func Build(action ActionID, version int, parameters Parameters) (Plan, error) {
	definition, ok := definitions[action]
	if !ok || version != definition.Version {
		return Plan{}, errors.New("action and version are not in the runbook catalog")
	}
	steps, normalized, err := buildSteps(action, parameters)
	if err != nil {
		return Plan{}, err
	}
	for index := range steps {
		steps[index].seal = sealStep(steps[index])
	}
	return Plan{definition: definition, parameters: normalized, steps: steps}, nil
}

func ScopeDigest(hostID, jobID string, plan Plan) (string, error) {
	if _, ok := definitions[plan.definition.ID]; !ok || len(plan.steps) == 0 {
		return "", ErrInvalidPlan
	}
	canonical := strings.Join([]string{
		CatalogVersion,
		string(plan.definition.ID),
		strconv.Itoa(plan.definition.Version),
		hostID,
		jobID,
		string(plan.parameters.Service),
		string(plan.parameters.Timezone),
		strconv.Itoa(plan.parameters.PID),
		strconv.FormatUint(plan.parameters.ProcessStartTicks, 10),
	}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:]), nil
}

func buildSteps(action ActionID, p Parameters) ([]Step, Parameters, error) {
	switch action {
	case ActionCapabilities:
		if p != (Parameters{}) {
			return nil, Parameters{}, errors.New("capabilities does not accept parameters")
		}
		return readOnlySteps("capabilities", "collect supported host tools", capabilitiesCommand), p, nil
	case ActionUpdateCheck:
		if p != (Parameters{}) {
			return nil, Parameters{}, errors.New("update check does not accept parameters")
		}
		return readOnlySteps("updates", "inspect cached package update metadata", updateCheckCommand), p, nil
	case ActionServiceStatus:
		command, ok := serviceStatusCommands[p.Service]
		if !ok || p.Timezone != "" || p.PID != 0 || p.ProcessStartTicks != 0 {
			return nil, Parameters{}, errors.New("service status requires exactly one approved service")
		}
		return readOnlySteps("service-status", "inspect approved service state", command), p, nil
	case ActionServiceRestart:
		commands, ok := serviceRestartCommands[p.Service]
		if !ok || p.Timezone != "" || p.PID != 0 || p.ProcessStartTicks != 0 {
			return nil, Parameters{}, errors.New("service restart requires exactly one approved service")
		}
		return mutatingSteps("service-restart", commands.evidence, commands.apply, commands.verify), p, nil
	case ActionTimezoneSet:
		commands, ok := timezoneCommands[p.Timezone]
		if !ok || p.Service != "" || p.PID != 0 || p.ProcessStartTicks != 0 {
			return nil, Parameters{}, errors.New("timezone set requires exactly one approved timezone")
		}
		return []Step{
			newStep("timezone-preflight", PhasePreflight, "check timedatectl and non-interactive sudo", privilegePreflight("timedatectl"), 10*time.Second),
			newStep("timezone-evidence", PhaseEvidence, "record the current timezone", "LC_ALL=C timedatectl show --property=Timezone --value", 10*time.Second),
			newStep("timezone-apply", PhaseApply, "set the approved timezone", commands.apply, 15*time.Second),
			newStep("timezone-verify", PhaseVerify, "verify the selected timezone", commands.verify, 10*time.Second),
		}, p, nil
	case ActionProcessSIGTERM:
		if p.Service != "" || p.Timezone != "" || p.PID < 100 || p.ProcessStartTicks == 0 {
			return nil, Parameters{}, errors.New("SIGTERM requires PID >= 100 and a positive process start tick")
		}
		pid := strconv.Itoa(p.PID)
		ticks := strconv.FormatUint(p.ProcessStartTicks, 10)
		preflight := "LC_ALL=C; test " + pid + " -ne 1; test " + pid + " -ne \"$$\"; test " + pid + " -ne \"$PPID\"; test -e /proc/" + pid + "/exe; test \"$(awk '{print $22}' /proc/" + pid + "/stat)\" = \"" + ticks + "\"; command -v sudo >/dev/null"
		evidence := "LC_ALL=C ps -p " + pid + " -o pid=,ppid=,user=,stat=,etimes=,comm="
		apply := "LC_ALL=C; test \"$(awk '{print $22}' /proc/" + pid + "/stat 2>/dev/null)\" = \"" + ticks + "\"; sudo -n kill -TERM -- " + pid
		verify := "LC_ALL=C; current=$(awk '{print $22}' /proc/" + pid + "/stat 2>/dev/null || true); test \"$current\" != \"" + ticks + "\""
		return []Step{
			newStep("process-preflight", PhasePreflight, "reject reserved, self, kernel-thread, and stale process targets", preflight, 10*time.Second),
			newStep("process-evidence", PhaseEvidence, "record non-secret process identity", evidence, 10*time.Second),
			newStep("process-apply", PhaseApply, "send SIGTERM once to the bound process instance", apply, 10*time.Second),
			newStep("process-verify", PhaseVerify, "verify the original process instance exited", verify, 15*time.Second),
		}, p, nil
	case ActionHostRebootPlan:
		if p != (Parameters{}) {
			return nil, Parameters{}, errors.New("host reboot plan does not accept parameters")
		}
		return []Step{
			newStep("reboot-preflight", PhasePreflight, "check shutdown and non-interactive sudo", privilegePreflight("shutdown"), 10*time.Second),
			newStep("reboot-evidence", PhaseEvidence, "record uptime and logged-in sessions", "LC_ALL=C uptime; who", 10*time.Second),
			newStep("reboot-apply", PhaseApply, "schedule a reboot in one minute", "LC_ALL=C sudo -n shutdown -r +1 'vpsmanager approved reboot'", 10*time.Second),
			newStep("reboot-verify", PhaseVerify, "verify a shutdown is scheduled", "LC_ALL=C shutdown --show", 10*time.Second),
		}, p, nil
	default:
		return nil, Parameters{}, errors.New("unsupported runbook action")
	}
}

func readOnlySteps(prefix, description, evidence string) []Step {
	return []Step{
		newStep(prefix+"-preflight", PhasePreflight, "check basic POSIX host capability", "LC_ALL=C id -u; uname -sr", 10*time.Second),
		newStep(prefix+"-evidence", PhaseEvidence, description, evidence, 60*time.Second),
	}
}

func mutatingSteps(prefix, evidence, apply, verify string) []Step {
	return []Step{
		newStep(prefix+"-preflight", PhasePreflight, "check systemctl and non-interactive sudo", privilegePreflight("systemctl"), 10*time.Second),
		newStep(prefix+"-evidence", PhaseEvidence, "record the current approved service state", evidence, 10*time.Second),
		newStep(prefix+"-apply", PhaseApply, "apply the approved service restart once", apply, 20*time.Second),
		newStep(prefix+"-verify", PhaseVerify, "verify the approved service is active", verify, 15*time.Second),
	}
}

func newStep(id string, phase Phase, description, command string, timeout time.Duration) Step {
	return Step{id: id, phase: phase, description: description, command: command, timeout: timeout}
}

func sealStep(step Step) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{step.id, string(step.phase), step.description, step.command, step.timeout.String()}, "\x00")))
}

func privilegePreflight(tool string) string {
	// tool is selected only from fixed literals in this source file.
	return "LC_ALL=C command -v " + tool + " >/dev/null; command -v sudo >/dev/null; sudo -n true"
}

const capabilitiesCommand = `LC_ALL=C
printf 'init\t'; if command -v systemctl >/dev/null; then printf 'systemd\n'; else printf 'unknown\n'; fi
for tool in sudo systemctl timedatectl shutdown apt apt-get dnf yum apk; do if command -v "$tool" >/dev/null; then printf 'tool\t%s\n' "$tool"; fi; done
printf 'timezone\t'; (timedatectl show --property=Timezone --value 2>/dev/null || date +%Z)`

const updateCheckCommand = `LC_ALL=C
if command -v apt >/dev/null; then apt list --upgradable 2>/dev/null || true
elif command -v dnf >/dev/null; then dnf --cacheonly --quiet check-update 2>/dev/null || test "$?" -eq 100
elif command -v yum >/dev/null; then yum --cacheonly --quiet check-update 2>/dev/null || test "$?" -eq 100
elif command -v apk >/dev/null; then apk version -l '<' 2>/dev/null
else printf 'unsupported package manager\n'; exit 3; fi`

var serviceStatusCommands = map[Service]string{
	ServiceNginx:  "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID nginx.service",
	ServiceSSH:    "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID ssh.service",
	ServiceDocker: "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID docker.service",
	ServiceCron:   "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID cron.service",
}

type commandPair struct{ evidence, apply, verify string }

var serviceRestartCommands = map[Service]commandPair{
	ServiceNginx:  {serviceStatusCommands[ServiceNginx], "LC_ALL=C sudo -n systemctl restart nginx.service", "LC_ALL=C systemctl is-active --quiet nginx.service; systemctl show --no-pager --property=ActiveState,SubState,MainPID nginx.service"},
	ServiceSSH:    {serviceStatusCommands[ServiceSSH], "LC_ALL=C sudo -n systemctl restart ssh.service", "LC_ALL=C systemctl is-active --quiet ssh.service; systemctl show --no-pager --property=ActiveState,SubState,MainPID ssh.service"},
	ServiceDocker: {serviceStatusCommands[ServiceDocker], "LC_ALL=C sudo -n systemctl restart docker.service", "LC_ALL=C systemctl is-active --quiet docker.service; systemctl show --no-pager --property=ActiveState,SubState,MainPID docker.service"},
	ServiceCron:   {serviceStatusCommands[ServiceCron], "LC_ALL=C sudo -n systemctl restart cron.service", "LC_ALL=C systemctl is-active --quiet cron.service; systemctl show --no-pager --property=ActiveState,SubState,MainPID cron.service"},
}

var timezoneCommands = map[Timezone]commandPair{
	TimezoneUTC:      {apply: "LC_ALL=C sudo -n timedatectl set-timezone UTC", verify: "LC_ALL=C test \"$(timedatectl show --property=Timezone --value)\" = 'UTC'"},
	TimezoneShanghai: {apply: "LC_ALL=C sudo -n timedatectl set-timezone Asia/Shanghai", verify: "LC_ALL=C test \"$(timedatectl show --property=Timezone --value)\" = 'Asia/Shanghai'"},
	TimezoneNewYork:  {apply: "LC_ALL=C sudo -n timedatectl set-timezone America/New_York", verify: "LC_ALL=C test \"$(timedatectl show --property=Timezone --value)\" = 'America/New_York'"},
	TimezoneLondon:   {apply: "LC_ALL=C sudo -n timedatectl set-timezone Europe/London", verify: "LC_ALL=C test \"$(timedatectl show --property=Timezone --value)\" = 'Europe/London'"},
}
