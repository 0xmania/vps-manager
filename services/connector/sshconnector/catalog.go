package sshconnector

import "errors"

const (
	CommandDiskUsage      CommandID = "disk_usage_v1"
	CommandListeningPorts CommandID = "listening_ports_v1"
	CommandServiceStatus  CommandID = "service_status_v1"
	CommandProcessList    CommandID = "process_inventory_v1"
)

// ServiceTarget is an enum mapped to reviewed command literals below; command
// construction does not interpolate it into a shell program.
type ServiceTarget string

const (
	ServiceNginx  ServiceTarget = "nginx"
	ServiceSSH    ServiceTarget = "ssh"
	ServiceDocker ServiceTarget = "docker"
	ServiceCron   ServiceTarget = "cron"
)

type ReadOnlyCommandRequest struct {
	ID      CommandID
	Service ServiceTarget
}

// ReadOnlyCommand returns reviewed, read-only programs. Unknown command IDs,
// extra parameters, and unapproved service names return an error.
func ReadOnlyCommand(request ReadOnlyCommandRequest) (Command, error) {
	switch request.ID {
	case CommandDiskUsage:
		if request.Service != "" {
			return Command{}, errors.New("disk usage does not accept parameters")
		}
		return Command{id: request.ID, script: "LC_ALL=C df -P -B1 2>/dev/null"}, nil
	case CommandListeningPorts:
		if request.Service != "" {
			return Command{}, errors.New("listening ports does not accept parameters")
		}
		return Command{id: request.ID, script: "LC_ALL=C ss -H -lntu 2>/dev/null"}, nil
	case CommandServiceStatus:
		script, ok := serviceStatusCommands[request.Service]
		if !ok {
			return Command{}, errors.New("service must be one of nginx, ssh, docker, or cron")
		}
		return Command{id: request.ID, script: script}, nil
	default:
		return Command{}, errors.New("command id is not in the read-only catalog")
	}
}

var serviceStatusCommands = map[ServiceTarget]string{
	ServiceNginx:  "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID nginx.service 2>/dev/null",
	ServiceSSH:    "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID ssh.service 2>/dev/null",
	ServiceDocker: "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID docker.service 2>/dev/null",
	ServiceCron:   "LC_ALL=C systemctl show --no-pager --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,MainPID cron.service 2>/dev/null",
}

// ProcessInventoryCommand is internal to the rule scanner. Its output omits
// command-line arguments and environments, which commonly contain secrets.
// Output is capped again by the connector execution budget.
func ProcessInventoryCommand() Command {
	return Command{id: CommandProcessList, script: "LC_ALL=C ps -eo pid=,ppid=,user=,pcpu=,etimes=,comm= --sort=-pcpu 2>/dev/null"}
}
